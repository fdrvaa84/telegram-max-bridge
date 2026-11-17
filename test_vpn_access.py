"""Unit checks and opt-in integration against real AWG in a disposable container.

Inside a disposable Ubuntu/Debian container with NET_ADMIN and /dev/net/tun,
install official awg/awg-quick and amneziawg-go, plus python3, iproute2,
qrencode and zbar-tools. Run TELEMAX_VPN_INTEGRATION=1 python3 -m unittest
-v test_vpn_access. No host network, host VPN configuration or credentials.
"""
import concurrent.futures
import ipaddress
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import vpn_access as vpn


class UnitTests(unittest.TestCase):
    def test_allocation_reserves_whole_peer_networks_and_both_families(self):
        addresses = [ipaddress.ip_interface('10.77.0.1/24'), ipaddress.ip_interface('fd77::1/64')]
        occupied = vpn.networks('10.77.0.0/29, fd77::2/128')
        self.assertEqual(vpn.free_addresses(addresses, occupied), ['10.77.0.8/32', 'fd77::3/128'])

    def test_exhaustion(self):
        with self.assertRaises(vpn.AccessError):
            vpn.free_addresses([ipaddress.ip_interface('10.77.0.1/30')], vpn.networks('10.77.0.2/32'))

    def test_repeated_quick_addresses(self):
        interface, peers = vpn.parse('[Interface]\nAddress=10.77.0.1/24\nAddress=fd77::1/64\n')
        self.assertEqual(len(interface['address'].split(',')), 2)
        self.assertFalse(peers)

    def test_duplicate_keys_and_invalid_key(self):
        with self.assertRaises(vpn.AccessError):
            vpn.parse('[Interface]\nPrivateKey=a\nPrivateKey=b\n')
        with self.assertRaises(vpn.AccessError):
            vpn.key('not-a-key')

    def test_atomic_permissions(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'secret'
            vpn.atomic(path, 'synthetic')
            vpn.private_file(path)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)


INTEGRATION = os.environ.get('TELEMAX_VPN_INTEGRATION') == '1'


@unittest.skipUnless(INTEGRATION, 'Real AWG integration is opt-in in a disposable container')
class IntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not Path('/.dockerenv').exists() or os.geteuid() != 0:
            raise RuntimeError('Use a disposable container as root, without host network or mounts')

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='telemax-vpn-')
        self.root = Path(self.temp.name)
        self.state = self.root / 'private'
        self.interface = 'tv' + os.urandom(4).hex()
        self.client_interface = 'tc' + os.urandom(4).hex()
        self.server = self.root / (self.interface + '.conf')
        self.old_private = vpn.run('awg', 'genkey').strip()
        self.old_public = vpn.public(self.old_private)
        self.old_psk = vpn.run('awg', 'genpsk').strip()
        self.server_private = vpn.run('awg', 'genkey').strip()
        self.server_text = ('[Interface]\nAddress = 10.77.0.1/24, fd77::1/64\nListenPort = 51877\n'
                            f'PrivateKey = {self.server_private}\nSaveConfig = false\n'
                            'Jc = 4\nJmin = 40\nJmax = 70\nS1 = 15\nS2 = 16\n'
                            'H1 = 101\nH2 = 102\nH3 = 103\nH4 = 104\n'
                            '\n[Peer]\n' + f'PublicKey = {self.old_public}\nPresharedKey = {self.old_psk}\n'
                            'AllowedIPs = 10.77.0.2/32, fd77::2/128\n')
        vpn.atomic(self.server, self.server_text)
        self.start_interface(self.interface)
        vpn.run('ip', 'address', 'add', '10.77.0.1/24', 'dev', self.interface)
        vpn.run('ip', 'address', 'add', 'fd77::1/64', 'dev', self.interface)
        self.apply_server()
        self.cli('prepare', '--server-config', str(self.server), '--endpoint', '192.0.2.10:51877',
                 '--dns', '1.1.1.1', '--routes', '0.0.0.0/0, ::/0', '--client-format', '1')
        self.profile = json.loads((self.state / 'profile.json').read_text())
        self.baseline = vpn.snapshot(self.profile)[1]

    def start_interface(self, name):
        vpn.run('amneziawg-go', name)
        vpn.run('ip', 'link', 'set', name, 'up')

    def apply_server(self):
        stripped = self.root / 'stripped.conf'
        vpn.atomic(stripped, vpn.run('awg-quick', 'strip', str(self.server)))
        vpn.run('awg', 'setconf', self.interface, str(stripped))
        stripped.unlink()

    def tearDown(self):
        for name in (self.interface, self.client_interface):
            subprocess.run(['ip', 'link', 'delete', name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.temp.cleanup()

    def cli(self, *args, expected=0):
        result = subprocess.run([sys.executable, str(Path(vpn.__file__).absolute()), '--state-dir',
                                 str(self.state), *args], capture_output=True)
        self.assertEqual(result.returncode, expected, result.stderr.decode())
        # The CLI must never reveal either existing server or client secret material.
        self.assertTrue(self.server_private.encode() not in result.stdout + result.stderr)
        self.assertTrue(self.old_psk.encode() not in result.stdout + result.stderr)
        return result

    def client(self, name):
        return self.state / 'devices' / name / (name + '.conf')

    def assert_old_preserved(self):
        vpn.unchanged_peers(self.baseline, vpn.snapshot(self.profile)[1])
        self.assertTrue(self.old_public in vpn.parse(self.server.read_text())[1])

    def assert_qr(self, name):
        conf = self.client(name)
        image = conf.with_suffix('.png')
        decoded = subprocess.run(['zbarimg', '--quiet', '--raw', str(image)], capture_output=True)
        self.assertEqual(decoded.returncode, 0)
        self.assertTrue(decoded.stdout == conf.read_bytes() + b'\n', 'QR payload differs from client conf')
        self.assertEqual(conf.stat().st_mode & 0o777, 0o600)
        self.assertEqual(image.stat().st_mode & 0o777, 0o600)
        self.assertEqual(conf.parent.stat().st_mode & 0o777, 0o700)

    def test_normal_repeat_real_client_parser_and_parallel(self):
        self.cli('add', 'phone')
        self.assert_qr('phone')
        before = self.client('phone').read_bytes()
        server_before = self.server.read_bytes()
        self.cli('add', 'phone')
        self.assertTrue(before == self.client('phone').read_bytes())
        self.assertTrue(server_before == self.server.read_bytes())
        self.start_interface(self.client_interface)
        stripped = self.root / 'client-stripped.conf'
        vpn.atomic(stripped, vpn.run('awg-quick', 'strip', str(self.client('phone'))))
        vpn.run('awg', 'setconf', self.client_interface, str(stripped))
        client, remote = vpn.parse(before.decode())
        pub = vpn.public(client['privatekey'])
        self.assertTrue(vpn.run('awg', 'show', self.client_interface, 'public-key').strip() == pub)
        self.assertTrue(set(vpn.networks(client['address'])) == set(vpn.networks('10.77.0.3/32, fd77::3/128')))
        self.assertTrue(vpn.public(self.server_private) in remote)
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as pool:
            list(pool.map(lambda name: self.cli('add', name), ['phone', 'tablet', 'laptop', 'tablet', 'watch']))
        persistent = vpn.parse(self.server.read_text())[1]
        active = vpn.snapshot(self.profile)[1]
        self.assertEqual(len(persistent), 5)
        self.assertEqual(len(active), 5)
        allocated = set()
        keys = set()
        for name in ('phone', 'tablet', 'laptop', 'watch'):
            client, remote = vpn.parse(self.client(name).read_text())
            key = vpn.public(client['privatekey'])
            self.assertTrue(key not in keys)
            keys.add(key)
            expected = {'allowedips': client['address'], 'presharedkey': next(iter(remote.values()))['presharedkey']}
            self.assertTrue(vpn.peer_matches(persistent.get(key), expected))
            self.assertTrue(vpn.peer_matches(active.get(key), expected))
            for address in vpn.networks(client['address']):
                self.assertTrue(address not in allocated)
                allocated.add(address)
            self.assert_qr(name)
        self.assert_old_preserved()

    def test_partial_live_apply_failure_rolls_back(self):
        before = self.server.read_bytes()
        real_run = vpn.run
        failed = False

        def failing(*args, **kwargs):
            nonlocal failed
            result = real_run(*args, **kwargs)
            if args[:2] == ('awg', 'set') and 'remove' not in args and not failed:
                failed = True
                raise vpn.AccessError('Controlled failure after real peer addition')
            return result

        with patch.object(vpn, 'run', side_effect=failing):
            with self.assertRaises(vpn.AccessError):
                vpn.add(self.state, self.profile, 'failed')
        self.assertTrue(failed)
        self.assertTrue(self.server.read_bytes() == before)
        self.assertEqual(len(vpn.snapshot(self.profile)[1]), 1)
        self.assertFalse((self.state / 'pending.json').exists())
        self.assertFalse(self.client('failed').exists())
        self.assert_old_preserved()
        self.cli('add', 'failed')
        self.assert_qr('failed')

    def test_rejected_live_apply_and_failed_rollback_retry(self):
        before = self.server.read_bytes()
        real_run = vpn.run

        def rejected(*args, **kwargs):
            if args[:2] == ('awg', 'set') and 'remove' not in args:
                raise vpn.AccessError('Controlled rejection before mutation')
            return real_run(*args, **kwargs)

        with patch.object(vpn, 'run', side_effect=rejected):
            with self.assertRaises(vpn.AccessError):
                vpn.add(self.state, self.profile, 'rejected')
        self.assertTrue(self.server.read_bytes() == before)
        self.assertEqual(len(vpn.snapshot(self.profile)[1]), 1)
        self.assertFalse((self.state / 'pending.json').exists())

        def unreachable(*args, **kwargs):
            if args[:2] == ('awg', 'set'):
                raise vpn.AccessError('Controlled temporary interface failure')
            return real_run(*args, **kwargs)

        with patch.object(vpn, 'run', side_effect=unreachable):
            with self.assertRaises(vpn.AccessError):
                vpn.add(self.state, self.profile, 'retry')
        self.assertTrue((self.state / 'pending.json').exists())
        self.cli('add', 'retry')
        self.assertFalse((self.state / 'pending.json').exists())
        self.assert_old_preserved()
        self.assert_qr('retry')

    def test_awg2_normal_qr_and_zero_padding(self):
        self.server_text = self.server_text.replace('S1 = 15', 'S1 = 0').replace('S2 = 16', 'S2 = 0')
        self.server_text = self.server_text.replace('H1 = 101', 'S3 = 17\nS4 = 18\nI1 = <b 0xabc123>\nH1 = 111-115')
        vpn.atomic(self.server, self.server_text)
        self.apply_server()
        self.profile['client_format'] = '2'
        vpn.atomic(self.state / 'profile.json', json.dumps(self.profile))
        self.cli('add', 'phone')
        self.assert_qr('phone')
        self.cli('add', 'phone')
        self.assert_old_preserved()
        self.start_interface(self.client_interface)
        stripped = self.root / 'v2.conf'
        vpn.atomic(stripped, vpn.run('awg-quick', 'strip', str(self.client('phone'))))
        vpn.run('awg', 'setconf', self.client_interface, str(stripped))

    def test_crash_recovery_on_next_invocation(self):
        real_run = vpn.run

        def crashing(*args, **kwargs):
            result = real_run(*args, **kwargs)
            if args[:2] == ('awg', 'set') and 'remove' not in args:
                raise KeyboardInterrupt()
            return result

        with patch.object(vpn, 'run', side_effect=crashing), patch.object(vpn, 'recover'):
            with self.assertRaises(KeyboardInterrupt):
                vpn.add(self.state, self.profile, 'interrupted')
        self.assertTrue((self.state / 'pending.json').exists())
        self.assertEqual(len(vpn.snapshot(self.profile)[1]), 2)
        self.cli('add', 'recovered')
        self.assertEqual(len(vpn.snapshot(self.profile)[1]), 2)
        self.assertEqual(len(vpn.parse(self.server.read_text())[1]), 2)
        self.assertFalse(self.client('interrupted').exists())
        self.assertFalse((self.state / 'pending.json').exists())
        self.assert_old_preserved()
        self.assert_qr('recovered')

    def test_live_only_peer_address_is_reserved(self):
        pub = vpn.public(vpn.run('awg', 'genkey').strip())
        vpn.run('awg', 'set', self.interface, 'peer', pub, 'allowed-ips', '10.77.0.3/32,fd77::3/128')
        self.cli('add', 'phone')
        client, _ = vpn.parse(self.client('phone').read_text())
        self.assertTrue(set(vpn.networks(client['address'])) == set(vpn.networks('10.77.0.4/32, fd77::4/128')))
        self.assertTrue(pub in vpn.snapshot(self.profile)[1])
        self.assert_old_preserved()

    def test_awg2_and_qr_capacity_preserves_working_conf(self):
        # A real, valid large AWG2 signature exceeds QR byte mode capacity.
        signature = '<b 0x' + 'ab' * 1300 + '>'
        self.server_text = self.server_text.replace('H1 = 101', 'S3 = 0\nS4 = 0\nI1 = ' + signature + '\nH1 = 111-115')
        vpn.atomic(self.server, self.server_text)
        self.apply_server()
        self.cli('add', 'unsupported', expected=1)
        self.assertEqual(len(vpn.snapshot(self.profile)[1]), 1)
        profile = dict(self.profile, client_format='2')
        vpn.atomic(self.state / 'profile.json', json.dumps(profile))
        self.profile = profile
        self.cli('add', 'large', expected=2)
        conf = self.client('large')
        self.assertTrue(conf.exists())
        self.assertFalse(conf.with_suffix('.png').exists())
        client, remote = vpn.parse(conf.read_text())
        self.assertTrue(client['i1'] == signature)
        self.assertEqual(len(vpn.snapshot(profile)[1]), 2)
        stripped = self.root / 'large-stripped.conf'
        vpn.atomic(stripped, vpn.run('awg-quick', 'strip', str(conf)))
        self.start_interface(self.client_interface)
        vpn.run('awg', 'setconf', self.client_interface, str(stripped))
        before = conf.read_bytes()
        self.cli('add', 'large', expected=2)
        self.assertTrue(conf.read_bytes() == before)
        self.assert_old_preserved()

    def test_drift_and_saveconfig_refused_before_mutation(self):
        for replace in [('SaveConfig = false', 'SaveConfig = true'), ('S1 = 15', 'S1 = 17')]:
            changed = self.server_text.replace(*replace)
            vpn.atomic(self.server, changed)
            self.cli('add', 'phone', expected=1)
            self.assertTrue(self.server.read_text() == changed)
            self.assertEqual(len(vpn.snapshot(self.profile)[1]), 1)
            self.assertFalse(self.client('phone').exists())
        self.assert_old_preserved()


if __name__ == '__main__':
    unittest.main()
