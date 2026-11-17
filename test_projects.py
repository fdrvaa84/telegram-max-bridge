"""Project isolation checks. Integration runs only in a disposable container.

Run TELEMAX_PROJECT_INTEGRATION=1 python -m unittest -v test_projects inside
Ubuntu with NET_ADMIN, /dev/net/tun, official AWG tools and system dependencies.
System service control is simulated, its VPN commands and HTTP processes are real.
Never run integration on a working server.
"""
import concurrent.futures
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import project
import vpn_access as vpn


class ProjectTests(unittest.TestCase):
    def test_installer_accepts_current_ubuntu_and_rejects_unknown_systems(self):
        installer = Path(__file__).with_name('install.sh').read_text()
        check = next(line for line in installer.splitlines() if line.startswith('case "$ID:$VERSION_ID"'))
        for system, version, accepted in [('ubuntu', '26.04', True), ('ubuntu', '24.04', True),
                                          ('debian', '13', True), ('ubuntu', '99.99', False)]:
            result = subprocess.run(['bash', '-c', check], env=dict(os.environ, ID=system, VERSION_ID=version),
                                    capture_output=True)
            self.assertEqual(result.returncode == 0, accepted, (system, version))
        dependencies = next(line for line in installer.splitlines() if line.startswith('apt-get install'))
        self.assertIn('iptables', dependencies.split())

    def test_names_and_routes_reject_injection(self):
        for name in ('../other', 'bad/name', '-x', 'a' * 21, 'Test'):
            with self.assertRaises(ValueError):
                project.metadata(name)
        for domain in ('example.org\nimport other', 'example.org {', ';id'):
            with self.assertRaises(ValueError):
                project.route(domain, 13000)
        self.assertIn('127.0.0.1:13000', project.route('one.example.org', 13000))

    def test_allocation_preserves_reservations_and_skips_listener(self):
        real_path = Path
        with tempfile.TemporaryDirectory() as temp:
            def path(value):
                return real_path(temp) / str(value).lstrip('/')
            with patch.object(project, 'Path', side_effect=path), socket.socket() as listener:
                reserved = project.allocate('probe')
                project.metadata('probe').unlink()
                listener.bind(('127.0.0.1', reserved))
                one = project.allocate('one')
                two = project.allocate('two')
                self.assertNotEqual(one, reserved)
                self.assertNotEqual(one, two)
                self.assertEqual(project.allocate('one'), one)

    def test_new_https_receiver_retry_and_stopped_receiver(self):
        for failure, prior_route in (('validate', None), ('enable', 'previous route\n')):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                def path(value):
                    if str(value).startswith('/tmp/'):
                        return Path(value)
                    return root / str(value).lstrip('/')
                active = False
                failed = False
                def run(args, **kwargs):
                    if args[:2] == ['apt-get', 'download']:
                        (Path(kwargs['cwd']) / 'caddy_test.deb').touch()
                    return subprocess.CompletedProcess(args, 0 if active else 3)
                def call(*args):
                    nonlocal active, failed
                    if (args[1:2] == (failure,) and not failed):
                        failed = True
                        if failure == 'enable':
                            active = True  # Partial start must also be undone.
                        raise ValueError('temporary failure')
                    if args[:3] == ('systemctl', 'enable', '--now'):
                        active = True
                    if args[:3] == ('systemctl', 'disable', '--now'):
                        active = False
                    return ''
                foreign = path('/etc/telemax/sites/foreign.caddy')
                project.write(foreign, 'foreign route\n')
                target = path('/etc/telemax/sites/project-alpha.caddy')
                if prior_route is not None:
                    project.write(target, prior_route)
                with patch.object(project, 'Path', side_effect=path), \
                     patch.object(project.subprocess, 'run', side_effect=run), \
                     patch.object(project, 'call', side_effect=call):
                    with self.assertRaisesRegex(ValueError, 'temporary failure'):
                        project.https('alpha', 'alpha.example.org', 13117)
                    self.assertFalse(active)
                    self.assertEqual(target.read_text() if target.exists() else None, prior_route)
                    # The normal second command must complete the initial install.
                    project.https('alpha', 'alpha.example.org', 13117)
                    self.assertTrue(active)
                    config = path('/etc/telemax/Caddyfile')
                    unit = path('/etc/systemd/system/telemax-web.service')
                    before = (config.read_bytes(), unit.read_bytes(), target.read_bytes())
                    active = False  # A later intentional stop must be respected.
                    with self.assertRaisesRegex(ValueError, 'остановлен'):
                        project.https('alpha', 'alpha.example.org', 13117)
                    self.assertFalse(active)
                    self.assertEqual(before, (config.read_bytes(), unit.read_bytes(), target.read_bytes()))
                    self.assertEqual(foreign.read_text(), 'foreign route\n')

    def test_firewall_rules_are_project_scoped(self):
        profile = dict(interface='tm9', subnet='10.9.0.0/24', external='eth0', port=42009)
        for table, chain, spec in vpn.firewall_rules(profile):
            self.assertIn('telemax-tm9', spec)
            self.assertTrue('42009' in spec or '10.9.0.0/24' in spec)
        self.assertEqual(len(vpn.firewall_rules(profile)), 4)


    def test_two_bridge_processes_keep_receivers_and_state_separate(self):
        import time
        import urllib.error
        import urllib.request
        import bridge
        script = '''import asyncio,sys
from argparse import Namespace
import bridge
async def api(self,*args,**kwargs): return {'user_id':self.c['max_bot_id']}
bridge.Bridge.api=api
asyncio.run(bridge.main(Namespace(config=sys.argv[1],check=False,login=False,enable=False)))
'''
        with tempfile.TemporaryDirectory() as temp:
            children = []
            ports = []
            try:
                for number in (1, 2):
                    root = Path(temp) / str(number)
                    root.mkdir()
                    with socket.socket() as sock:
                        sock.bind(('127.0.0.1', 0))
                        port = sock.getsockname()[1]
                    ports.append(port)
                    config = dict(enabled=False, port=port, max_bot_id=number, max_owner_id=number,
                                  state_dir=str(root / 'state'), webhook_secret='synthetic-' + str(number))
                    vpn.atomic(root / 'config.json', json.dumps(config))
                    store = bridge.Store(root / 'state')
                    store.set('project', number)
                    store.close()
                    child = subprocess.Popen([sys.executable, '-c', script, str(root / 'config.json')],
                                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    children.append(child)
                self.assertNotEqual(*ports)
                for number, port in enumerate(ports, 1):
                    for _ in range(100):
                        try:
                            with urllib.request.urlopen(f'http://127.0.0.1:{port}/health', timeout=1) as response:
                                self.assertTrue(json.load(response)['ready'])
                            break
                        except OSError:
                            time.sleep(.05)
                    else:
                        self.fail('Receiver did not start')
                    request = urllib.request.Request(f'http://127.0.0.1:{port}/webhook', data=b'{}',
                              headers={'X-Max-Bot-Api-Secret': 'synthetic-' + str(3-number), 'Content-Type': 'application/json'})
                    with self.assertRaises(urllib.error.HTTPError) as error:
                        urllib.request.urlopen(request, timeout=1)
                    self.assertEqual(error.exception.code, 403)
                    request.add_header('X-Max-Bot-Api-Secret', 'synthetic-' + str(number))
                    with urllib.request.urlopen(request, timeout=1) as response:
                        self.assertEqual(json.load(response), {'handled': False})
            finally:
                for child in children:
                    child.terminate()
                for child in children:
                    out, err = child.communicate(timeout=10)
                    self.assertEqual(child.returncode, 0, err.decode())
            for number in (1, 2):
                store = bridge.Store(Path(temp) / str(number) / 'state')
                self.assertEqual(store.get('project'), number)
                store.close()


SHIM = '''#!/usr/bin/env python3
import os, pathlib, subprocess, sys
args=[a for a in sys.argv[1:] if a not in ('--quiet','--now')]
cmd=args[0]
name=args[-1].removesuffix('.service')
root=pathlib.Path('/tmp/project-services'); root.mkdir(exist_ok=True)
active=root/(name+'.active'); enabled=root/(name+'.enabled')
if cmd == 'daemon-reload': sys.exit(0)
if cmd == 'is-active': sys.exit(0 if active.exists() else 3)
if cmd == 'is-enabled': sys.exit(0 if enabled.exists() else 1)
if cmd in ('disable','enable'):
 if cmd == 'enable': enabled.touch()
 else: enabled.unlink(missing_ok=True)
 if '--now' not in sys.argv: sys.exit(0)
 cmd='start' if cmd=='enable' else 'stop'
if cmd == 'try-restart':
 if not active.exists(): sys.exit(0)
 cmd='restart'
if cmd == 'restart':
 subprocess.run([sys.argv[0], 'stop', name], check=True)
 cmd='start'
if cmd in ('start','stop'):
 if name.startswith('telemax-vpn-') and (cmd=='start' or active.exists()):
  p=name[len('telemax-vpn-'):]
  result=subprocess.run(['/usr/local/bin/telemax-vpn','--project',p,'up' if cmd=='start' else 'down'],
                        stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
  if result.returncode: sys.exit(result.returncode)
 if cmd=='start': active.touch()
 else: active.unlink(missing_ok=True)
 sys.exit(0)
sys.exit(2)
'''


@unittest.skipUnless(os.environ.get('TELEMAX_PROJECT_INTEGRATION') == '1', 'disposable container only')
class ProjectIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not Path('/.dockerenv').exists() or os.geteuid() != 0:
            raise RuntimeError('Integration requires a disposable root container')
        cls.source = Path(__file__).resolve().parent
        cls.env = dict(os.environ)
        cls.env.pop('TELEMAX_PROJECT_INTEGRATION', None)
        shim = Path('/tmp/project-bin')
        shim.mkdir(exist_ok=True)
        (shim / 'systemctl').write_text(SHIM)
        (shim / 'systemctl').chmod(0o755)
        cls.env['PATH'] = str(shim) + ':' + cls.env['PATH']
        cls.server_ip = json.loads(vpn.run('ip', '-j', '-4', 'address', 'show', 'dev', 'eth0'))[0]['addr_info'][0]['local']
        Path('/run/systemd/system').mkdir(parents=True, exist_ok=True)
        # A third-party VPN and listener exist before installation begins.
        foreign_config = Path('/tmp/foreignawg.conf')
        private = vpn.key(vpn.run('awg', 'genkey').strip())
        foreign_peer = vpn.public(vpn.run('awg', 'genkey').strip())
        psk = vpn.key(vpn.run('awg', 'genpsk').strip())
        vpn.atomic(foreign_config, f'[Interface]\nPrivateKey = {private}\nAddress = 10.234.1.1/24\nListenPort = 42000\nSaveConfig = false\nJc = 4\nJmin = 40\nJmax = 70\nS1 = 56\nS2 = 120\nH1 = 111\nH2 = 222\nH3 = 333\nH4 = 444\n[Peer]\nPublicKey = {foreign_peer}\nPresharedKey = {psk}\nAllowedIPs = 10.234.1.2/32\n')
        cls.foreign_before = foreign_config.read_bytes()
        vpn.run('awg-quick', 'up', str(foreign_config))
        cls.addClassCleanup(vpn.run, 'awg-quick', 'down', str(foreign_config))
        cls.foreign_http = subprocess.Popen([sys.executable, '-m', 'http.server', '19090', '--bind', '127.0.0.1'],
                                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        cls.addClassCleanup(cls.foreign_http.wait, timeout=10)
        cls.addClassCleanup(cls.foreign_http.terminate)
        def install(name):
            result = subprocess.run(['bash', str(cls.source / 'install.sh'), '--project', name],
                                    env=cls.env, capture_output=True, timeout=300)
            if result.returncode:
                raise AssertionError((result.stdout + result.stderr).decode()[-1500:])
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            list(pool.map(install, ('alpha', 'beta')))

    def cli(self, *args, expected=0):
        result = subprocess.run(args, env=self.env, capture_output=True, timeout=120)
        self.assertEqual(result.returncode, expected, result.stderr.decode()[-1000:])
        return result.stdout

    def test_selected_update_rollback_and_setup_state(self):
        import shutil
        git = Path('/tmp/project-bin/git')
        git.write_text('#!/usr/bin/env python3\nimport shutil,sys\nshutil.copytree(' + repr(str(self.source)) + ',sys.argv[-1])\n')
        git.chmod(0o755)
        try:
            for name, active in (('alpha', True), ('beta', False)):
                unit = 'telemax-' + name
                self.cli('systemctl', 'start' if active else 'stop', unit)
                current = Path('/opt/telemax/projects') / name / 'current'
                before = current.resolve()
                config = Path('/var/lib/telemax-projects') / name / 'config.json'
                original = config.read_bytes()
                self.cli('/usr/local/bin/telemax', '--project', name, 'configure', expected=1)
                self.cli('systemctl', 'is-active', '--quiet', unit, expected=0 if active else 3)
                self.cli('/usr/local/bin/telemax', '--project', name, 'update')
                self.assertNotEqual(current.resolve(), before)
                self.cli('systemctl', 'is-active', '--quiet', unit, expected=0 if active else 3)
                self.assertTrue(config.read_bytes() == original, 'Private settings changed')
                self.cli('/usr/local/bin/telemax', '--project', name, 'rollback')
                self.assertEqual(current.resolve(), before)
                self.cli('systemctl', 'is-active', '--quiet', unit, expected=0 if active else 3)
                self.assertTrue(config.read_bytes() == original, 'Private settings changed')
        finally:
            git.unlink(missing_ok=True)

    def test_two_projects_real_awg_qr_concurrency_and_recovery(self):
        old = self.cli('awg', 'show', 'all', 'dump')
        listeners = self.cli('ss', '-H', '-ltnu')
        foreign = Path('/tmp/foreign-project')
        foreign.mkdir(exist_ok=True)
        (foreign / 'state').write_bytes(b'unrelated project')
        foreign_rule = ['iptables', '-A', 'INPUT', '-p', 'tcp', '--dport', '19090', '-j', 'ACCEPT']
        self.cli(*foreign_rule)
        # A published container port can be occupied solely by a DNAT rule.
        self.cli('iptables', '-t', 'nat', '-A', 'PREROUTING', '-p', 'udp', '--dport', '42001',
                 '-j', 'DNAT', '--to-destination', '192.0.2.1:42001')
        def create(name):
            self.cli('/usr/local/bin/telemax-vpn', '--project', name, 'create',
                     '--public-ip', self.server_ip, '--dns', '1.1.1.1')
        # Force one failure after a real firewall insertion during preparation.
        import shutil
        real_iptables = shutil.which('iptables')
        fault = Path('/tmp/iptables-project-fault')
        fault.touch()
        wrapper = Path('/tmp/project-bin/iptables')
        wrapper.write_text('#!/usr/bin/env python3\nimport pathlib,subprocess,sys\n'
                           'r=subprocess.run([' + repr(real_iptables) + ']+sys.argv[1:])\n'
                           'p=pathlib.Path("/tmp/iptables-project-fault")\n'
                           'if p.exists() and "-I" in sys.argv and "FORWARD" in sys.argv:\n p.unlink()\n sys.exit(1)\n'
                           'sys.exit(r.returncode)\n')
        wrapper.chmod(0o755)
        try:
            self.cli('/usr/local/bin/telemax-vpn', '--project', 'alpha', 'create',
                     '--public-ip', self.server_ip, '--dns', '1.1.1.1', expected=1)
        finally:
            wrapper.unlink()
        state = Path('/etc/telemax/projects/alpha/vpn')
        pending = json.loads((state / 'creation.json').read_text())
        original_key = vpn.parse(Path(pending['server_config']).read_text())[0]['privatekey']
        self.assertNotIn(pending['interface'], self.cli('awg', 'show', 'interfaces').decode().split())
        self.assertNotIn(('telemax-' + pending['interface']).encode(), self.cli('iptables-save'))
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
            list(pool.map(create, ('alpha', 'beta', 'alpha')))
        self.assertTrue(vpn.parse(Path(pending['server_config']).read_text())[0]['privatekey'] == original_key, 'Key changed during recovery')
        profiles = []
        for name in ('alpha', 'beta'):
            state = Path('/etc/telemax/projects') / name / 'vpn'
            profile = json.loads((state / 'profile.json').read_text())
            profiles.append(profile)
            self.assertNotEqual(profile['port'], 42001)
            def issue(device):
                self.cli('/usr/local/bin/telemax-vpn', '--project', name, 'add', device)
            with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
                list(pool.map(issue, ('phone', 'laptop', 'phone', 'tablet')))
            conf = state / 'devices/phone/phone.conf'
            before = conf.read_bytes()
            issue('phone')
            self.assertTrue(conf.read_bytes() == before, 'Device bytes changed')
            decoded = self.cli('zbarimg', '--quiet', '--raw', str(conf.with_suffix('.png')))
            self.assertTrue(decoded == before + b'\n', 'QR bytes differ')
            self.assertEqual(conf.stat().st_mode & 0o777, 0o600)
            self.assertEqual(conf.parent.stat().st_mode & 0o777, 0o700)
            self.assertEqual(len(vpn.snapshot(profile)[1]), 3)
            # Failure after real peer application must roll back exact old bytes.
            config = Path(profile['server_config'])
            original = config.read_bytes()
            backup = config.with_suffix('.test-backup')
            config.rename(backup)
            try:
                self.cli('/usr/local/bin/telemax-vpn', '--project', name, 'create',
                         '--public-ip', self.server_ip, '--dns', '1.1.1.1', expected=1)
                self.assertFalse(config.exists())
                self.assertEqual(len(vpn.snapshot(profile)[1]), 3)
            finally:
                backup.rename(config)
            real_run = vpn.run
            def fail(*args, **kwargs):
                result = real_run(*args, **kwargs)
                if args[:2] == ('awg', 'set') and 'remove' not in args:
                    raise vpn.AccessError('controlled failure')
                return result
            with vpn.locked(state / '.lock'), patch.object(vpn, 'run', side_effect=fail):
                with self.assertRaises(vpn.AccessError):
                    vpn.add(state, profile, 'failed')
            self.assertTrue(config.read_bytes() == original, 'Private settings changed')
            self.assertEqual(len(vpn.snapshot(profile)[1]), 3)
            # Simulate interruption that also prevents rollback, then recover via CLI.
            with vpn.locked(state / '.lock'), patch.object(vpn, 'run', side_effect=fail), patch.object(vpn, 'recover'):
                with self.assertRaises(vpn.AccessError):
                    vpn.add(state, profile, 'crashed')
            self.assertTrue((state / 'pending.json').exists())
            issue('recovered')
            self.assertFalse((state / 'pending.json').exists())
            self.assertFalse((state / 'devices/crashed').exists())
            self.assertEqual(len(vpn.snapshot(profile)[1]), 4)
            self.cli('/usr/local/bin/telemax-vpn', '--project', name, 'down')
            self.cli('/usr/local/bin/telemax-vpn', '--project', name, 'up')
            self.assertEqual(len(vpn.snapshot(profile)[1]), 4)
            issue('phone')
            self.cli('systemctl', 'stop', 'telemax-vpn-' + name)
            create(name)
            self.cli('systemctl', 'is-active', '--quiet', 'telemax-vpn-' + name, expected=3)
            self.cli('systemctl', 'start', 'telemax-vpn-' + name)
        clients = [Path('/etc/telemax/projects') / n / 'vpn/devices/phone/phone.conf' for n in ('alpha', 'beta')]
        self.assertTrue(vpn.parse(clients[0].read_text())[0]['privatekey'] != vpn.parse(clients[1].read_text())[0]['privatekey'], 'Device keys overlap')
        for field in ('interface', 'port', 'subnet', 'server_config'):
            self.assertNotEqual(profiles[0][field], profiles[1][field])
        one = json.loads(Path('/opt/telemax/projects/alpha/project.json').read_text())
        two = json.loads(Path('/opt/telemax/projects/beta/project.json').read_text())
        self.assertNotEqual(one['port'], two['port'])
        self.assertEqual((foreign / 'state').read_bytes(), b'unrelated project')
        self.assertTrue(Path('/tmp/foreignawg.conf').read_bytes() == self.foreign_before, 'Foreign settings changed')
        self.cli('iptables', '-C', *foreign_rule[2:])
        # Existing interfaces and listeners remain present after project operations.
        for line in old.splitlines():
            self.assertTrue(line in self.cli('awg', 'show', 'all', 'dump').splitlines(), 'Foreign VPN changed')
        for line in listeners.splitlines():
            self.assertIn(line, self.cli('ss', '-H', '-ltnu').splitlines())

    def test_selected_commands_and_shared_https(self):
        import asyncio
        from aiohttp import web, ClientSession
        ports = []
        for name in ('alpha', 'beta'):
            meta = json.loads((Path('/opt/telemax/projects') / name / 'project.json').read_text())
            port = meta['port']
            ports.append(port)
            root = Path('/var/lib/telemax-projects') / name
            config = dict(enabled=False, port=port, domain=name + '.localhost',
                          state_dir=str(root / 'state'))
            vpn.atomic(root / 'config.json', json.dumps(config))
            import pwd
            owner = pwd.getpwnam('telemax-' + name)
            os.chown(root / 'config.json', owner.pw_uid, owner.pw_gid)
            self.cli('/usr/local/bin/telemax', '--project', name, 'status')
            self.cli('/usr/local/bin/telemax', '--project', name, 'logs')
            self.cli('/usr/local/bin/telemax', '--project', name, 'start', expected=1)
            self.cli('/usr/local/bin/telemax', '--project', name, 'https', '--fragment')
            self.assertIn(str(port), (Path('/etc/telemax/sites') / ('project-' + name + '.example')).read_text())
        # A real shared Caddy process retains a third-party route across reloads.
        config = Path('/tmp/shared-Caddyfile')
        config.write_text('{\n admin 127.0.0.1:22019\n local_certs\n}\nhttp://foreign.localhost:18080 {\n respond "foreign"\n}\n')
        caddy = subprocess.Popen(['caddy', 'run', '--config', str(config), '--adapter', 'caddyfile'],
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            import time
            for _ in range(100):
                try:
                    with socket.create_connection(('127.0.0.1', 22019), timeout=.1):
                        break
                except OSError:
                    time.sleep(.05)
            else:
                self.fail('Shared Caddy did not start')
            # Mark existing receiver active in the service-control simulation.
            Path('/tmp/project-services/caddy.active').touch()
            before = config.read_text()
            for name in ('alpha', 'beta'):
                self.cli('/usr/local/bin/telemax', '--project', name, 'https', '--caddy-config', str(config))
            self.assertTrue(config.read_text().startswith(before))
            self.assertIn('foreign.localhost', config.read_text())
            before = config.read_bytes()
            self.cli('/usr/local/bin/telemax', '--project', 'alpha', 'https', '--caddy-config', str(config), '--receiver', 'stopped', expected=1)
            self.assertEqual(config.read_bytes(), before)
            async def check():
                runners = []
                try:
                    for port in ports:
                        app = web.Application()
                        app.router.add_get('/health', lambda r, p=port: web.json_response({'port': p}))
                        runner = web.AppRunner(app)
                        await runner.setup()
                        await web.TCPSite(runner, '127.0.0.1', port).start()
                        runners.append(runner)
                    async with ClientSession() as http:
                        for name, port in zip(('alpha', 'beta'), ports):
                            async with http.get('https://127.0.0.1/health', headers={'Host': name + '.localhost'}, ssl=False, server_hostname=name + '.localhost') as response:
                                self.assertEqual(await response.json(), {'port': port})
                        async with http.get('http://127.0.0.1:18080', headers={'Host': 'foreign.localhost'}) as response:
                            self.assertEqual(await response.text(), 'foreign')
                finally:
                    for runner in runners:
                        await runner.cleanup()
            asyncio.run(check())
        finally:
            caddy.terminate()
            caddy.wait(timeout=10)
        # A failed first validation must not poison the ordinary retry.
        existing_route = Path('/etc/telemax/sites/project-alpha.caddy').read_bytes()
        wrapper = Path('/tmp/project-bin/caddy')
        wrapper.write_text('#!/bin/sh\nexit 1\n')
        wrapper.chmod(0o755)
        try:
            self.cli('/usr/local/bin/telemax', '--project', 'alpha', 'https', expected=1)
            self.assertFalse(Path('/etc/telemax/Caddyfile').exists())
            self.assertFalse(Path('/etc/systemd/system/telemax-web.service').exists())
            self.assertEqual(Path('/etc/telemax/sites/project-alpha.caddy').read_bytes(), existing_route)
        finally:
            wrapper.unlink()
        # Exercise the default shared receiver generated when 80/443 are free.
        self.cli('/usr/local/bin/telemax', '--project', 'alpha', 'https')
        self.cli('install', '-d', '-m', '700', '-o', 'telemax-web', '-g', 'telemax-web', '/run/telemax-web')
        managed = subprocess.Popen(['runuser', '-u', 'telemax-web', '--', 'env',
                                   'HOME=/var/lib/telemax-web', '/opt/telemax/web/usr/bin/caddy', 'run',
                                   '--config', '/etc/telemax/Caddyfile', '--adapter', 'caddyfile'],
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            for _ in range(100):
                if Path('/run/telemax-web/admin.sock').exists():
                    break
                time.sleep(.05)
            else:
                self.fail('Generated shared receiver did not start')
            self.cli('/usr/local/bin/telemax', '--project', 'beta', 'https')
            self.assertIsNone(managed.poll())
            self.cli('systemd-analyze', 'verify', '/etc/systemd/system/telemax-alpha.service',
                     '/etc/systemd/system/telemax-beta.service', '/etc/systemd/system/telemax-web.service')
        finally:
            managed.terminate()
            managed.wait(timeout=10)
        # Once installed successfully, an intentional stop stays stopped.
        self.cli('systemctl', 'stop', 'telemax-web')
        config = Path('/etc/telemax/Caddyfile')
        target = Path('/etc/telemax/sites/project-alpha.caddy')
        before = (config.read_bytes(), target.read_bytes())
        self.cli('/usr/local/bin/telemax', '--project', 'alpha', 'https', expected=1)
        self.cli('systemctl', 'is-active', '--quiet', 'telemax-web', expected=3)
        self.assertEqual(before, (config.read_bytes(), target.read_bytes()))


if __name__ == '__main__':
    unittest.main()
