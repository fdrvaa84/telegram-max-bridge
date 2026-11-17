#!/usr/bin/env python3
"""Private, transactional device provisioning for an existing awg-quick server."""
import argparse
import base64
import contextlib
import fcntl
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import signal
import secrets
import stat
import subprocess
import sys
import tempfile


class AccessError(Exception):
    pass


V1 = 'Jc Jmin Jmax S1 S2 H1 H2 H3 H4'.split()
V2 = 'S3 S4 I1 I2 I3 I4 I5'.split()
# AWG 3.1 requires client-side support beyond the standalone app's baseline.
V3 = ('HeaderProtectionKey ContentPaddingAddition RekeyAfterTime RekeyTimeout '
      'RejectAfterTime KeepaliveTimeout MaxHandshakeAttempts RandomTrailers DisableCookies').split()
QUICK = 'Address DNS MTU Table PreUp PostUp PreDown PostDown SaveConfig'.split()
KNOWN = {k.lower(): k for k in V1 + V2 + V3 + QUICK + ['PrivateKey', 'ListenPort', 'FwMark']}


def require(condition, message):
    if not condition:
        raise AccessError(message)


def run(*args, data=None):
    result = subprocess.run(args, input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            timeout=30)
    # Tool diagnostics can contain keys and configuration lines.
    require(result.returncode == 0, 'Не удалось выполнить действие с VPN. Секретные подробности скрыты.')
    return result.stdout.decode()


def key(value):
    try:
        valid = len(base64.b64decode(value, validate=True)) == 32
    except (ValueError, TypeError):
        valid = False
    require(valid, 'Некорректный ключ в настройках.')
    return value


def public(private):
    return key(run('awg', 'pubkey', data=(key(private) + '\n').encode()).strip())


def parse(text):
    sections = []
    for raw in text.splitlines():
        line = raw.split('#', 1)[0].strip()
        if not line:
            continue
        if line in ('[Interface]', '[Peer]'):
            sections.append((line[1:-1], {}))
            continue
        require(sections and '=' in line, 'Не удалось прочитать настройки VPN.')
        name, value = (v.strip() for v in line.split('=', 1))
        name = name.lower()
        values = sections[-1][1]
        # awg-quick permits repeated Address and hook directives.
        if name in values and name in ('address', 'dns', 'allowedips'):
            values[name] += ', ' + value
        elif name in values and name in ('preup', 'postup', 'predown', 'postdown'):
            values[name] += '\n' + value
        else:
            require(name not in values, 'Повторяющийся параметр VPN требует проверки.')
            values[name] = value
    require(sections and sections[0][0] == 'Interface' and
            sum(name == 'Interface' for name, _ in sections) == 1,
            'Ожидались серверные настройки awg-quick.')
    peers = {}
    for name, values in sections[1:]:
        require(name == 'Peer' and 'publickey' in values, 'Некорректное подключение в настройках.')
        pub = key(values['publickey'])
        require(pub not in peers, 'В настройках повторяется клиент.')
        peers[pub] = values
    return sections[0][1], peers


def networks(value):
    return [ipaddress.ip_network(v.strip(), strict=False) for v in value.split(',') if v.strip()]


def normalized(value):
    value = re.sub(r'\s+', '', value).lower()
    if re.fullmatch(r'\d+', value):
        return str(int(value))
    if re.fullmatch(r'(\d+)-(\d+)', value):
        a, b = value.split('-')
        if a == b:
            return str(int(a))
    return value


def private_file(path):
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and
            not info.st_mode & 0o077, 'Настройки должны принадлежать root и иметь права 600.')


def private_dir(path):
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid() and
            not info.st_mode & 0o077, 'Каталог выдачи должен принадлежать root и иметь права 700.')


def sync_dir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def atomic(path, content):
    fd, temp = tempfile.mkstemp(prefix='.write-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(content.encode() if isinstance(content, str) else content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, path)
        sync_dir(path.parent)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


@contextlib.contextmanager
def locked(path):
    fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


def snapshot(profile):
    return parse(run('awg', 'showconf', profile['interface']))


def validate_server(profile):
    path = Path(profile['server_config'])
    private_file(path)
    original = path.read_text()
    server, peers = parse(original)
    active, active_peers = snapshot(profile)
    require(not set(server) - set(KNOWN), 'Неизвестные параметры сервера требуют проверки совместимости.')
    require(server.get('saveconfig', 'false').lower() == 'false',
            'Для выдачи требуется SaveConfig=false, чтобы остановка сервера не перезаписывала клиентов.')
    require(public(server.get('privatekey', '')) == public(active.get('privatekey', '')),
            'Постоянные и действующие ключи сервера различаются.')
    require(server.get('listenport') and server['listenport'] == active.get('listenport'),
            'Постоянный и действующий порт сервера различаются.')
    endpoint = profile['endpoint']
    host, port = endpoint.rsplit(':', 1)
    endpoint_ip = ipaddress.ip_address(host.strip('[]'))
    expected_host = f'[{endpoint_ip}]' if endpoint_ip.version == 6 else str(endpoint_ip)
    require(host == expected_host, 'Укажите корректный публичный IP:порт, для IPv6 нужны квадратные скобки.')
    require(int(port) == int(server['listenport']) and 0 < int(port) < 65536,
            'Публичный порт должен совпадать с подготовленным сервером. Перенаправление портов не поддерживается.')
    obfuscation = {}
    for name in V1 + V2 + V3:
        field = name.lower()
        if field in server:
            effective = active.get(field, '0') if name in V1[:5] + ['S3', 'S4'] else active.get(field)
            require(effective is not None and normalized(server[field]) == normalized(effective),
                    'Постоянные и действующие параметры AmneziaWG различаются.')
        if field in active:
            obfuscation[name] = active[field]
        elif field in server:
            obfuscation[name] = server[field]
    require(all(name in obfuscation for name in V1), 'У сервера отсутствуют проверяемые параметры AmneziaWG.')
    # Copy all effective fields, including omitted defaults, never invent obfuscation.
    require(not set(active) - {k.lower() for k in V1 + V2 + V3 + ['PrivateKey', 'ListenPort', 'FwMark']},
            'Действующая версия AmneziaWG пока не поддерживается выдачей.')
    for name in V3:
        if name.lower() not in server and normalized(obfuscation.get(name, 'off')) in ('off', 'false', '0'):
            obfuscation.pop(name, None)
    require(not any(name in obfuscation for name in V3),
            'Параметры AWG3.1 требуют отдельной проверки приложения. Автоматическая выдача поддерживает AWG1/2.')
    if profile['client_format'] == '1':
        require(not any(normalized(obfuscation.get(name, '0')) != '0' for name in ('S3', 'S4')) and
                not any(name in obfuscation for name in ('I1', 'I2', 'I3', 'I4', 'I5')) and
                not any('-' in obfuscation.get(name, '') for name in ('H1', 'H2', 'H3', 'H4')),
                'Параметры сервера требуют приложения с поддержкой AWG2.')
        obfuscation = {name: value for name, value in obfuscation.items() if name in V1}
    addresses = [ipaddress.ip_interface(v.strip()) for v in server.get('address', '').split(',') if v.strip()]
    require(addresses and len({v.version for v in addresses}) == len(addresses),
            'Поддерживается одна серверная подсеть каждого вида адресов.')
    live_addresses = json.loads(run('ip', '-j', 'address', 'show', 'dev', profile['interface']))
    assigned = {v['local'] for item in live_addresses for v in item.get('addr_info', [])}
    require(any('UP' in item.get('flags', []) for item in live_addresses), 'Подготовленное подключение VPN остановлено.')
    require(all(str(v.ip) in assigned for v in addresses), 'Серверные адреса отсутствуют на действующем подключении.')
    # Both sources reserve addresses, including live clients absent from the file.
    occupied = [net for peer in list(peers.values()) + list(active_peers.values())
                for net in networks(peer.get('allowedips', ''))]
    return path, original, peers, active_peers, addresses, occupied, obfuscation, public(server['privatekey'])


def free_addresses(addresses, occupied):
    selected = []
    for interface in addresses:
        subnet = interface.network
        candidate = int(subnet.network_address) + 1
        end = int(subnet.broadcast_address) - (1 if subnet.version == 4 else 0)
        blockers = occupied + [ipaddress.ip_network(f'{interface.ip}/{interface.max_prefixlen}')]
        while candidate <= end:
            address = ipaddress.ip_address(candidate) if subnet.version == 4 else ipaddress.IPv6Address(candidate)
            overlaps = [net for net in blockers if net.version == address.version and address in net]
            if overlaps:
                candidate = max(int(net.broadcast_address) for net in overlaps) + 1
                continue
            selected.append(f'{address}/{address.max_prefixlen}')
            break
        else:
            raise AccessError('В подготовленной подсети закончились свободные адреса.')
    return selected


def peer_matches(peer, expected):
    return (peer is not None and peer.get('presharedkey', '') == expected['presharedkey'] and
            set(networks(peer.get('allowedips', ''))) == set(networks(expected['allowedips'])))


def unchanged_peers(before, after):
    # Endpoints can roam while provisioning. Compare identity, routing and PSK only.
    for pub, peer in before.items():
        other = after.get(pub, {})
        require(other.get('presharedkey', '') == peer.get('presharedkey', '') and
                set(networks(other.get('allowedips', ''))) == set(networks(peer.get('allowedips', ''))) and
                pub in after, 'Обнаружено внешнее изменение существующего клиента. Требуется проверка.')


def qr(conf, image):
    temp = image.with_suffix('.pending.png')
    try:
        result = subprocess.run(['qrencode', '-8', '-l', 'M', '-o', str(temp)], input=conf.read_bytes(),
                                stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=30)
        if result.returncode:
            image.unlink(missing_ok=True)
            # Oversized obfuscation signatures can exceed the QR byte capacity.
            return False
        os.chmod(temp, 0o600)
        with temp.open('rb') as stream:
            os.fsync(stream.fileno())
        os.replace(temp, image)
        sync_dir(image.parent)
        return True
    finally:
        temp.unlink(missing_ok=True)


def recover(state, profile):
    journal = state / 'pending.json'
    if not journal.exists():
        return
    private_file(journal)
    pending = json.loads(journal.read_text())
    path = Path(profile['server_config'])
    private_file(path)
    current = path.read_text()
    require(current in (pending['before'], pending['after']),
            'После прерванной выдачи настройки изменились извне. Сохранена закрытая копия для восстановления.')
    final = state / 'devices' / pending['name']
    if final.exists() and current == pending['after']:
        # Rename is the commit point. A crash after it only needs cleanup.
        _, peers = snapshot(profile)
        require(peer_matches(peers.get(pending['public']), pending['peer']),
                'Прерванная выдача требует восстановления действующего подключения.')
    else:
        run('awg', 'set', profile['interface'], 'peer', pending['public'], 'remove')
        require(pending['public'] not in snapshot(profile)[1], 'Не удалось убрать незавершённое подключение.')
        if current == pending['after']:
            atomic(path, pending['before'])
        require(path.read_text() == pending['before'], 'Не удалось вернуть постоянные настройки.')
        unchanged_peers(pending['existing'], snapshot(profile)[1])
        shutil.rmtree(state / 'devices' / ('.pending-' + pending['name']), ignore_errors=True)
    journal.unlink()
    sync_dir(state)


def add(state, profile, name):
    require(re.fullmatch(r'[a-zA-Z0-9_-]{1,15}', name), 'Имя устройства: до 15 латинских букв, цифр, дефисов или подчёркиваний.')
    for program in ('awg', 'qrencode', 'ip'):
        require(shutil.which(program), 'Установите awg, iproute2 и qrencode по инструкции.')
    recover(state, profile)
    path, original, peers, active_peers, addresses, occupied, obfuscation, server_public = validate_server(profile)
    devices = state / 'devices'
    private_dir(devices)
    final = devices / name
    if final.exists():
        private_dir(final)
        conf = final / (name + '.conf')
        private_file(conf)
        client, remote = parse(conf.read_text())
        pub = public(client['privatekey'])
        require(len(remote) == 1, 'В сохранённом доступе ожидался один сервер.')
        expected = {'allowedips': client['address'], 'presharedkey': next(iter(remote.values()))['presharedkey']}
        remote_peer = remote.get(server_public, {})
        require(remote_peer.get('endpoint') == profile['endpoint'] and
                remote_peer.get('allowedips') == profile['routes'] and client.get('dns') == profile['dns'] and
                all(normalized(client.get(field.lower(), '')) == normalized(value)
                    for field, value in obfuscation.items()),
                'Сохранённые настройки устройства отличаются от подготовленного сервера.')
        require(peer_matches(peers.get(pub), expected) and peer_matches(active_peers.get(pub), expected),
                'Сохранённый доступ расходится с сервером. Новые ключи не создавались, требуется проверка.')
        image = final / (name + '.png')
        ok = qr(conf, image)
        return conf, image, ok
    stage = devices / ('.pending-' + name)
    if stage.exists():
        # A crash before the journal cannot have touched the server.
        private_dir(stage)
        shutil.rmtree(stage)
    private_dir(stage)
    conf = stage / (name + '.conf')
    image = stage / (name + '.png')
    try:
        private = key(run('awg', 'genkey').strip())
        pub = public(private)
        psk = key(run('awg', 'genpsk').strip())
        require(pub not in peers and pub not in active_peers, 'Новый ключ совпал с существующим.')
        allocated = ', '.join(free_addresses(addresses, occupied))
        link = json.loads(run('ip', '-j', 'link', 'show', 'dev', profile['interface']))
        mtu = int(link[0]['mtu'])
        content = ('[Interface]\nPrivateKey = ' + private + '\nAddress = ' + allocated +
                   '\nDNS = ' + profile['dns'] + f'\nMTU = {mtu}\n' +
                   ''.join(f'{field} = {value}\n' for field, value in obfuscation.items()) +
                   '\n[Peer]\nPublicKey = ' + server_public + '\nPresharedKey = ' + psk +
                   '\nEndpoint = ' + profile['endpoint'] + '\nAllowedIPs = ' + profile['routes'] +
                   '\nPersistentKeepalive = 25\n')
        atomic(conf, content)
        ok = qr(conf, image)
        peer = {'allowedips': allocated, 'presharedkey': psk}
        block = f'\n# telemax-vpn device {name}\n[Peer]\nPublicKey = {pub}\nPresharedKey = {psk}\nAllowedIPs = {allocated}\n'
        updated = original.rstrip() + '\n' + block
        # Durable recovery record precedes any persistent or live mutation.
        atomic(state / 'pending.json', json.dumps({'name': name, 'public': pub, 'peer': peer,
                                                  'before': original, 'after': updated, 'existing': active_peers}))
        require(path.read_text() == original, 'Серверные настройки изменились во время выдачи.')
        atomic(path, updated)
        psk_file = stage / 'psk'
        atomic(psk_file, psk + '\n')
        try:
            run('awg', 'set', profile['interface'], 'peer', pub, 'preshared-key', str(psk_file),
                'allowed-ips', allocated.replace(' ', ''))
        finally:
            psk_file.unlink(missing_ok=True)
        _, after = snapshot(profile)
        require(peer_matches(after.get(pub), peer), 'Сервер не подтвердил новый доступ.')
        unchanged_peers(active_peers, after)
        require(path.read_text() == updated and peer_matches(parse(updated)[1].get(pub), peer),
                'Постоянные настройки нового доступа не подтверждены.')
        os.rename(stage, final)
        sync_dir(devices)
        (state / 'pending.json').unlink()
        sync_dir(state)
        return final / conf.name, final / image.name, ok
    except BaseException:
        # A failed rollback leaves the journal intact for the next invocation.
        if (state / 'pending.json').exists():
            recover(state, profile)
        else:
            shutil.rmtree(stage, ignore_errors=True)
        raise


def project_state(name):
    require(re.fullmatch(r'[a-z][a-z0-9-]{0,19}', name), 'Некорректное имя проекта.')
    require((Path('/opt/telemax/projects') / name / 'project.json').is_file(),
            'Сначала установите выбранный проект.')
    return Path('/etc/telemax/projects') / name / 'vpn'


def firewall_rules(profile):
    interface, subnet, external = profile['interface'], profile['subnet'], profile['external']
    tag = ['-m', 'comment', '--comment', 'telemax-' + interface]
    return [
        ('filter', 'INPUT', ['-p', 'udp', '--dport', str(profile['port']), *tag, '-j', 'ACCEPT']),
        ('filter', 'FORWARD', ['-i', interface, '-o', external, '-s', subnet, *tag, '-j', 'ACCEPT']),
        ('filter', 'FORWARD', ['-i', external, '-o', interface, '-d', subnet,
                             '-m', 'conntrack', '--ctstate', 'RELATED,ESTABLISHED', *tag, '-j', 'ACCEPT']),
        ('nat', 'POSTROUTING', ['-s', subnet, '-o', external, *tag, '-j', 'MASQUERADE'])]


def firewall(profile, enable):
    for table, chain, spec in firewall_rules(profile):
        check = subprocess.run(['iptables', '-w', '10', '-t', table, '-C', chain, *spec],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)
        require(check.returncode in (0, 1), 'Не удалось проверить действующие правила трафика.')
        if enable and check.returncode == 1:
            run('iptables', '-w', '10', '-t', table, '-I', chain, '1', *spec)
        elif not enable and check.returncode == 0:
            run('iptables', '-w', '10', '-t', table, '-D', chain, *spec)


def vpn_lifecycle(state, enable):
    private_file(state / 'creation.json')
    profile = json.loads((state / 'creation.json').read_text())
    config = Path(profile['server_config'])
    private_file(config)
    interface = profile['interface']
    interfaces = run('awg', 'show', 'interfaces').split()
    if not enable:
        # Only remove rules and the interface reserved by this project's record.
        if interface in interfaces:
            validate_server(profile)
            run('awg-quick', 'down', str(config))
        firewall(profile, False)
        return
    created = False
    try:
        if interface not in interfaces:
            run('awg-quick', 'up', str(config))
            created = True
        validate_server(profile)
        firewall(profile, True)
    except BaseException:
        # awg-quick handles partial interface setup itself. Clean our exact rules.
        firewall(profile, False)
        if created:
            run('awg-quick', 'down', str(config))
        raise


def create_project_vpn(state, name, public_ip, dns):
    for program in ('awg', 'awg-quick', 'amneziawg-go', 'ip', 'iptables', 'qrencode'):
        require(shutil.which(program), 'Нужны существующие awg, awg-quick, amneziawg-go, iproute2, iptables и qrencode. Установите только недостающие программы по официальной инструкции.')
    public_ip = str(ipaddress.IPv4Address(public_ip))
    dns = ', '.join(str(ipaddress.ip_address(v.strip())) for v in dns.split(','))
    record = state / 'creation.json'
    initialized = (state / 'profile.json').exists()
    unit = 'telemax-vpn-' + name
    was_active = subprocess.run(['systemctl', 'is-active', '--quiet', unit],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0
    private_dir(Path('/run/telemax'))
    with locked(Path('/run/telemax/vpn-create.lock')):
        if record.exists():
            private_file(record)
            profile = json.loads(record.read_text())
            require(profile['endpoint'].rsplit(':', 1)[0] == public_ip and profile['dns'] == dns,
                    'Проект уже имеет другие параметры VPN. Существующие данные сохранены.')
        else:
            require(not (state / 'profile.json').exists(), 'Проект уже привязан к подготовленному VPN.')
            routes = json.loads(run('ip', '-j', '-4', 'route', 'show', 'table', 'all'))
            occupied = [ipaddress.ip_network(v['dst'], strict=False) for v in routes
                        if v.get('dst') not in (None, 'default')]
            links = {v['ifname'] for v in json.loads(run('ip', '-j', 'link'))}
            ports = set()
            for item in Path('/etc/telemax/projects').glob('*/vpn/creation.json'):
                other = json.loads(item.read_text())
                occupied.append(ipaddress.ip_network(other['subnet']))
                links.add(other['interface'])
                ports.add(other['port'])
            # Include stopped conventional VPN files as reservations as well.
            for directory in ('/etc/amnezia/amneziawg', '/etc/wireguard'):
                for config in Path(directory).glob('*.conf'):
                    server, _ = parse(config.read_text())
                    if server.get('listenport'):
                        ports.add(int(server['listenport']))
                    occupied.extend(networks(server.get('address', '')))
                    links.add(config.stem)
            subnet = None
            for block in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'):
                subnet = next((net for net in ipaddress.ip_network(block).subnets(new_prefix=24)
                               if not any(net.overlaps(other) for other in occupied)), None)
                if subnet:
                    break
            require(subnet is not None, 'Свободная частная подсеть не найдена.')
            interface = next(('tm' + str(i) for i in range(1, 10000) if 'tm' + str(i) not in links), None)
            require(interface is not None, 'Свободное имя подключения не найдено.')
            # All UDP listeners, including wildcard and IPv6, reserve their ports.
            for line in run('ss', '-H', '-lun').splitlines():
                fields = line.split()
                if len(fields) > 4:
                    ports.add(int(fields[3].rsplit(':', 1)[1]))
            # Published container UDP ports may use DNAT without a listening socket.
            for line in run('iptables-save', '-t', 'nat').splitlines():
                if '-p udp' not in line or not any(target in line for target in ('-j DNAT', '-j REDIRECT')):
                    continue
                match = re.search(r'--dports? ([0-9,:-]+)', line)
                if match:
                    for value in match[1].split(','):
                        ends = re.split('[:-]', value)
                        ports.update(range(int(ends[0]), int(ends[-1]) + 1))
            port = next((p for p in range(42000, 65000) if p not in ports), None)
            require(port is not None, 'Свободный UDP-порт не найден.')
            external_routes = json.loads(run('ip', '-j', '-4', 'route', 'get', '1.1.1.1'))
            require(external_routes and external_routes[0].get('dev'), 'Внешний путь трафика не найден.')
            external = external_routes[0]['dev']
            require(re.fullmatch(r'[a-zA-Z0-9_.:-]{1,15}', external), 'Неподдерживаемое имя внешнего подключения.')
            config = state / (interface + '.conf')
            profile = dict(server_config=str(config), interface=interface, endpoint=f'{public_ip}:{port}',
                           dns=dns, routes='0.0.0.0/0, ::/0', client_format='1',
                           subnet=str(subnet), port=port, external=external)
            private = key(run('awg', 'genkey').strip())
            headers = secrets.SystemRandom().sample(range(100000, 2000000000), 4)
            content = (f'[Interface]\nPrivateKey = {private}\nAddress = {subnet.network_address + 1}/24\n'
                       f'ListenPort = {port}\nMTU = 1280\nSaveConfig = false\n'
                       'Jc = 4\nJmin = 40\nJmax = 70\nS1 = 56\nS2 = 120\n' +
                       ''.join(f'H{i} = {value}\n' for i, value in enumerate(headers, 1)))
            # A durable record reserves names, port and subnet before live changes.
            # Keep initial bytes in the private record to recover an interrupted write.
            profile['initial_config'] = content
            atomic(record, json.dumps(profile))
        config = Path(profile['server_config'])
        if not config.exists():
            require(not initialized, 'Серверные настройки проекта утрачены. Сохранённые устройства и действующий VPN не изменены; восстановите закрытую копию настроек.')
            atomic(config, profile['initial_config'])
        private_file(config)
        unit = 'telemax-vpn-' + name
        binary = Path('/usr/local/bin/telemax-vpn')
        require(binary.is_file(), 'Установите программу выдачи через установщик проекта.')
        unit_path = Path('/etc/systemd/system') / (unit + '.service')
        unit_text = f'''[Unit]
Description=AmneziaWG for Telemax project {name}
After=network-online.target
Wants=network-online.target
[Service]
Type=oneshot
RemainAfterExit=yes
Environment=PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
ExecStart={binary} --project {name} up
ExecStop={binary} --project {name} down
TimeoutStartSec=120
TimeoutStopSec=120
[Install]
WantedBy=multi-user.target
'''
        if unit_path.exists():
            require(unit_path.read_text() == unit_text, 'Имя службы уже занято другой настройкой.')
        else:
            atomic(unit_path, unit_text)
        # Forwarding is shared. Never reset it while stopping one project.
        atomic(Path('/etc/sysctl.d') / ('80-' + unit + '.conf'), 'net.ipv4.ip_forward=1\n')
        if run('sysctl', '-n', 'net.ipv4.ip_forward').strip() != '1':
            run('sysctl', '-w', 'net.ipv4.ip_forward=1')
        run('systemctl', 'daemon-reload')
    # Do not hold the project lock while systemd's child calls up/down.
    if not initialized:
        run('systemctl', 'enable', '--now', unit)
    if not initialized or was_active:
        validate_server(profile)
    atomic(state / 'profile.json', json.dumps(profile))
    print(('Отдельный VPN проекта запущен и проверен на сервере. ' if not initialized or was_active
           else 'Прежнее остановленное состояние VPN проекта сохранено. ') + 'UDP-порт: ' + str(profile['port']))
    print('Разрешите этот порт в панели провайдера. IPv4 настроен; IPv6 направляется в туннель без выхода. Проверьте блокировку обхода в приложении и реальную передачу с устройства.')


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description='Закрытая выдача отдельных доступов AmneziaWG.')
    parser.add_argument('--state-dir', type=Path)
    parser.add_argument('--project', help='имя установленного отдельного проекта')
    commands = parser.add_subparsers(dest='command', required=True)
    setup = commands.add_parser('prepare', help='сохранить проверенные параметры подготовленного сервера')
    setup.add_argument('--server-config', type=Path, required=True)
    setup.add_argument('--endpoint', required=True, help='публичный IP:порт, IPv6 в квадратных скобках')
    setup.add_argument('--dns', required=True, help='проверенные IP DNS через запятую')
    setup.add_argument('--routes', required=True, help='клиентские маршруты через запятую')
    setup.add_argument('--client-format', choices=['1', '2'], required=True,
                       help='проверенная поддержка AWG1 или AWG2 установленным приложением')
    create = commands.add_parser('create', help='создать отдельный совместимый AWG1 VPN проекта')
    create.add_argument('--public-ip', required=True)
    create.add_argument('--dns', required=True)
    commands.add_parser('up', help='запуск VPN выбранного проекта')
    commands.add_parser('down', help='остановка VPN выбранного проекта')
    issue = commands.add_parser('add', help='выдать или повторно получить доступ по имени устройства')
    issue.add_argument('name')
    args = parser.parse_args()
    require(os.geteuid() == 0, 'Запустите через sudo.')
    require(not (args.project and args.state_dir), 'Выберите --project либо --state-dir.')
    state = project_state(args.project) if args.project else (args.state_dir or Path('/etc/telemax-vpn')).absolute()
    if args.command == 'create':
        require(args.project, 'Для нового VPN укажите --project.')
        private_dir(state)
        with locked(state / '.create.lock'):
            create_project_vpn(state, args.project, args.public_ip, args.dns)
        return 0
    require(args.command not in ('up', 'down') or args.project, 'Укажите --project.')
    private_dir(state)
    with locked(state / '.lock'):
        if args.command in ('up', 'down'):
            vpn_lifecycle(state, args.command == 'up')
            return 0
        profile_path = state / 'profile.json'
        if args.command == 'prepare':
            config = args.server_config.absolute()
            require(not config.is_symlink() and re.fullmatch(r'[a-zA-Z0-9_=+.-]{1,15}\.conf', config.name),
                    'Укажите обычный файл настроек awg-quick с именем интерфейса.')
            dns = ', '.join(str(ipaddress.ip_address(v.strip())) for v in args.dns.split(','))
            routes = ', '.join(str(v) for v in networks(args.routes))
            require(routes, 'Нужны согласованные клиентские маршруты.')
            profile = dict(server_config=str(config), interface=config.stem, endpoint=args.endpoint,
                           dns=dns, routes=routes, client_format=args.client_format)
            with locked(config.parent / ('.' + config.name + '.telemax-vpn.lock')):
                if profile_path.exists():
                    private_file(profile_path)
                    require(json.loads(profile_path.read_text()) == profile,
                            'В этой папке уже сохранены другие параметры. Для другого подготовленного сервера укажите отдельную закрытую папку через --state-dir.')
                require(not (state / 'pending.json').exists(), 'Сначала завершите прерванную выдачу командой add.')
                validate_server(profile)
                atomic(profile_path, json.dumps(profile))
            print('Параметры подготовленного сервера проверены и сохранены. Теперь выполните add ИМЯ.')
            return 0
        private_file(profile_path)
        profile = json.loads(profile_path.read_text())
        config = Path(profile['server_config'])
        with locked(config.parent / ('.' + config.name + '.telemax-vpn.lock')):
            conf, image, ok = add(state, profile, args.name)
        print('Доступ сохранён и подтверждён на сервере. Закрытый файл: ' + str(conf))
        if ok:
            print('Закрытый QR-код: ' + str(image))
        else:
            print('QR-код создать не удалось (возможна нехватка вместимости). Импортируйте сохранённый .conf. Повтор add безопасен.')
        return 0 if ok else 2


if __name__ == '__main__':
    def interrupted(signum, frame):
        raise AccessError('Выдача прервана. Незавершённые изменения будут восстановлены.')
    signal.signal(signal.SIGTERM, interrupted)
    try:
        sys.exit(main())
    except AccessError as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)
    except (OSError, ValueError, KeyError, subprocess.TimeoutExpired, KeyboardInterrupt):
        # Never print an exception from configuration parsing or a subprocess.
        print('Выдача не завершена. Проверьте закрытые настройки и состояние сервера по инструкции. '
              'При наличии записи восстановления повторите add; при внешних изменениях нужна ручная проверка.', file=sys.stderr)
        sys.exit(1)
