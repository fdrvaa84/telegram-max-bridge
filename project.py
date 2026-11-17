#!/usr/bin/env python3
"""Project allocation and additive integration with a shared HTTPS receiver."""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import sys
import tempfile


def call(*args):
    result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120)
    if result.returncode:
        raise ValueError('Команда не завершена. Действующие службы сохранены. Проверьте настройку приёмника.')
    return result.stdout.decode()


def write(path, text, mode=0o644):
    path.parent.mkdir(parents=True, exist_ok=True)
    previous = path.stat() if path.exists() else None
    fd, name = tempfile.mkstemp(dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(name, mode)
        if previous is not None:
            os.chown(name, previous.st_uid, previous.st_gid)
        os.replace(name, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def metadata(name):
    if not re.fullmatch(r'[a-z][a-z0-9-]{0,19}', name):
        raise ValueError('Некорректное имя проекта.')
    return Path('/opt/telemax/projects') / name / 'project.json'


def allocate(name):
    # Caller holds the installation lock until the release is published.
    path = metadata(name)
    if path.exists():
        return json.loads(path.read_text())['port']
    reserved = {3117}
    for item in Path('/opt/telemax/projects').glob('*/project.json'):
        reserved.add(json.loads(item.read_text())['port'])
    legacy = Path('/var/lib/telemax/config.json')
    if legacy.exists():
        reserved.add(json.loads(legacy.read_text()).get('port', 3117))
    for port in range(13117, 65536):
        if port in reserved:
            continue
        with socket.socket() as sock:
            try:
                sock.bind(('127.0.0.1', port))
            except OSError:
                continue
        write(path, json.dumps({'name': name, 'port': port}))
        return port
    raise ValueError('Свободный местный порт не найден.')


def route(domain, port):
    # Domain validation is also performed by manage.py before this entry point.
    if not re.fullmatch(r'[a-z0-9][a-z0-9.-]{0,252}', domain) or not 0 < port < 65536:
        raise ValueError('Некорректный домен или порт.')
    return f'''{domain} {{
    @bridge path /webhook /health
    handle @bridge {{
        reverse_proxy 127.0.0.1:{port}
    }}
    handle {{
        respond 404
    }}
}}
'''


def https(name, domain, port, config=None, receiver='caddy', fragment=False):
    if name:
        metadata(name)
    parent = Path('/etc/telemax')
    if not parent.exists():
        parent.mkdir(mode=0o755)
        parent.chmod(0o755)
    # VPN setup may have created this shared parent with root-only access.
    # Keep private project children protected while allowing the web user through.
    parent.chmod((parent.stat().st_mode & 0o777) | 0o111)
    sites = Path('/etc/telemax/sites')
    sites.mkdir(parents=True, exist_ok=True, mode=0o755)
    target = sites / (('project-' + name if name else 'legacy') + '.caddy')
    os.chmod(sites, 0o755)
    content = route(domain, port)
    if fragment:
        write(target.with_suffix('.example'), content)
        print('Настройка для общего Caddy сохранена: ' + str(target.with_suffix('.example')))
        print('Добавьте import этого файла в действующую настройку, проверьте caddy validate и примените caddy reload.')
        print('Для другого приёмника направьте только /webhook и /health своего домена на http://127.0.0.1:' + str(port) + ', остальные пути — 404. Сертификат получает действующий приёмник.')
        return
    managed = Path('/etc/telemax/Caddyfile')
    own_unit = Path('/etc/systemd/system/telemax-web.service')
    created_receiver = False
    if config is None:
        if Path('/etc/caddy/Caddyfile').exists():
            raise ValueError('Обнаружен общий Caddy. Используйте https --caddy-config /etc/caddy/Caddyfile либо https --fragment для другого приёмника.')
        config = managed
        receiver = 'telemax-web'
        if not config.exists():
            listeners = call('ss', '-H', '-ltn', '( sport = :80 or sport = :443 )').strip()
            if listeners:
                https(name, domain, port, fragment=True)
                raise ValueError('Общий приёмник уже работает. Подготовлена настройка для добавления домена. Примените её в этом приёмнике.')
            if own_unit.exists():
                raise ValueError('Существующая служба приёмника требует проверки её настройки.')
            # Extract only the binary, preserving other system-wide web services.
            with tempfile.TemporaryDirectory() as temp:
                subprocess.run(['apt-get', 'download', 'caddy'], cwd=temp, check=True,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                package = next(Path(temp).glob('caddy_*.deb'))
                call('dpkg-deb', '-x', str(package), '/opt/telemax/web')
            call('sh', '-c', 'id telemax-web >/dev/null 2>&1 || useradd --system --home-dir /var/lib/telemax-web --create-home --shell /usr/sbin/nologin telemax-web')
            call('install', '-d', '-m', '700', '-o', 'telemax-web', '-g', 'telemax-web', '/var/lib/telemax-web')
            write(config, '{\n    admin unix//run/telemax-web/admin.sock\n}\n')
            write(own_unit, '''[Unit]
Description=Shared HTTPS receiver for Telemax projects
After=network-online.target
Wants=network-online.target
[Service]
User=telemax-web
Group=telemax-web
Environment=HOME=/var/lib/telemax-web
RuntimeDirectory=telemax-web
RuntimeDirectoryMode=0700
ExecStart=/opt/telemax/web/usr/bin/caddy run --config /etc/telemax/Caddyfile --adapter caddyfile
ExecReload=/opt/telemax/web/usr/bin/caddy reload --config /etc/telemax/Caddyfile --adapter caddyfile
Restart=on-failure
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/telemax-web /run/telemax-web
[Install]
WantedBy=multi-user.target
''')
            call('systemctl', 'daemon-reload')
            created_receiver = True
    if not config.is_file() or config.is_symlink():
        raise ValueError('Укажите обычный действующий файл Caddy. Для другого приёмника используйте --fragment.')
    binary = shutil.which('caddy') or '/opt/telemax/web/usr/bin/caddy'
    before = config.read_text()
    previous = target.read_text() if target.exists() else None
    # Exact import for this project, without changing any existing directive.
    directive = 'import ' + str(target)
    write(target, content)
    try:
        if directive not in before.splitlines():
            write(config, before + ('' if before.endswith('\n') else '\n') + directive + '\n', config.stat().st_mode & 0o777)
        call(binary, 'validate', '--config', str(config), '--adapter', 'caddyfile')
        if subprocess.run(['systemctl', 'is-active', '--quiet', receiver]).returncode == 0:
            call(binary, 'reload', '--config', str(config), '--adapter', 'caddyfile')
        elif receiver == 'telemax-web' and created_receiver:
            call('systemctl', 'enable', '--now', receiver)
        else:
            raise ValueError('Выбранный общий приёмник остановлен. Его прежнее состояние сохранено.')
    except BaseException:
        write(config, before, config.stat().st_mode & 0o777)
        if previous is None:
            target.unlink(missing_ok=True)
        else:
            write(target, previous)
        if created_receiver:
            # Only this attempt created these files; undo a partial enable/start
            # before removing them so a normal retry is a fresh installation.
            call('systemctl', 'disable', '--now', receiver)
            config.unlink()
            own_unit.unlink()
            call('systemctl', 'daemon-reload')
        raise
    print('Маршрут проекта добавлен и проверен. Проверьте доступность собственного домена и привязку MAX.')


def main():
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest='command', required=True)
    for command in ('allocate', 'port'):
        commands.add_parser(command).add_argument('name')
    p = commands.add_parser('https')
    p.add_argument('name')
    p.add_argument('domain')
    p.add_argument('port', type=int)
    p.add_argument('--caddy-config', type=Path)
    p.add_argument('--receiver', default='caddy')
    p.add_argument('--fragment', action='store_true')
    args = parser.parse_args()
    if args.command == 'allocate':
        allocate(args.name)
    elif args.command == 'port':
        print(json.loads(metadata(args.name).read_text())['port'])
    else:
        https(args.name, args.domain, args.port, args.caddy_config, args.receiver, args.fragment)


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        print(str(error) if isinstance(error, ValueError) else 'Действие не завершено. Проверьте общую настройку приёмника.', file=sys.stderr)
        sys.exit(1)
