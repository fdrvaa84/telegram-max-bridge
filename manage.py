#!/usr/bin/env python3
"""Private terminal setup and safe diagnostics. Never print secrets/exceptions."""
import argparse
import asyncio
import getpass
import hashlib
import hmac
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import sys
import time
from urllib.parse import urlsplit
from aiohttp import ClientSession, ClientTimeout, TCPConnector, web
from bridge import atomic, load_config, Bridge, PublicResolver

DEFAULT = '/var/lib/telemax/config.json'


class SetupError(ValueError):
    pass


def private_terminal():
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        raise SetupError('Требуется личное окно подключения к серверу.')


def hidden(prompt):
    private_terminal()
    value = getpass.getpass(prompt + ' (ввод скрыт): ').strip()
    if not value:
        raise SetupError('Пустое значение не сохранено.')
    return value


def domain_name(value):
    value = value.strip().lower()
    if not re.fullmatch(r'(?=.{1,253}$)[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?', value) or '.' not in value:
        raise SetupError('Нужно доменное имя без https, порта и пути.')
    try:
        ipaddress.ip_address(value)
    except ValueError:
        if all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', s) for s in value.split('.')):
            return value
    raise SetupError('Нужно доменное имя, а не адрес сервера.')


def save(path, config):
    atomic(path, json.dumps(config, ensure_ascii=False, indent=2).encode())


def configure(path):
    private_terminal()
    if Path(path).exists():
        raise SetupError('Настройки уже есть. Не перезаписываем вход и привязку.')
    print('Введите собственные реквизиты. Они останутся только на этом сервере.')
    api_id = int(hidden('Telegram api_id с my.telegram.org/apps'))
    api_hash = hidden('Telegram api_hash')
    if api_id <= 0 or not re.fullmatch(r'[a-fA-F0-9]{32}', api_hash):
        raise SetupError('Проверьте реквизиты Telegram.')
    token = hidden('Ключ вашего отдельного бота MAX')
    domain = domain_name(input('Ваш домен для MAX: '))
    config = dict(api_id=api_id, api_hash=api_hash, max_bot_token=token,
        domain=domain, webhook_secret=secrets.token_hex(32), local_token=secrets.token_hex(32),
        enabled=False, max_owner_id=None, max_bot_id=None,
        state_dir=str(Path(path).parent / 'state'), port=3117)
    save(path, config)
    print('Настройки сохранены с закрытым доступом. Пересылка ещё выключена.')


async def subscribe(bridge):
    url = 'https://' + bridge.c['domain'] + '/webhook'
    result = await bridge.api('GET', '/subscriptions')
    # An unrelated subscription can leak or compete for bot updates. Do not delete it.
    if any(item.get('url') != url for item in result.get('subscriptions', [])):
        raise SetupError('У бота уже есть другой адрес. Используйте отдельного нового бота.')
    await bridge.api('POST', '/subscriptions', {'url': url,
        'update_types': ['message_created', 'message_callback'], 'secret': bridge.c['webhook_secret']})
    result = await bridge.api('GET', '/subscriptions')
    if not any(item.get('url') == url for item in result.get('subscriptions', [])):
        raise SetupError('MAX не подтвердил подписку.')


class Pairing:
    def __init__(self, config, code):
        self.config, self.code = config, code
        self.owner = None
        self.name = None
        self.found = asyncio.Event()
        self.expires = time.monotonic() + 300

    async def accept(self, request):
        if not hmac.compare_digest(request.headers.get('X-Max-Bot-Api-Secret', ''), self.config['webhook_secret']):
            raise web.HTTPForbidden()
        event = await request.json()
        m = event.get('message') or {}
        sender, recipient = m.get('sender') or {}, m.get('recipient') or {}
        if (time.monotonic() < self.expires and self.owner is None
            and event.get('update_type') == 'message_created'
            and recipient.get('chat_type') == 'dialog'
            and recipient.get('user_id') == self.config['max_bot_id']
            and isinstance(sender.get('user_id'), int) and not sender.get('is_bot')
            and hmac.compare_digest((m.get('body', {}).get('text') or '').strip(), '/bind ' + self.code)):
            self.owner = sender['user_id']
            self.name = sender.get('first_name') or 'Ваш аккаунт MAX'
            self.found.set()
        return web.json_response({'handled': self.found.is_set()})


async def remote_command(path, command):
    config = load_config(path)
    async with ClientSession(timeout=ClientTimeout(total=30), connector=TCPConnector(resolver=PublicResolver())) as http:
        b = Bridge(config, None)
        b.http = http
        me = await b.api('GET', '/me')
        if not me.get('is_bot', True) or not isinstance(me.get('user_id'), int):
            raise SetupError('MAX не подтвердил вашего бота.')
        if config.get('max_bot_id') and config['max_bot_id'] != me['user_id']:
            raise SetupError('Ключ относится к другому боту. Прежняя привязка сохранена.')
        config['max_bot_id'] = me['user_id']
        if command == 'pair':
            private_terminal()
            if config.get('max_owner_id'):
                raise SetupError('Владелец уже привязан. Повторный захват запрещён.')
            code = secrets.token_urlsafe(24)
            pairing = Pairing(config, code)
            app = web.Application(client_max_size=65536)
            app.router.add_post('/webhook', pairing.accept)
            app.router.add_get('/health', lambda r: web.json_response({'ready': True, 'enabled': False}))
            runner = web.AppRunner(app, access_log=None)
            await runner.setup()
            await web.TCPSite(runner, '127.0.0.1', config['port']).start()
            try:
                await check_https(config, http)
                await subscribe(b)
                print('Откройте личный диалог со СВОИМ ботом MAX и отправьте за 5 минут:')
                print('/bind ' + code, flush=True)
                await asyncio.wait_for(pairing.found.wait(), 300)
                # repr prevents terminal control sequences in an untrusted display name.
                print('Запрос от:', repr(pairing.name))
                if input('Это ваш аккаунт? Напишите ПОДТВЕРЖДАЮ: ').strip() != 'ПОДТВЕРЖДАЮ':
                    raise SetupError('Привязка не подтверждена.')
                config['max_owner_id'] = pairing.owner
                save(path, config)
                print('Владелец привязан. Другие пользователи не смогут отправлять ответы.')
            finally:
                await runner.cleanup()
        elif command == 'subscribe':
            await check_https(config, http)
            await subscribe(b)
            save(path, config)
            print('MAX подтвердил адрес приёма. Проверьте живой ответ в MAX.')
        elif command == 'unsubscribe':
            url = 'https://' + config['domain'] + '/webhook'
            from urllib.parse import urlencode
            await b.api('DELETE', '/subscriptions?' + urlencode({'url': url}))
            print('Приём от MAX отключён. Вход Telegram остаётся сохранённым.')


async def check_https(config, http):
    # Caddy serves only this harmless health response and /webhook.
    async with http.get('https://' + config['domain'] + '/health', allow_redirects=False) as response:
        if response.status != 200 or (await response.json()).get('ready') is not True:
            raise SetupError('Защищённый адрес пока недоступен. Проверьте домен, сертификат и порты.')


def status(path):
    config = load_config(path)
    print('Передача:', 'включена' if config.get('enabled') else 'выключена')
    print('Владелец MAX:', 'привязан' if config.get('max_owner_id') else 'не привязан')
    root = Path(config['state_dir'])
    print('Вход Telegram:', 'сохранён' if (root/'telegram.session').exists() else 'не выполнен')
    db_path = root / 'state.sqlite'
    if db_path.exists():
        db = sqlite3.connect(db_path.as_uri() + '?mode=ro', uri=True)
        labels = {'done': 'доставлено', 'pending': 'ожидает', 'uncertain': 'исход неизвестен, повтор запрещён',
            'blocked': 'не отправлено', 'choice_wait': 'ожидает выбора видео',
            'awaiting_choice': 'готовится выбор видео', 'sending': 'отправляется', 'reserved': 'подготовлено'}
        for state, count in db.execute('SELECT state,count(*) FROM jobs GROUP BY state'):
            print(labels.get(state, 'другое состояние') + ':', count)
        cloud_table = db.execute("SELECT 1 FROM sqlite_master WHERE name='cloud_copies'").fetchone()
        if cloud_table:
            for state, count in db.execute('SELECT state,count(*) FROM cloud_copies GROUP BY state'):
                print('Облачные копии:', 'проверено' if state == 'verified' else 'ожидает', count)
        db.close()
    print('Облака:', 'настроены два; подтверждения показаны выше' if config.get('cloud_copies') else 'не настроены, только локальное хранение')
    if root.exists():
        print('Свободно на диске, ГБ:', round(__import__('shutil').disk_usage(root).free/1024**3, 1))


def clouds(path):
    private_terminal()
    config = load_config(path)
    targets = []
    print('Нужны два ВАШИХ разных поставщика S3. Без этого подтверждаются только местные оригиналы.')
    for number in (1, 2):
        endpoint = hidden(f'Адрес HTTPS хранилища {number} без пути').rstrip('/')
        p = urlsplit(endpoint)
        if p.scheme != 'https' or not p.hostname or p.path or p.query or p.fragment or p.username or p.port not in (None,443):
            raise SetupError('Нужен обычный защищённый адрес хранилища.')
        target = dict(endpoint=endpoint, bucket=hidden('Имя частного хранилища'),
            access_key=hidden('Ключ доступа'), secret_key=hidden('Секретный ключ'), region=hidden('Регион'))
        targets.append(target)
    if urlsplit(targets[0]['endpoint']).hostname == urlsplit(targets[1]['endpoint']).hostname:
        raise SetupError('Нужны два разных поставщика, а не две папки у одного.')
    config['cloud_copies'] = targets
    save(path, config)
    print('Два направления настроены. Копии ещё НЕ подтверждены. Перезапустите передачу и проверьте состояние.')


def cli():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description='Личная связь Telegram и MAX')
    parser.add_argument('--config', default=DEFAULT)
    parser.add_argument('command', choices=['configure','pair','subscribe','unsubscribe','status','domain','clouds'])
    args = parser.parse_args()
    try:
        if args.command == 'configure': configure(args.config)
        elif args.command == 'status': status(args.config)
        elif args.command == 'domain': print(domain_name(load_config(args.config)['domain']))
        elif args.command == 'clouds': clouds(args.config)
        else: asyncio.run(remote_command(args.config, args.command))
    except (Exception, KeyboardInterrupt) as error:
        # Never expose HTTP exception strings (may contain signed media URLs/tokens).
        print(str(error) if isinstance(error, SetupError) else 'Действие не завершено. Проверьте введённые данные, доступность сети и инструкцию.', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(cli())
