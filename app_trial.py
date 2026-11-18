#!/usr/bin/env python3
"""Isolated, loopback-only owner experiment. No bridge activation or cloud copies.

Site protocol inspected 2026-11-18: GET /auth and /js/my-telegram.js?13.
Reference (not live proof of creation): WireCatLabs/tg-cli,
src/telegram/registration.ts. Official instructions: core.telegram.org/api/obtaining_api_id.
Run in a dedicated private state directory, never a production project directory.
"""
import argparse
import asyncio
import base64
import hmac
from html.parser import HTMLParser
import json
import logging
import os
from pathlib import Path
import re
import secrets
import time

from aiohttp import ClientSession, ClientTimeout, CookieJar, web
from telethon import TelegramClient, errors

SITE = 'https://my.telegram.org'


class SafeError(Exception):
    pass


class Page(HTMLParser):
    def __init__(self, source):
        super().__init__(convert_charrefs=True)
        self.forms, self.inputs, self.copies, self.text = [], [], [], []
        self.skip = 0
        self.feed(source)

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag in ('script', 'style'):
            self.skip += 1
        if tag == 'form':
            self.forms.append(a)
        if tag == 'input':
            self.inputs.append(a)
        for key in ('data-value', 'data-copy'):
            if key in a:
                self.copies.append(a[key])

    def handle_endtag(self, tag):
        if tag in ('script', 'style'):
            self.skip = max(0, self.skip - 1)

    def handle_data(self, data):
        if not self.skip:
            self.text.append(data)


def inspect_app(source):
    p = Page(source)
    text = ' '.join(' '.join(p.text).split())
    ids = set(re.findall(r'api_id:?\s*(\d+)\b', text, re.I))
    hashes = set(re.findall(r'api_hash:?\s*([a-f0-9]{32})\b', text, re.I))
    existing = any(f.get('id') == 'app_edit_form' for f in p.forms) or 'App configuration' in text
    if existing or 'api_id' in text:
        ids.update(v for v in p.copies if re.fullmatch(r'[1-9]\d*', v))
        hashes.update(v for v in p.copies if re.fullmatch(r'[a-fA-F0-9]{32}', v))
        if len(ids) == len(hashes) == 1:
            return 'existing', {'api_id': int(next(iter(ids))), 'api_hash': next(iter(hashes))}
        raise SafeError('Приложение найдено, но прочитать его настройки не удалось. Создание запрещено.')
    create = any(f.get('id') == 'app_create_form' and f.get('action', '/apps/create') == '/apps/create' for f in p.forms)
    tokens = [a.get('value', '') for a in p.inputs if a.get('name') == 'hash']
    names = {a.get('name') for a in p.inputs}
    if create and {'app_title', 'app_shortname'} <= names and len(tokens) == 1 and re.fullmatch(r'[a-fA-F0-9]+', tokens[0]):
        return 'absent', tokens[0]
    raise SafeError('Страница Telegram не распознана. Это не означает, что приложения нет. Создание остановлено.')


def private_write(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as stream:
        json.dump(data, stream)
        stream.flush()
        os.fsync(stream.fileno())


class Trial:
    def __init__(self, root):
        self.root = root
        self.phase = 'phone'
        self.message = 'Шаг 1. Вход на сайт управления своим приложением Telegram.'
        self.http = None
        self.client = None
        self.phone = self.random_hash = self.code_hash = None
        self.deadline = 0
        self.last_send = 0
        self.lock = asyncio.Lock()
        self.keys = None
        self.created = False
        keyfile = root / 'application.json'
        if keyfile.exists():
            self.keys = json.loads(keyfile.read_text())
            self.phone = self.keys['owner_phone']
            self.phase = 'bridge_phone'
            self.message = 'Настройки своего приложения сохранены. Шаг 2: отдельный личный вход пересылки.'

    async def call(self, path, form=None):
        if self.http is None:
            self.http = ClientSession(cookie_jar=CookieJar(), timeout=ClientTimeout(total=25))
        async with self.http.request('POST' if form is not None else 'GET', SITE + path,
                data=form, allow_redirects=False, headers={'Origin': SITE,
                'Referer': SITE + ('/apps' if path.startswith('/apps') else '/auth'),
                'X-Requested-With': 'XMLHttpRequest'}) as r:
            body = await r.content.read(1_000_001)
            if r.status != 200 or len(body) > 1_000_000:
                raise SafeError('Telegram не разрешил действие или страница недоступна. Автоматического повтора нет.')
            return body.decode('utf-8')

    async def obtain(self):
        kind, value = inspect_app(await self.call('/apps'))
        if kind == 'absent':
            marker = self.root / 'creation-attempt.json'
            if marker.exists():
                raise SafeError('Ранее создание уже запрашивалось. Приложение пока не найдено; повторное создание заблокировано.')
            private_write(marker, {'attempted': True})
            # Mark before sending: after ambiguous outcomes only read, never retry creation.
            result = (await self.call('/apps/create', dict(hash=value,
                app_title='Personal MAX Bridge', app_shortname='maxbridge' + secrets.token_hex(5),
                app_url='https://github.com/fdrvaa84/telegram-max-bridge',
                app_platform='desktop', app_desc='Private forwarding for my own account'))).strip()
            if result not in ('', 'true'):
                raise SafeError('Telegram отказал в создании либо ответ не распознан. Повторного создания не будет.')
            kind, value = inspect_app(await self.call('/apps'))
            if kind != 'existing':
                raise SafeError('Создание не подтверждено чтением настроек. Повторного создания не будет.')
            self.created = True
        value['owner_phone'] = self.phone
        private_write(self.root / 'application.json', value)
        self.keys = value
        self.phase = 'bridge_phone'
        self.message = ('Новое приложение создано и прочитано.' if self.created else
            'Существующее приложение прочитано и сохранено без изменений. Создание нового не проверено.')
        self.message += ' Шаг 2: отдельный личный вход самой пересылки.'
        await self.http.close()
        self.http = None
        self.random_hash = None

    async def action(self, action, value, consent=False):
        async with self.lock:
            if action == 'site_phone' and self.phase == 'phone':
                if not consent:
                    raise SafeError('Нужно явное согласие на чтение своего приложения и создание только при его отсутствии.')
                self.validate_phone(value)
                if time.monotonic() - self.last_send < 60:
                    raise SafeError('Перед повторным запросом подождите минуту.')
                self.last_send = time.monotonic()
                self.phone = value
                raw = await self.call('/auth/send_password', {'phone': value})
                try:
                    token = json.loads(raw).get('random_hash')
                except (ValueError, AttributeError):
                    token = None
                if not isinstance(token, str) or not token:
                    raise SafeError('Telegram не выдал подтверждение входа. Запрос не повторяется автоматически.')
                self.random_hash = token
                self.deadline = time.monotonic() + 300
                self.phase = 'site_code'
                self.message = 'Введите код именно от my.telegram.org. Это ещё не вход пересылки.'
            elif action == 'site_code' and self.phase == 'site_code':
                if time.monotonic() > self.deadline:
                    self.phase = 'phone'
                    self.random_hash = None
                    raise SafeError('Время ввода истекло. Запросите новый код.')
                response = await self.call('/auth/login', dict(phone=self.phone,
                    random_hash=self.random_hash, password=value))
                if response.strip() not in ('true', '', 'null'):
                    raise SafeError('Код неверен, истёк или Telegram отказал во входе. Вход не подтверждён.')
                self.phase = 'read_app'
                await self.obtain()
            elif action == 'read_app' and self.phase == 'read_app':
                await self.obtain()
            elif action == 'bridge_phone' and self.phase == 'bridge_phone':
                self.validate_phone(value)
                if self.phone and value != self.phone:
                    raise SafeError('Для пересылки нужен тот же номер, что для собственного приложения.')
                self.phone = value
                if self.client is None:
                    self.client = TelegramClient(str(self.root / 'trial'), self.keys['api_id'],
                        self.keys['api_hash'], request_retries=0, flood_sleep_threshold=0,
                        receive_updates=False)
                    await self.client.connect()
                if await self.client.is_user_authorized():
                    await self.finish()
                    return
                if time.monotonic() - self.last_send < 60:
                    raise SafeError('Перед новым запросом кода подождите минуту.')
                self.last_send = time.monotonic()
                sent = await self.client.send_code_request(value)
                self.code_hash = sent.phone_code_hash
                self.deadline = time.monotonic() + 300
                self.phase = 'bridge_code'
                self.message = 'Шаг 2. Введите новый код входа пересылки из Telegram, не код сайта.'
            elif action == 'bridge_code' and self.phase == 'bridge_code':
                if time.monotonic() > self.deadline:
                    self.phase = 'bridge_phone'
                    self.code_hash = None
                    raise SafeError('Время ввода истекло. Запросите новый код пересылки.')
                try:
                    await self.client.sign_in(self.phone, value, phone_code_hash=self.code_hash)
                except errors.SessionPasswordNeededError:
                    self.phase = 'bridge_password'
                    self.message = 'Telegram запросил дополнительный пароль для входа пересылки.'
                    return
                except errors.PhoneCodeExpiredError:
                    self.phase = 'bridge_phone'
                    self.code_hash = None
                    raise SafeError('Код пересылки истёк. Запросите новый.') from None
                except errors.PhoneCodeInvalidError:
                    raise SafeError('Код пересылки неверен. Проверьте код из последнего сообщения.') from None
                await self.finish()
            elif action == 'bridge_password' and self.phase == 'bridge_password':
                try:
                    await self.client.sign_in(password=value)
                except errors.PasswordHashInvalidError:
                    raise SafeError('Дополнительный пароль неверен.') from None
                await self.finish()
            elif action == 'max_token' and self.phase == 'max_token':
                await self.check_max(value)
            else:
                raise SafeError('Действие сейчас недоступно. Обновите страницу.')

    @staticmethod
    def validate_phone(value):
        if not re.fullmatch(r'\+[1-9]\d{7,14}', value):
            raise SafeError('Введите свой номер с плюсом и кодом страны, без пробелов.')

    async def finish(self):
        me = await self.client.get_me()
        if not me or '+' + (me.phone or '') != self.phone:
            raise SafeError('Принадлежность входа нужному номеру не подтверждена. Пересылка выключена.')
        self.phase = 'max_token'
        self.message = 'Личный вход подтверждён. Введите ключ отдельного свободного бота MAX. Действующий бот не подходит. Проверка только прочитает его состояние; пересылка пока выключена.'
        self.code_hash = None
        await self.client.disconnect()
        self.client = None

    async def check_max(self, token):
        # Reuse the established verified MAX trust context, without touching production config.
        from bridge import ssl_context
        from aiohttp import TCPConnector
        async with ClientSession(connector=TCPConnector(ssl=ssl_context()),
                timeout=ClientTimeout(total=25)) as http:
            results = []
            for path in ('/me', '/subscriptions'):
                async with http.get('https://platform-api2.max.ru' + path,
                        headers={'Authorization': token}, allow_redirects=False) as r:
                    if r.status != 200:
                        raise SafeError('MAX не подтвердил доступ. Проверьте ключ отдельного бота.')
                    results.append(await r.json())
            me, subscriptions = results
            if not me.get('user_id') or not me.get('is_bot'):
                raise SafeError('MAX не подтвердил, что это бот.')
            if not isinstance(subscriptions.get('subscriptions'), list):
                raise SafeError('Не удалось прочитать подключения бота. Подключение остановлено.')
            if subscriptions['subscriptions']:
                raise SafeError('У бота уже есть подключение. Оно сохранено; нужен отдельный свободный бот.')
            private_write(self.root / 'max-bot.json', {'token': token, 'bot_id': me['user_id']})
        self.phase = 'ready'
        self.message = 'Личный вход и отдельный свободный бот подтверждены. Пересылка пока выключена: помощник должен подготовить обмен только с согласованными участниками и проверить доставку и ответы в личной переписке и группе.'

    async def close(self):
        if self.http:
            await self.http.close()
        if self.client:
            await self.client.disconnect()


HTML = '''<!doctype html><html lang="ru"><meta charset="utf-8"><meta name="referrer" content="no-referrer"><title>Пробное подключение</title><style>body{font:18px system-ui;max-width:700px;margin:40px auto;padding:16px}input,button{font:inherit;padding:10px}p{line-height:1.5}</style><h1>Отдельное пробное подключение</h1><p>Действующая пересылка остаётся включённой. Здесь будет новый личный вход. Ничего не скачивается.</p><p>Сначала — подтверждение входа на my.telegram.org и чтение своего приложения либо попытка создания нового. Telegram может отказать. Существующее приложение не меняется. Затем — отдельное подтверждение входа самой пересылки.</p><p id="status"></p><form id="form" autocomplete="off"><p id="consentRow"><label><input type="checkbox" id="consent">Это мой аккаунт. Разрешаю вход на сайт, чтение моего приложения и создание, только если его нет.</label></p><label id="label" for="value"></label><p><input id="value" type="password" autocomplete="off" maxlength="256" required></p><button id="send">Продолжить</button></form><p id="result"></p><script>
const csrf='CSRF_VALUE';let phase='';const input=document.getElementById('value');async function tick(){try{let r=await fetch('/status',{cache:'no-store'});if(!r.ok)throw Error();let s=await r.json();phase=s.phase;document.getElementById('status').textContent=s.message;document.getElementById('form').hidden=phase==='ready';document.getElementById('consentRow').hidden=phase!=='phone';input.required=phase!=='read_app';input.hidden=phase==='read_app';document.getElementById('label').textContent=({phone:'Ваш номер Telegram',site_code:'Код входа на сайт',bridge_phone:'Тот же номер для отдельного входа пересылки',bridge_code:'Код входа пересылки',bridge_password:'Дополнительный пароль Telegram',max_token:'Ключ отдельного свободного бота MAX',read_app:'Повторить только чтение страницы приложения'})[phase]||'';}catch(e){document.getElementById('result').textContent='Соединение потеряно. Действия не отправляются.';}}
document.getElementById('form').onsubmit=async e=>{e.preventDefault();let value=input.value;input.value='';document.getElementById('send').disabled=true;try{let r=await fetch('/action',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF':csrf},body:JSON.stringify({action:({phone:'site_phone'})[phase]||phase,value,consent:document.getElementById('consent').checked})});let s=await r.json();document.getElementById('result').textContent=s.message||'Действие принято.';}catch(e){document.getElementById('result').textContent='Ответ не получен. Не повторяйте создание: сначала обновите состояние.';}finally{value='';document.getElementById('send').disabled=false;await tick();}};tick();setInterval(tick,4000);</script></html>'''


def make_app(trial, password, port):
    csrf = secrets.token_urlsafe(32)
    authority = f'127.0.0.1:{port}'
    @web.middleware
    async def secure(request, handler):
        if request.host != authority or request.query_string:
            return web.Response(status=403)
        expected = 'Basic ' + base64.b64encode(('owner:' + password).encode()).decode()
        if not hmac.compare_digest(request.headers.get('Authorization', ''), expected):
            return web.Response(status=401, headers={'WWW-Authenticate': 'Basic realm="Private trial"'})
        if request.method == 'POST' and (request.headers.get('Origin') != 'http://' + authority or
                not hmac.compare_digest(request.headers.get('X-CSRF', ''), csrf)):
            return web.Response(status=403)
        try:
            response = await handler(request)
        except Exception:
            response = web.json_response({'message': 'Действие не завершено. Секретные сведения скрыты; автоматического повтора нет.'}, status=400)
        response.headers.update({'Cache-Control': 'no-store', 'Referrer-Policy': 'no-referrer',
            'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'DENY',
            'Content-Security-Policy': "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'none'"})
        return response

    async def page(request):
        return web.Response(text=HTML.replace('CSRF_VALUE', csrf), content_type='text/html')

    async def status(request):
        return web.json_response({'phase': trial.phase, 'message': trial.message})

    async def action(request):
        try:
            data = await request.json()
            value = data.get('value', '')
            if not isinstance(value, str) or len(value) > 256:
                raise SafeError('Значение не принято.')
            await trial.action(data.get('action'), value, data.get('consent') is True)
            return web.json_response({'message': trial.message})
        except SafeError as e:
            return web.json_response({'message': str(e)}, status=400)
        finally:
            value = None

    app = web.Application(middlewares=[secure], client_max_size=4096)
    app.router.add_get('/', page)
    app.router.add_get('/status', status)
    app.router.add_post('/action', action)
    async def cleanup(app):
        await trial.close()
    app.on_cleanup.append(cleanup)
    return app


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--state', required=True, type=Path)
    parser.add_argument('--port', type=int, default=18789)
    args = parser.parse_args()
    os.umask(0o077)
    # A separate directory is required, refuse anything containing a configured bridge.
    args.state.mkdir(parents=True, exist_ok=True, mode=0o700)
    if (args.state / 'config.json').exists() or (args.state / 'state').exists():
        raise SystemExit('Use a separate trial directory.')
    args.state.chmod(0o700)
    password_file = args.state / 'page-password'
    if not password_file.exists():
        fd = os.open(password_file, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, 'w') as f:
            f.write(secrets.token_urlsafe(24))
    logging.disable(logging.CRITICAL)
    trial = Trial(args.state)
    web.run_app(make_app(trial, password_file.read_text(), args.port), host='127.0.0.1',
        port=args.port, access_log=None, print=None)


if __name__ == '__main__':
    main()
