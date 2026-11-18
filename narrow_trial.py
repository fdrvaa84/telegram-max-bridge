"""Bounded owner-only trial. No webhook, dialog enumeration or production writes."""
import argparse
import asyncio
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import signal
import time
from urllib.parse import urlencode

import aiohttp
from telethon import events, types

from app_trial import LoginOnlyClient, private_write
from bridge import Bridge, Store, reply_input, ssl_context


def fresh(message, activated):
    return bool(message.date and message.date.timestamp() >= activated)


def allowed_reply(message, config, store, activated):
    if message.get('recipient', {}).get('chat_id') != config['max_chat_id']:
        return None
    if message.get('timestamp', 0) < int(activated * 1000):
        return None
    result = reply_input(message, config, store)
    if result and result['chat'] in config['allowed_peers']:
        return result
    return None


class TrialBridge(Bridge):
    async def api(self, method, route, body=None):
        if method == 'GET' and not (route == '/me' or route.startswith('/messages/')
                                    or route.startswith('/messages?chat_id=' + str(self.c['max_chat_id']) + '&')):
            raise ValueError('trial_read_route_denied')
        if method != 'GET' and not (
            method == 'POST' and (
                route == '/messages?user_id=' + str(self.c['max_owner_id'])
                or route.startswith('/uploads?type='))):
            raise ValueError('trial_route_denied')
        return await super().api(method, route, body)

    async def capture(self, message, chat):
        if message.chat_id not in self.c['allowed_peers'] or not fresh(message, self.c['activated']):
            return
        await super().capture(message, chat)
        key = f'tg:{message.chat_id}:{message.id}'
        row = self.s.db.execute('SELECT payload FROM jobs WHERE k=?', (key,)).fetchone()
        if row:
            payload = json.loads(row[0])
            if not payload['text'].startswith('ПРОБА\n'):
                payload['text'] = 'ПРОБА\n' + payload['text']
                self.s.update(key, 'pending', payload)


class ObservedTelegram:
    """Verify exact Telegram destination IDs from real send receipts."""
    def __init__(self, client, store):
        self.client, self.store = client, store

    def __getattr__(self, name):
        return getattr(self.client, name)

    async def __call__(self, request):
        result = await self.client(request)
        for update in getattr(result, 'updates', []):
            message = getattr(update, 'message', None)
            if not isinstance(message, types.Message):
                continue
            actual = await self.client.get_messages(request.peer, ids=message.id)
            if (not actual or actual.reply_to_msg_id != request.reply_to.reply_to_msg_id
                    or actual.message != message.message):
                raise ValueError('telegram_receipt_not_verified')
            expected_topic = getattr(request.reply_to, 'top_msg_id', None)
            actual_topic = getattr(actual.reply_to, 'reply_to_top_id', None)
            if expected_topic and actual_topic != expected_topic:
                raise ValueError('telegram_topic_not_verified')
            receipts = self.store.get('telegram_receipts', [])
            receipts.append({'chat': actual.chat_id, 'message': actual.id,
                             'reply_to': actual.reply_to_msg_id, 'topic': actual_topic,
                             'destination_observed': True})
            self.store.set('telegram_receipts', receipts)
        return result


async def run(root, login_root, minutes):
    os.umask(0o077)
    config = json.loads((root / 'max-private.json').read_text())
    approval = json.loads((root / 'allowlist.json').read_text())
    config.update(allowed_peers=approval['peers'], chat_classification={}, enabled=True)
    if not config['allowed_peers'] or approval.get('owner_only_verified') is not True:
        raise ValueError('owner_only_allowlist_required')
    app = json.loads((login_root / 'application.json').read_text())
    client = LoginOnlyClient(str(login_root / 'trial-qr'), app['api_id'], app['api_hash'],
                             receive_updates=True, catch_up=False, request_retries=0,
                             flood_sleep_threshold=0)
    store = Store(root / 'queue')
    stop = asyncio.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        asyncio.get_running_loop().add_signal_handler(sig, stop.set)
    await client.connect()
    try:
        owner = await client.get_me()
        if (not owner or owner.bot or owner.id != config['telegram_owner_id']
                or '+' + (owner.phone or '').lstrip('+') != app['owner_phone']):
            raise ValueError('fresh_owner_mismatch')
        for peer in config['allowed_peers']:
            entity = await client.get_entity(peer)
            if isinstance(entity, types.User):
                if entity.bot or entity.id not in approval['owned_human_accounts']:
                    raise ValueError('unapproved_human')
            else:
                members = await client.get_participants(entity, limit=100)
                permitted = set(approval['owned_human_accounts'] + approval.get('owned_bot_ids', []))
                if not entity.creator or not members or any(m.id not in permitted for m in members):
                    raise ValueError('group_ownership_not_verified')
        config['activated'] = store.get('activated') or time.time()
        store.set('activated', config['activated'])
        expires = min(store.get('expires') or time.time() + minutes * 60,
                      config['activated'] + 90 * 60)
        store.set('expires', expires)
        bridge = TrialBridge(config, store, ObservedTelegram(client, store))
        async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=ssl_context()),
                                        timeout=aiohttp.ClientTimeout(total=45)) as http:
            bridge.http = http
            bot = await bridge.api('GET', '/me')
            if bot.get('user_id') != config['max_bot_id'] or not bot.get('is_bot'):
                raise ValueError('max_bot_mismatch')
            initial = await bridge.api('GET', '/messages?' + urlencode({
                'chat_id': config['max_chat_id'], 'from': int(config['activated'] * 1000), 'count': 100}))
            if not isinstance(initial.get('messages'), list):
                raise ValueError('max_read_not_confirmed')

            async def incoming(event):
                try:
                    if event.chat_id in config['allowed_peers'] and fresh(event.message, config['activated']):
                        await bridge.capture(event.message, await event.get_chat())
                except Exception as error:
                    store.set('capture_error', type(error).__name__)

            client.add_event_handler(incoming, events.NewMessage(chats=config['allowed_peers'], incoming=True))
            # Probe only the already approved owner MAX chat; this is not a user reply.
            if not store.get('probe_started'):
                store.set('probe_started', True)
                try:
                    result = await bridge.api('POST', '/messages?user_id=' + str(config['max_owner_id']),
                        {'text': 'ПРОБА\nОтдельная проверка подключена. Копии новых сообщений будут отмечены словом «ПРОБА». Это служебная проверка, отвечать на неё не нужно.'})
                    mid = result['message']['body']['mid']
                    observed = await bridge.api('GET', '/messages/' + mid)
                    message = observed.get('message', observed)
                    if (message['sender']['user_id'] != config['max_bot_id']
                            or message['recipient']['chat_id'] != config['max_chat_id']
                            or message['recipient']['user_id'] != config['max_owner_id']):
                        raise ValueError('max_probe_destination_mismatch')
                    store.set('max_probe_observed', True)
                except BaseException:
                    store.set('probe_uncertain', True)
                    raise
            if not store.get('max_probe_observed'):
                raise ValueError('probe_requires_reconciliation')
            failures = 0
            while not stop.is_set() and time.time() < expires and not (root / 'stop').exists():
                try:
                    result = await bridge.api('GET', '/messages?' + urlencode({
                        'chat_id': config['max_chat_id'], 'from': int(config['activated'] * 1000), 'count': 100}))
                    messages = result.get('messages')
                    if not isinstance(messages, list) or len(messages) >= 100:
                        raise ValueError('bounded_read_incomplete')
                    for message in messages:
                        payload = allowed_reply(message, config, store, config['activated'])
                        if payload:
                            if any(a['type'] == 'video' for a in payload['attachments']) and not payload['mode']:
                                store.set('video_choice_needed', True)
                                continue
                            store.add('max:' + payload['source_mid'], 'telegram', payload)
                    failures = 0
                    for row in store.db.execute("SELECT * FROM jobs WHERE state='pending' AND direction IN ('max','telegram') AND retry_at<=? ORDER BY rowid LIMIT 10", (time.time(),)).fetchall():
                        payload = json.loads(row['payload'])
                        if payload['chat'] not in config['allowed_peers']:
                            raise ValueError('destination_outside_allowlist')
                        try:
                            await (bridge.deliver_max(row['k'], payload) if row['direction'] == 'max'
                                   else bridge.deliver_telegram(row['k'], payload))
                        except Exception as error:
                            state = store.db.execute('SELECT state FROM jobs WHERE k=?', (row['k'],)).fetchone()[0]
                            if state not in ('uncertain', 'blocked'):
                                store.update(row['k'], 'blocked')
                            store.set('send_error', type(error).__name__)
                            stop.set()
                    for row in store.db.execute('SELECT mid FROM copies').fetchall():
                        seen = store.get('max_observed', [])
                        if row['mid'] not in seen:
                            fetched = await bridge.api('GET', '/messages/' + row['mid'])
                            message = fetched.get('message', fetched)
                            if (message['recipient']['chat_id'] != config['max_chat_id']
                                    or message['sender']['user_id'] != config['max_bot_id']):
                                raise ValueError('max_destination_not_verified')
                            store.set('max_observed', seen + [row['mid']])
                    store.set('last_read_ok', time.time())
                except Exception as error:
                    failures += 1
                    store.set('read_error', type(error).__name__)
                    if failures >= 3:
                        stop.set()
                private_write(root / 'status.json', {
                    'active': not stop.is_set(), 'activated': config['activated'], 'expires': expires,
                    'max_send_read_verified': store.get('max_probe_observed', False),
                    'forward_observed': len(store.get('max_observed', [])),
                    'reverse_observed': len(store.get('telegram_receipts', [])),
                    'coverage': {'personal_human': bool(store.get('max_observed', [])), 'groups': False},
                    'last_read_ok': store.get('last_read_ok'), 'read_error': store.get('read_error'),
                    'send_error': store.get('send_error'), 'video_choice_needed': store.get('video_choice_needed', False)})
                try:
                    await asyncio.wait_for(stop.wait(), timeout=4)
                except asyncio.TimeoutError:
                    pass
    finally:
        status_path = root / 'status.json'
        if status_path.exists():
            status = json.loads(status_path.read_text())
            status['active'] = False
            private_write(status_path, status)
        await client.disconnect()
        store.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--state', type=Path, required=True)
    parser.add_argument('--login-state', type=Path, required=True)
    parser.add_argument('--minutes', type=int, default=90, choices=range(1, 91))
    args = parser.parse_args()
    asyncio.run(run(args.state, args.login_state, args.minutes))
