#!/usr/bin/env python3
"""Telegram account ↔ owner-bound MAX bot.
All private state is outside this checkout.
"""
import argparse
import asyncio
import contextlib
import fcntl
import hashlib
import hmac
import ipaddress
import json
import logging
import mimetypes
import os
from pathlib import Path
import secrets
import socket
import ssl
import signal
import sqlite3
import time
from urllib.parse import quote, urlsplit

from aiohttp import ClientSession, ClientTimeout, FormData, web
from aiohttp.resolver import DefaultResolver
from telethon import TelegramClient, errors, functions, types, utils

MAX_BYTES = 250 * 1024 * 1024


def ssl_context():
    """Keep system roots and add the pinned public MAX trust root locally.

    Source: https://gu-st.ru/content/lending/russian_trusted_root_ca_pem.crt
    Authority: https://www.gosuslugi.ru/crt
    """
    pem = Path(__file__).with_name('russian_trusted_root_ca.pem').read_text(encoding='ascii')
    fingerprint = hashlib.sha256(ssl.PEM_cert_to_DER_cert(pem)).hexdigest()
    if fingerprint != 'd26d2d0231b7c39f92cc738512ba54103519e4405d68b5bd703e9788ca8ecf31':
        raise ValueError('max_trust_root_fingerprint_mismatch')
    context = ssl.create_default_context()
    context.load_verify_locations(cadata=pem)
    return context


def atomic(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temp = path.with_name(path.name + '.part')
    with temp.open('wb') as f:
        os.chmod(temp, 0o600)
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.replace(temp, path)
    fd = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def load_config(path):
    p = Path(path)
    if p.stat().st_mode & 0o077:
        raise ValueError('private_config_permissions')
    return json.loads(p.read_text())


class HistoryClient(TelegramClient):
    async def _call(self, sender, request, ordered=False, flood_sleep_threshold=None):
        # Resume the same history page after Telegram's required pause. Sending
        # keeps Telethon's zero-retry policy because its outcome can be uncertain.
        if not isinstance(request, (functions.messages.GetDialogsRequest,
                                    functions.messages.GetHistoryRequest,
                                    functions.messages.GetMessagesRequest,
                                    functions.channels.GetMessagesRequest)):
            return await super()._call(sender, request, ordered=ordered,
                                       flood_sleep_threshold=flood_sleep_threshold)
        for attempt in range(4):
            try:
                return await super()._call(sender, request, ordered=ordered,
                                           flood_sleep_threshold=0)
            except errors.FloodWaitError as error:
                if attempt == 3:
                    raise
                await asyncio.sleep(max(1, error.seconds))


class Store:
    def __init__(self, root):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.lock = (self.root / 'worker.lock').open('a')
        fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        self.db = sqlite3.connect(self.root / 'state.sqlite')
        self.db.row_factory = sqlite3.Row
        self.db.executescript('''
        PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;
        CREATE TABLE IF NOT EXISTS kv(k TEXT PRIMARY KEY,v TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS local_files(owner TEXT NOT NULL,path TEXT NOT NULL,
          removed INTEGER NOT NULL DEFAULT 0,PRIMARY KEY(owner,path));
        CREATE TABLE IF NOT EXISTS jobs(k TEXT PRIMARY KEY,direction TEXT NOT NULL,
          state TEXT NOT NULL,payload TEXT NOT NULL,attempts INTEGER NOT NULL DEFAULT 0,
          retry_at REAL NOT NULL DEFAULT 0);
        CREATE TABLE IF NOT EXISTS copies(mid TEXT PRIMARY KEY,chat INTEGER NOT NULL,
          message INTEGER NOT NULL,topic INTEGER,classification TEXT NOT NULL);
        ''')
        if 'bot_id' not in {r[1] for r in self.db.execute('PRAGMA table_info(copies)')}:
            self.db.execute('ALTER TABLE copies ADD COLUMN bot_id INTEGER')
        # MAX has no documented idempotency key. Never blindly repeat an uncertain send.
        self.db.execute("UPDATE jobs SET state='uncertain' WHERE state='sending' AND direction IN ('max','max-part','choice','notice')")
        self.db.execute("UPDATE jobs SET state='uncertain' WHERE state='sending' AND direction='telegram'")
        self.db.commit()

    def close(self):
        self.db.close()
        self.lock.close()

    def get(self, key, default=None):
        row = self.db.execute('SELECT v FROM kv WHERE k=?', (key,)).fetchone()
        return json.loads(row[0]) if row else default

    def set(self, key, value):
        with self.db:
            self.db.execute('INSERT OR REPLACE INTO kv VALUES (?,?)', (key, json.dumps(value)))

    def add(self, key, direction, payload, state='pending'):
        with self.db:
            self.db.execute('INSERT OR IGNORE INTO jobs(k,direction,state,payload) VALUES (?,?,?,?)',
                            (key, direction, state, json.dumps(payload)))

    def update(self, key, state, payload=None, delay=0):
        with self.db:
            self.db.execute('UPDATE jobs SET state=?,attempts=attempts+1,retry_at=? WHERE k=?',
                            (state, time.time() + delay, key))
            if payload is not None:
                self.db.execute('UPDATE jobs SET payload=? WHERE k=?', (json.dumps(payload), key))

    def binding(self, mid):
        row = self.db.execute('SELECT * FROM copies WHERE mid=?', (mid,)).fetchone()
        return dict(row) if row else None

    def complete_copy(self, key, mid, p):
        with self.db:
            self.db.execute('INSERT OR IGNORE INTO copies(mid,chat,message,topic,classification,bot_id) VALUES (?,?,?,?,?,?)',
                            (mid, p['chat'], p['message'], p.get('topic'), p['classification'], p.get('bot_id')))
            self.db.execute("UPDATE jobs SET state='done' WHERE k=?", (key,))


def protected(message, chat):
    media = getattr(message, 'media', None)
    return bool(getattr(message, 'noforwards', False) or getattr(chat, 'noforwards', False)
                or getattr(media, 'ttl_seconds', None) or getattr(message, 'ttl_period', None)
                or isinstance(message, types.MessageService))


def classify(config, chat):
    # Optional source exclusions are explicit; never infer them from names.
    return config.get('chat_classification', {}).get(str(chat), 'personal')


def media_kind(message):
    if isinstance(getattr(message, 'media', None), types.MessageMediaWebPage):
        return None
    if message.video_note:
        return 'round'
    if message.voice:
        return 'voice'
    if message.photo:
        return 'image'
    if message.video:
        return 'video'
    if message.audio:
        return 'audio'
    if message.document:
        return 'file'
    return None


def reply_input(message, config, store):
    if message.get('recipient', {}).get('chat_type') != 'dialog':
        return None
    sender = message.get('sender') or {}
    if sender.get('user_id') != config['max_owner_id'] or sender.get('is_bot'):
        return None
    link = message.get('link') or {}
    if link.get('type') != 'reply':
        return None
    mid = (link.get('message') or {}).get('mid')
    binding = store.binding(mid) if isinstance(mid, str) else None
    if not binding:
        return None
    if ((config.get('webhook_secret') or binding.get('bot_id') is not None)
            and binding.get('bot_id') != config['max_bot_id']):
        return None
    body = message.get('body') or {}
    if not isinstance(body.get('mid'), str):
        raise ValueError('missing_message_id')
    attachments = body.get('attachments') or []
    if len(attachments) > 10 or any(a.get('type') not in ('image', 'video', 'audio', 'file') for a in attachments):
        raise ValueError('unsupported_attachment')
    text = body.get('text') or ''
    mode = None
    # Explicit choice belongs to this reply, never a global sticky preference.
    if any(a.get('type') == 'video' for a in attachments):
        prefix, sep, rest = text.partition('\n')
        if prefix.strip().lower() in ('видео', 'кружочек'):
            mode = 'round' if prefix.strip().lower() == 'кружочек' else 'video'
            text = rest if sep else ''
    if not text and not attachments:
        raise ValueError('empty_reply')
    return dict(binding, bot_id=config['max_bot_id'], text=text, attachments=attachments, mode=mode,
                source_mid=body['mid'], random_ids=[secrets.randbits(63) for _ in range(len(attachments) + 1)])


async def public_url(url):
    p = urlsplit(url)
    if p.scheme != 'https' or not p.hostname or p.username or p.password or p.port not in (None, 443):
        raise ValueError('unsafe_media_url')
    rows = await asyncio.to_thread(socket.getaddrinfo, p.hostname, 443, type=socket.SOCK_STREAM)
    if not rows or any(not ipaddress.ip_address(r[4][0]).is_global for r in rows):
        raise ValueError('unsafe_media_host')
    return url


class PublicResolver(DefaultResolver):
    async def resolve(self, host, port=0, family=socket.AF_INET):
        rows = await super().resolve(host, port, family)
        if not rows or any(not ipaddress.ip_address(row['host']).is_global for row in rows):
            raise ValueError('non_public_destination')
        return rows


class MaxError(Exception):
    def __init__(self, status, code):
        self.status, self.code = status, code


class Bridge:
    def __init__(self, config, store, client=None):
        self.c, self.s, self.tg = config, store, client
        self.http = None
        self.stopping = False
        self.scan_pending = set()
        self.owner_usernames = None

    async def api(self, method, route, body=None):
        async with self.http.request(method, 'https://platform-api2.max.ru' + route,
                                     headers={'Authorization': self.c['max_bot_token']}, json=body) as r:
            result = await r.json(content_type=None)
            if r.status >= 400 or result.get('success') is False:
                raise MaxError(r.status if r.status >= 400 else 400, result.get('code', 'rejected'))
            return result

    def save_original(self, key, index, data, name, p):
        if not data or len(data) > MAX_BYTES:
            raise ValueError('invalid_media_size')
        digest = hashlib.sha256(data).hexdigest()
        path = self.s.root / 'originals' / hashlib.sha256(key.encode()).hexdigest() / str(index)
        self.track_files(key, path)
        atomic(path, data)
        atomic(path.with_suffix('.json'), json.dumps({'name': name, 'sha256': digest, 'size': len(data),
            'chat': p['chat'], 'message': p['message'], 'classification': p['classification']}).encode())
        # Optional independent cloud queues are seeded from durable local originals.
        return str(path)

    def track_files(self, key, source):
        # Register predictable outputs before writing, so crashes retain ownership.
        with self.s.db:
            for suffix in ('', '.json', '.jpg', '.ogg', '.m4a', '.mp4', '.part', '.json.part'):
                self.s.db.execute('INSERT OR IGNORE INTO local_files(owner,path) VALUES (?,?)',
                                  (key, str(source) + suffix))

    def cleanup_files(self):
        # Jobs and file ownership are durable. Re-running after any unlink is safe.
        jobs = {r['k']: r for r in self.s.db.execute('SELECT k,direction,state,payload FROM jobs')}
        payloads = {key: json.loads(row['payload']) for key, row in jobs.items()}
        for key, row in jobs.items():
            if row['direction'] not in ('max', 'telegram'):
                continue
            p = payloads[key]
            count = 1 if row['direction'] == 'max' and p.get('kind') else len(p.get('attachments', []))
            for index in range(count):
                source = self.s.root / 'originals' / hashlib.sha256(key.encode()).hexdigest() / str(index)
                # Adopt only historical files with their original integrity record.
                if source.with_suffix('.json').is_file():
                    self.track_files(key, source)
        active_payloads = [json.dumps(payloads[key]) for key, row in jobs.items() if row['state'] != 'done']
        paths = self.s.db.execute('SELECT DISTINCT path FROM local_files WHERE removed=0').fetchall()
        removed = 0
        for entry in paths:
            path = Path(entry['path'])
            owners = [r[0] for r in self.s.db.execute('SELECT owner FROM local_files WHERE path=?', (str(path),))]
            if any(owner not in jobs or jobs[owner]['state'] != 'done' for owner in owners):
                continue
            # Only exact registered files under this bridge's private originals tree.
            base = self.s.root / 'originals'
            if (path.parent.parent != base or base.is_symlink() or path.parent.is_symlink()
                    or path.is_symlink() or path.resolve().parent.parent != base.resolve()):
                continue
            source = path.with_name(path.name.split('.')[0])
            if (not source.name.isdecimal() or source.is_symlink()
                    or source.with_suffix('.json').is_symlink()
                    or any(str(source) in text for text in active_payloads)):
                continue
            try:
                meta_path = source.with_suffix('.json')
                if path.exists():
                    meta = json.loads(meta_path.read_text())
                    if any(not self.cleanup_backup_ready(owner, payloads[owner], source, meta) for owner in owners):
                        continue
                    # Keep the integrity record until all byte files have gone.
                    if path == meta_path and any(Path(str(source) + suffix).exists()
                            for suffix in ('', '.jpg', '.ogg', '.m4a', '.mp4', '.part', '.json.part')):
                        continue
                    path.unlink()
                    fd = os.open(path.parent, os.O_RDONLY)
                    try:
                        os.fsync(fd)
                    finally:
                        os.close(fd)
                    removed += 1
                with self.s.db:
                    self.s.db.execute('UPDATE local_files SET removed=1 WHERE path=?', (str(path),))
            except (OSError, ValueError, sqlite3.Error):
                logging.warning('local_cleanup_pending')
        return removed

    def cleanup_backup_ready(self, key, p, source, meta):
        targets = self.c.get('cloud_copies') or []
        if not targets:
            # Outstanding consumers survive removal of an optional configuration.
            table = self.s.db.execute("SELECT 1 FROM sqlite_master WHERE name='cloud_copies'").fetchone()
            return not table or not self.s.db.execute(
                "SELECT 1 FROM cloud_copies WHERE path=? AND state!='verified'", (str(source),)).fetchone()
        if len(targets) != 2 or targets[0]['endpoint'] == targets[1]['endpoint']:
            return False
        table = self.s.db.execute("SELECT 1 FROM sqlite_master WHERE name='cloud_copies'").fetchone()
        if not table:
            return False
        for target in targets:
            identity = hashlib.sha256((target['endpoint'] + '/' + target['bucket']).encode()).hexdigest()
            row = self.s.db.execute('SELECT state FROM cloud_copies WHERE path=? AND target=?',
                                    (str(source), identity)).fetchone()
            if not row or row[0] != 'verified':
                return False
        return not self.s.db.execute("SELECT 1 FROM cloud_copies WHERE path=? AND state!='verified'",
                                     (str(source),)).fetchone()

    def original(self, path):
        data = Path(path).read_bytes()
        meta = json.loads(Path(path).with_suffix('.json').read_text())
        if len(data) != meta['size'] or hashlib.sha256(data).hexdigest() != meta['sha256']:
            raise ValueError('original_integrity_failed')
        return data

    async def eligible(self, m, chat):
        if m.out or m.chat_id in (self.c['telegram_owner_id'], 777000) or m.sender_id == 777000:
            return False
        if str(m.chat_id) in self.c.get('excluded_chat_ids', []) or classify(self.c, m.chat_id) == 'excluded':
            return False
        if protected(m, chat):
            return False
        if isinstance(chat, types.User):
            # Telegram's auth notification accounts and bot conversations are never bridged.
            return not chat.bot and not getattr(chat, 'support', False)
        if not (isinstance(chat, types.Chat) or isinstance(chat, types.Channel) and chat.megagroup):
            return False
        if m.mentioned:
            return True
        entities = getattr(m, 'entities', None) or []
        if any(isinstance(entity, types.MessageEntityMentionName)
               and entity.user_id == self.c['telegram_owner_id'] for entity in entities):
            return True
        mentions = [entity for entity in entities if isinstance(entity, types.MessageEntityMention)]
        if mentions:
            if self.owner_usernames is None:
                owner = await self.tg.get_me()
                names = [getattr(owner, 'username', None)] + [
                    item.username for item in getattr(owner, 'usernames', None) or [] if item.active]
                self.owner_usernames = {'@' + name.casefold() for name in names if name}
            if any(text.casefold() in self.owner_usernames
                   for text in utils.get_inner_text(m.message or '', mentions)):
                return True
        if m.reply_to_msg_id:
            original = await self.tg.get_messages(chat, ids=m.reply_to_msg_id)
            return original is not None and original.sender_id == self.c['telegram_owner_id']
        return False

    async def capture(self, m, chat):
        if not await self.eligible(m, chat):
            return
        kind = media_kind(m)
        if m.media and not kind and not isinstance(m.media, types.MessageMediaWebPage):
            # Unsupported ephemeral/paid/contact/poll formats are not downloaded.
            return
        sender = await m.get_sender()
        header = ' '.join(filter(None, [getattr(sender, 'first_name', None), getattr(sender, 'last_name', None)])) or 'Отправитель'
        source = 'Личный чат' if isinstance(chat, types.User) else (getattr(chat, 'title', None) or 'Группа')
        header = source + '\n' + header
        note = {'voice': 'Голосовое (аудиозапись)', 'round': 'Кружочек (видеозапись)'}.get(kind)
        p = {'chat': m.chat_id, 'message': m.id,
             'topic': getattr(m.reply_to, 'reply_to_top_id', None) or
                      (getattr(m.reply_to, 'reply_to_msg_id', None) if getattr(m.reply_to, 'forum_topic', False) else None),
             'is_group': not isinstance(chat, types.User),
             'classification': classify(self.c, m.chat_id), 'text': header + '\n' + (note + '\n' if note else '') + (m.message or ''),
             'kind': kind, 'original_name': getattr(m.file, 'name', None) if m.file else None}
        # Queue source identity before downloading; do not advance a durable cursor past failures.
        self.s.add(f"tg:{m.chat_id}:{m.id}", 'max', p)

    async def scan(self):
        since = self.s.get('since')
        if since is None:
            self.s.set('since', int(time.time()))
            return
        # Poll history with per-dialog committed cursors; no read acknowledgements.
        # Errors abort that scan, not recorded as an empty history.
        async for dialog in self.tg.iter_dialogs(ignore_migrated=True):
            if dialog.id in (777000, self.c['telegram_owner_id']):
                continue
            chat = dialog.entity
            if isinstance(chat, types.User) and (chat.bot or getattr(chat, 'support', False)):
                continue
            if isinstance(chat, types.Channel) and not chat.megagroup:
                continue
            if str(dialog.id) in self.c.get('excluded_chat_ids', []) or classify(self.c, dialog.id) == 'excluded':
                continue
            try:
                await self.scan_dialog(dialog, since)
            except Exception as e:
                self.scan_pending.add(dialog.id)
                self.log_read_failure('dialog', dialog.id, e)

    def log_read_failure(self, kind, identity, error):
        opaque = hmac.new(self.c['local_token'].encode(),
                          f'{kind}:{identity}'.encode(), hashlib.sha256).hexdigest()[:24]
        logging.warning('source_read_pending time=%s object=%s failure=%s',
                        int(time.time()), opaque, type(error).__name__)

    async def scan_dialog(self, dialog, since):
        chat = dialog.entity
        key = f'cursor:{dialog.id}'
        cursor = self.s.get(key, 0)
        latest = getattr(dialog, 'message', None)
        if latest is not None and dialog.id not in self.scan_pending:
            latest_id = getattr(latest, 'id', None)
            latest_date = getattr(latest, 'date', None)
            if cursor and latest_id is not None and latest_id <= cursor:
                return
            if not cursor and latest_date is not None and latest_date.timestamp() < since:
                return
        if not cursor:
            import datetime
            start = datetime.datetime.fromtimestamp(since, datetime.timezone.utc)
            messages = self.tg.iter_messages(chat, offset_date=start, reverse=True)
        else:
            messages = self.tg.iter_messages(chat, min_id=cursor, reverse=True)
        async for m in messages:
            try:
                await self.capture(m, chat)
            except Exception as e:
                self.scan_pending.add(dialog.id)
                self.log_read_failure('message', f'{dialog.id}:{m.id}', e)
                raise
            self.s.set(key, m.id)
        self.scan_pending.discard(dialog.id)

    async def scan_loop(self):
        while not self.stopping:
            try:
                self.cleanup_files()
            except Exception:
                logging.warning('local_cleanup_pending')
            if self.c.get('enabled') and self.tg:
                try:
                    await self.scan()
                except Exception as e:
                    self.log_read_failure('scan', 'dialogs', e)
            await asyncio.sleep(30)

    async def refreshed_max_url(self, attachment, source_mid, rejected=None):
        payload = attachment.get('payload') or {}
        fresh = await self.api('GET', '/messages/' + quote(source_mid, safe=''))
        if fresh.get('body', {}).get('mid') != source_mid:
            raise ValueError('attachment_identity_unavailable')
        identity = next((k for k in ('token', 'photo_id') if payload.get(k) is not None), None)
        matches = [item for item in fresh.get('body', {}).get('attachments', [])
                   if identity and item.get('type') == attachment['type']
                   and item.get('payload', {}).get(identity) == payload[identity]]
        if len(matches) != 1:
            raise ValueError('attachment_identity_unavailable')
        current = matches[0].get('payload') or {}
        # The message URL is the supplied file. Playback variants are a fallback.
        url = current.get('url')
        if url and url != rejected:
            return url
        if attachment['type'] == 'video' and current.get('token'):
            info = await self.api('GET', '/videos/' + quote(current['token'], safe=''))
            if info.get('token') != current['token']:
                raise ValueError('attachment_identity_unavailable')
            urls = info.get('urls') or {}
            return next((urls[k] for k in ('mp4_1080', 'mp4_720', 'mp4_480',
                                          'mp4_360', 'mp4_240', 'mp4_144')
                         if urls.get(k) and urls[k] != rejected), None)
        return None

    async def download_max(self, attachment, source_mid):
        url = (attachment.get('payload') or {}).get('url')
        refreshes = 0
        if not url:
            url = await self.refreshed_max_url(attachment, source_mid)
        # Validate every redirect, never attach the bot token to a media host.
        for _ in range(7):
            if not url:
                raise ValueError('media_url_unavailable')
            await public_url(url)
            async with self.http.get(url, allow_redirects=False) as r:
                if r.status in (403, 404) and refreshes < (2 if attachment['type'] == 'video' else 1):
                    url = await self.refreshed_max_url(attachment, source_mid, rejected=url)
                    refreshes += 1
                    continue
                if r.status in (301, 302, 303, 307, 308):
                    from urllib.parse import urljoin
                    url = urljoin(url, r.headers['Location'])
                    continue
                r.raise_for_status()
                if int(r.headers.get('Content-Length', 0)) > MAX_BYTES:
                    raise ValueError('media_too_large')
                data = bytearray()
                async for chunk in r.content.iter_chunked(262144):
                    data.extend(chunk)
                    if len(data) > MAX_BYTES:
                        raise ValueError('media_too_large')
                return bytes(data)
        raise ValueError('media_redirect_limit')

    async def convert(self, source, kind):
        if kind == 'image':
            from PIL import Image, ImageOps
            target = source + '.jpg'
            with Image.open(source) as image:
                image = ImageOps.exif_transpose(image).convert('RGB')
                image.thumbnail((2560, 2560))
                image.save(target, format='JPEG', quality=90)
            os.chmod(target, 0o600)
            return target
        if kind not in ('voice', 'round', 'video', 'max_voice'):
            return source
        target = source + ('.ogg' if kind == 'voice' else '.m4a' if kind == 'max_voice' else '.mp4')
        args = ['ffmpeg', '-nostdin', '-v', 'error', '-y', '-i', source]
        if kind in ('voice', 'max_voice'):
            args += ['-vn', '-c:a', 'libopus' if kind == 'voice' else 'aac', '-ac', '1', '-ar', '48000']
        else:
            args += ['-map', '0:v:0', '-map', '0:a:0?', '-c:v', 'libx264', '-pix_fmt', 'yuv420p', '-c:a', 'aac', '-movflags', '+faststart']
            if kind == 'round':
                # Reject videos over Telegram's 60-second circle limit; never silently truncate.
                probe = await self.probe(source)
                if float(probe['format']['duration']) > 60:
                    raise ValueError('round_over_60_seconds')
                args += ['-vf', "crop=min(iw\\,ih):min(iw\\,ih),scale=384:384"]
        proc = await asyncio.create_subprocess_exec(*args, target, stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL)
        try:
            await asyncio.wait_for(proc.wait(), 180)
        except BaseException:
            proc.kill()
            await proc.wait()
            raise
        if proc.returncode:
            raise ValueError('conversion_failed')
        os.chmod(target, 0o600)
        return target

    async def probe(self, source):
        proc = await asyncio.create_subprocess_exec('ffprobe', '-v', 'error', '-show_format', '-show_streams', '-of', 'json', source,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
        out, _ = await asyncio.wait_for(proc.communicate(), 30)
        if proc.returncode:
            raise ValueError('probe_failed')
        return json.loads(out)

    async def upload_max(self, source, kind, name=None):
        result = await self.api('POST', '/uploads?type=' + kind)
        await public_url(result['url'])
        headers = {}
        if kind == 'image':
            if urlsplit(result['url']).hostname != 'iu.oneme.ru':
                raise ValueError('unsafe_photo_upload_host')
            headers['Authorization'] = self.c['max_bot_token']
        form = FormData()
        with open(source, 'rb') as f:
            form.add_field('data', f, filename=name or Path(source).name, content_type=mimetypes.guess_type(name or source)[0] or 'application/octet-stream')
            async with self.http.post(result['url'], data=form, headers=headers, allow_redirects=False) as r:
                r.raise_for_status()
                if r.status != 200:
                    raise ValueError('unexpected_upload_status')
                if kind in ('video', 'audio'):
                    if (await r.text()).strip() != '<retval>1</retval>':
                        raise ValueError('upload_failed')
                else:
                    uploaded = await r.json(content_type=None)
        if kind in ('video', 'audio'):
            payload = {'token': result['token']}
        elif kind == 'image':
            photos = list(uploaded['photos'].values())
            if len(photos) != 1:
                raise ValueError('unexpected_photo_upload_response')
            payload = {'token': photos[0]['token']}
        else:
            payload = {'token': uploaded['token']}
        if not isinstance(payload['token'], str) or not payload['token']:
            raise ValueError('missing_upload_token')
        return {'type': kind, 'payload': payload}

    async def deliver_max(self, key, p):
        p['bot_id'] = self.c['max_bot_id']
        # Revalidate source permissions immediately before copying original bytes.
        if classify(self.c, p['chat']) == 'excluded' or str(p['chat']) in self.c.get('excluded_chat_ids', []):
            self.s.update(key, 'blocked')
            return
        p['classification'] = classify(self.c, p['chat'])
        chat = await self.tg.get_entity(p['chat'])
        m = await self.tg.get_messages(chat, ids=p['message'])
        if m is None or protected(m, chat):
            self.s.update(key, 'blocked')
            return
        attachments = p.get('max_attachments', [])
        if p.get('kind') and not attachments:
            source = self.s.root / 'originals' / hashlib.sha256(key.encode()).hexdigest() / '0'
            if source.exists():
                data = self.original(source)
            else:
                if m.file and m.file.size and m.file.size > MAX_BYTES:
                    raise ValueError('media_too_large')
                data = await self.tg.download_media(m, file=bytes)
                source = Path(self.save_original(key, 0, data, p.get('original_name') or ('attachment' + (m.file.ext or '')), p))
            self.track_files(key, source)
            converted = await self.convert(str(source), 'max_voice' if p['kind'] == 'voice' else 'video' if p['kind'] in ('round', 'video') else p['kind'])
            kind = {'voice': 'audio', 'round': 'video'}.get(p['kind'], p['kind'])
            name = p.get('original_name') or ('attachment' + (m.file.ext or ''))
            if p['kind'] == 'image':
                name = 'image.jpg'
            elif p['kind'] == 'voice':
                name = 'voice.m4a'
            elif p['kind'] in ('video', 'round'):
                name = 'video.mp4'
            attachments = [await self.upload_max(converted, kind, name)]
            p['max_attachments'] = attachments
            # Retain the same upload token while MAX processes audio/video.
            self.s.update(key, 'pending', p)
        # Persist all chunks first; every delivered chunk receives a genuine binding.
        chunks = [p['text'][i:i+3500] for i in range(0, len(p['text']), 3500)] or ['Сообщение']
        for i, text in enumerate(chunks):
            part = key + f':part:{i}'
            existing = self.s.db.execute('SELECT state FROM jobs WHERE k=?', (part,)).fetchone()
            if existing and existing[0] == 'done':
                continue
            if existing and existing[0] in ('uncertain', 'sending'):
                self.s.update(key, 'uncertain')
                return
            self.s.add(part, 'max-part', p, 'reserved')
            self.s.update(part, 'sending')
            try:
                result = await self.api('POST', '/messages?user_id=' + str(self.c['max_owner_id']),
                                        {'text': text, **({'attachments': attachments} if i == 0 and attachments else {})})
                mid = result['message']['body']['mid']
                if not isinstance(mid, str) or not mid.strip():
                    raise RuntimeError('missing_delivery_receipt')
                self.s.complete_copy(part, mid, p)
            except MaxError as e:
                if e.code == 'attachment.not.ready':
                    self.s.update(part, 'reserved')
                    attempts = self.s.db.execute('SELECT attempts FROM jobs WHERE k=?', (key,)).fetchone()[0]
                    self.s.update(key, 'pending', p, delay=min(900, 5 * 2 ** min(attempts, 8)))
                    return
                elif e.status in (400, 401, 403, 404, 413, 429):
                    self.s.update(part, 'reserved')  # Explicit rejection: safe to retry.
                else:
                    self.s.update(part, 'uncertain')
                    self.s.update(key, 'uncertain')
                raise
            except BaseException:
                self.s.update(part, 'uncertain')
                self.s.update(key, 'uncertain')
                raise
        self.s.update(key, 'done')

    async def deliver_telegram(self, key, p):
        if classify(self.c, p['chat']) == 'excluded' or str(p['chat']) in self.c.get('excluded_chat_ids', []):
            self.s.update(key, 'blocked')
            return
        p['classification'] = classify(self.c, p['chat'])
        first_attempt = p.setdefault('first_attempt', time.time())
        if time.time() - first_attempt > 20 * 3600 and p.get('attempted'):
            self.s.update(key, 'uncertain', p)
            return
        peer = await self.tg.get_input_entity(p['chat'])
        original = await self.tg.get_messages(peer, ids=p['message'])
        if not original or protected(original, await self.tg.get_entity(peer)):
            self.s.update(key, 'blocked')
            return
        # Resolve peer and original only from the stored binding, never from MAX text.
        reply = types.InputReplyToMessage(reply_to_msg_id=p['message'], top_msg_id=p.get('topic'))
        done = p.setdefault('sent', [])
        for index, attachment in enumerate(p['attachments']):
            if index in done:
                continue
            source = self.s.root / 'originals' / hashlib.sha256(key.encode()).hexdigest() / str(index)
            name = attachment.get('filename') or ('attachment' + {'image': '.jpg', 'video': '.mp4', 'audio': '.ogg', 'file': ''}[attachment['type']])
            if source.exists():
                self.original(source)
            else:
                data = await self.download_max(attachment, p['source_mid'])
                source = Path(self.save_original(key, index, data, name, p))
            kind = 'voice' if attachment['type'] == 'audio' else p.get('mode') if attachment['type'] == 'video' else attachment['type']
            self.track_files(key, source)
            converted = await self.convert(str(source), kind)
            uploaded = await self.tg.upload_file(converted, file_name=name if kind == 'file' else 'image.jpg' if kind == 'image' else Path(converted).name)
            caption = p['text'] if index == 0 and kind != 'round' and len(p['text']) <= 1024 else ''
            if kind == 'image':
                media = types.InputMediaUploadedPhoto(file=uploaded)
            else:
                attrs = [types.DocumentAttributeFilename(file_name=name)]
                mime = mimetypes.guess_type(name)[0] or 'application/octet-stream'
                if kind == 'voice':
                    probe = await self.probe(converted)
                    attrs.append(types.DocumentAttributeAudio(duration=int(float(probe['format']['duration'])), voice=True))
                    mime = 'audio/ogg'
                if kind in ('video', 'round'):
                    probe = await self.probe(converted)
                    stream = next(s for s in probe['streams'] if s['codec_type'] == 'video')
                    attrs.append(types.DocumentAttributeVideo(duration=float(probe['format']['duration']), w=stream['width'], h=stream['height'],
                        round_message=kind == 'round', supports_streaming=True))
                    mime = 'video/mp4'
                media = types.InputMediaUploadedDocument(file=uploaded, mime_type=mime, attributes=attrs, force_file=kind == 'file')
            p['attempted'] = True
            self.s.update(key, 'sending', p)
            try:
                await self.tg(functions.messages.SendMediaRequest(peer=peer, media=media, message=caption,
                             random_id=p['random_ids'][index], reply_to=reply))
            except errors.RandomIdDuplicateError:
                pass
            except errors.FloodWaitError:
                raise
            except errors.RPCError as error:
                self.s.update(key, 'uncertain' if error.code >= 500 else 'blocked', p)
                raise
            except BaseException:
                self.s.update(key, 'uncertain', p)
                raise
            done.append(index)
            self.s.update(key, 'pending', p)
        needs_text = p['text'] and (not p['attachments'] or p.get('mode') == 'round' or len(p['text']) > 1024)
        if needs_text and 'text' not in done:
            # Telegram text limit is 4096; MAX text is bounded to the same size at acceptance.
            p['attempted'] = True
            self.s.update(key, 'sending', p)
            try:
                await self.tg(functions.messages.SendMessageRequest(peer=peer, message=p['text'],
                             random_id=p['random_ids'][-1], reply_to=reply, no_webpage=True))
            except errors.RandomIdDuplicateError:
                pass
            except errors.FloodWaitError:
                raise
            except errors.RPCError as error:
                self.s.update(key, 'uncertain' if error.code >= 500 else 'blocked', p)
                raise
            except BaseException:
                self.s.update(key, 'uncertain', p)
                raise
            done.append('text')
        self.s.update(key, 'done', p)

    async def accept(self, request):
        official = request.path == '/webhook'
        if official:
            secret = self.c.get('webhook_secret')
            if not secret or not hmac.compare_digest(request.headers.get('X-Max-Bot-Api-Secret', ''), secret):
                raise web.HTTPForbidden()
        elif not hmac.compare_digest(request.headers.get('Authorization', ''), 'Bearer ' + self.c['local_token']):
            raise web.HTTPForbidden()
        event = await request.json()
        if not self.c.get('enabled'):
            return web.json_response({'handled': False})
        return await self.accept_event(event)

    async def accept_event(self, event):
        if self.c.get('webhook_secret'):
            message = event.get('message') or {}
            if event.get('update_type') == 'message_created':
                if message.get('recipient', {}).get('user_id') != self.c['max_bot_id']:
                    return web.json_response({'handled': False})
            elif event.get('update_type') == 'message_callback':
                if (message.get('sender', {}).get('user_id') != self.c['max_bot_id']
                        or message.get('recipient', {}).get('user_id') != self.c['max_owner_id']):
                    return web.json_response({'handled': False})
        if event.get('update_type') == 'message_callback':
            return await self.choose(event)
        if event.get('update_type') != 'message_created':
            return web.json_response({'handled': False})
        p = reply_input(event.get('message') or {}, self.c, self.s)
        if p is None:
            return web.json_response({'handled': False})
        if len(p['text']) > 4096:
            raise web.HTTPBadRequest(text='reply_too_long')
        key = 'max:' + p['source_mid']
        self.s.add(key, 'telegram', p, 'awaiting_choice' if any(a['type'] == 'video' for a in p['attachments']) and not p['mode'] else 'pending')
        # No AI task is started for replies bound to a Telegram copy.
        return web.json_response({'handled': True})

    async def choose(self, event):
        callback = event.get('callback') or {}
        message = event.get('message') or {}
        if (callback.get('user', {}).get('user_id') != self.c['max_owner_id']
                or callback.get('user', {}).get('is_bot')
                or message.get('recipient', {}).get('chat_type') != 'dialog'):
            return web.json_response({'handled': True})
        payload = callback.get('payload', '')
        if not isinstance(payload, str) or not payload.startswith('tg-choice:'):
            return web.json_response({'handled': False})
        parts = payload.split(':')
        if len(parts) != 3 or parts[2] not in ('video', 'round'):
            return web.json_response({'handled': True})
        for row in self.s.db.execute("SELECT * FROM jobs WHERE state='choice_wait' AND direction='telegram'").fetchall():
            p = json.loads(row['payload'])
            if p.get('bot_id', self.c['max_bot_id']) != self.c['max_bot_id']:
                continue
            if p.get('choice_token') == parts[1] and p.get('choice_mid') == message.get('body', {}).get('mid'):
                p['mode'] = parts[2]
                self.s.update(row['k'], 'pending', p)
                break
        if self.c.get('webhook_secret') and isinstance(callback.get('callback_id'), str):
            try:
                await self.api('POST', '/answers?callback_id=' + quote(callback['callback_id'], safe=''), {})
            except Exception:
                logging.warning('callback_ack_pending')
        return web.json_response({'handled': True})

    async def prompt_choices(self):
        for row in self.s.db.execute("SELECT * FROM jobs WHERE state='awaiting_choice' AND direction='telegram'").fetchall():
            p = json.loads(row['payload'])
            p['choice_token'] = p.get('choice_token') or secrets.token_hex(16)
            part = row['k'] + ':choice'
            previous = self.s.db.execute('SELECT state FROM jobs WHERE k=?', (part,)).fetchone()
            if previous and previous[0] in ('uncertain', 'sending'):
                continue
            self.s.add(part, 'choice', p, 'reserved')
            self.s.update(part, 'sending', p)
            buttons = [[{'type': 'callback', 'text': label, 'payload': 'tg-choice:' + p['choice_token'] + ':' + mode}
                        for label, mode in [('Видео', 'video'), ('Кружочек', 'round')]]]
            try:
                response = await self.api('POST', '/messages?user_id=' + str(self.c['max_owner_id']),
                    {'text': 'Как отправить этот видеоответ в Telegram? Для кружочка нужно видео до 60 секунд; края будут обрезаны до круга.',
                     'link': {'type': 'reply', 'mid': p['source_mid']},
                     'attachments': [{'type': 'inline_keyboard', 'payload': {'buttons': buttons}}]})
                p['choice_mid'] = response['message']['body']['mid']
                with self.s.db:
                    self.s.db.execute("UPDATE jobs SET state='done' WHERE k=?", (part,))
                    self.s.db.execute("UPDATE jobs SET state='choice_wait',payload=? WHERE k=?", (json.dumps(p), row['k']))
            except MaxError as e:
                self.s.update(part, 'reserved' if e.status in (400, 401, 403, 404, 413, 429) else 'uncertain')
                raise
            except BaseException:
                self.s.update(part, 'uncertain')
                raise

    async def notice(self, key, text):
        part = key + ':notice'
        previous = self.s.db.execute('SELECT state FROM jobs WHERE k=?', (part,)).fetchone()
        if previous and previous[0] in ('done', 'uncertain', 'sending'):
            return
        self.s.add(part, 'notice', {'text': text})
        self.s.update(part, 'sending')
        try:
            await self.api('POST', '/messages?user_id=' + str(self.c['max_owner_id']), {'text': text})
            self.s.update(part, 'done')
        except MaxError as e:
            self.s.update(part, 'pending' if e.status in (400, 401, 403, 404, 413, 429) else 'uncertain')
        except Exception:
            self.s.update(part, 'uncertain')

    async def work(self):
        while not self.stopping:
            try:
                self.cleanup_files()
            except Exception:
                logging.warning('local_cleanup_pending')
            if self.c.get('enabled') and self.tg:
                try:
                    await self.prompt_choices()
                except Exception:
                    logging.warning('choice_delivery_pending')
                for notice in self.s.db.execute("SELECT k,payload FROM jobs WHERE direction='notice' AND state='pending' LIMIT 10").fetchall():
                    source_key = notice['k'].removesuffix(':notice')
                    source = self.s.db.execute('SELECT state FROM jobs WHERE k=?', (source_key,)).fetchone()
                    if source and source[0] == 'uncertain':
                        continue
                    await self.notice(source_key, json.loads(notice['payload'])['text'])
                rows = self.s.db.execute("SELECT * FROM jobs WHERE state='pending' AND retry_at<=? AND direction IN ('max','telegram') ORDER BY rowid LIMIT 30", (time.time(),)).fetchall()
                for row in rows:
                    try:
                        p = json.loads(row['payload'])
                        await (self.deliver_max(row['k'], p) if row['direction'] == 'max' else self.deliver_telegram(row['k'], p))
                    except errors.FloodWaitError as e:
                        self.s.update(row['k'], 'pending', delay=max(1, e.seconds))
                    except MaxError as e:
                        if e.status in (401, 403):
                            self.s.update(row['k'], 'blocked')
                            await self.notice(row['k'], 'Макс отказал в доступе. Проверь доступ личного бота и его ключ в закрытых настройках перед повтором.')
                        else:
                            current = self.s.db.execute('SELECT state FROM jobs WHERE k=?', (row['k'],)).fetchone()[0]
                            if current not in ('uncertain', 'blocked'):
                                self.s.update(row['k'], 'pending', delay=min(900, 5 * 2 ** min(row['attempts'], 8)))
                    except ValueError as e:
                        self.s.update(row['k'], 'blocked')
                        reason = {'round_over_60_seconds': 'Кружочек длиннее минуты. Повтори ответ, выбрав «Видео».',
                                  'media_too_large': 'Вложение слишком большое. Пришли уменьшенный файл.',
                                  'original_integrity_failed': 'Не удалось подтвердить целостность сохранённого вложения. Нужна проверка перед отправкой.'}.get(str(e),
                                  'Не удалось подготовить вложение для отправки. Повтори ответ в другом формате.')
                        await self.notice(row['k'], reason)
                        logging.warning('delivery_blocked')
                    except Exception:
                        current = self.s.db.execute('SELECT state FROM jobs WHERE k=?', (row['k'],)).fetchone()[0]
                        if current not in ('uncertain', 'blocked'):
                            self.s.update(row['k'], 'pending', delay=min(900, 5 * 2 ** min(row['attempts'], 8)))
                        logging.warning('delivery_blocked' if current == 'blocked' else 'delivery_pending')
            await asyncio.sleep(5)


async def private_qr_login(client, root, filename):
    # File-only QR is opt-in. Never place its short-lived login token in output.
    if Path(filename).name != filename or not filename.endswith('.png'):
        raise ValueError('private_qr_filename_required')
    import io
    import qrcode
    destination = root / filename
    qr = await client.qr_login()
    try:
        for attempt in range(10):
            image = qrcode.make(qr.url)
            buffer = io.BytesIO()
            image.save(buffer, format='PNG')
            atomic(destination, buffer.getvalue())
            print('Закрытый QR входа обновлён: ' + str(destination), flush=True)
            try:
                await qr.wait(timeout=30)
                return
            except asyncio.TimeoutError:
                if attempt == 9:
                    raise
                await qr.recreate()
    finally:
        destination.unlink(missing_ok=True)


async def main(args):
    os.umask(0o077)
    logging.basicConfig(level=logging.WARNING, format='%(asctime)s %(message)s')
    logging.getLogger('telethon').setLevel(logging.CRITICAL)
    c = load_config(args.config)
    if args.check:
        print(json.dumps({'enabled': bool(c.get('enabled')), 'personal_bot_bound': bool(c.get('max_owner_id') and c.get('max_bot_id')),
            'telegram_credentials': bool(c.get('api_id') and c.get('api_hash')),
            'session_present': (Path(c['state_dir']) / 'telegram.session').exists()}))
        return
    s = Store(c['state_dir'])
    client = None
    if args.enable and not (c.get('max_owner_id') and c.get('max_bot_id')):
        raise ValueError('max_pairing_required')
    if args.login or c.get('enabled'):
        if args.login:
            if not os.isatty(0) or not os.isatty(1):
                raise ValueError('private_terminal_required')
            if not c.get('api_id') or not c.get('api_hash'):
                import getpass
                print('Нужны реквизиты вашего приложения с https://my.telegram.org → API development tools. Они сохранятся только в закрытых настройках сервера.')
                c['api_id'] = int(getpass.getpass('api_id (ввод скрыт): ').strip())
                c['api_hash'] = getpass.getpass('api_hash (ввод скрыт): ').strip()
        if not c.get('api_id') or not c.get('api_hash'):
            raise ValueError('owner_telegram_application_credentials_required')
        client = HistoryClient(str(s.root / 'telegram'), c['api_id'], c['api_hash'], receive_updates=bool(args.login), request_retries=0, flood_sleep_threshold=0)
        await client.connect()
        if args.login:
            if not os.isatty(0) or not os.isatty(1):
                raise ValueError('private_terminal_required')
            if not await client.is_user_authorized():
                import qrcode
                try:
                    if getattr(args, 'qr_file', None):
                        await private_qr_login(client, s.root, args.qr_file)
                    else:
                        qr = await client.qr_login()
                        code = qrcode.QRCode()
                        code.add_data(qr.url)
                        code.print_ascii(invert=True)
                        await qr.wait(timeout=60)
                except errors.SessionPasswordNeededError:
                    import getpass
                    await client.sign_in(password=getpass.getpass('Пароль Telegram (ввод скрыт): '))
            me = await client.get_me()
            if me.bot:
                raise ValueError('personal_account_required')
            print('Подтвердите, что это ваш аккаунт:', me.first_name, me.phone)
            if input('Напишите ПОДТВЕРЖДАЮ: ').strip() != 'ПОДТВЕРЖДАЮ':
                raise ValueError('identity_not_confirmed')
            if c.get('telegram_owner_id') and c['telegram_owner_id'] != me.id:
                raise ValueError('telegram_identity_mismatch')
            c['telegram_owner_id'] = me.id
            if args.enable:
                c['enabled'] = True
                if s.get('since') is None:
                    s.set('since', int(time.time()))
            atomic(args.config, json.dumps(c, ensure_ascii=False, indent=2).encode())
            print('Вход подтверждён. Связь включится после запуска службы.' if c.get('enabled') else 'Вход подтверждён. Передача пока выключена.')
            await client.disconnect()
            s.close()
            return
        if not await client.is_user_authorized():
            raise ValueError('owner_login_required')
        me = await client.get_me()
        if me.bot or me.id != c.get('telegram_owner_id'):
            raise ValueError('telegram_identity_mismatch')
    b = Bridge(c, s, client)
    tls = ssl_context()
    from aiohttp import TCPConnector
    async with ClientSession(timeout=ClientTimeout(total=240), connector=TCPConnector(ssl=tls, resolver=PublicResolver())) as http:
        b.http = http
        bot = await b.api('GET', '/me')
        if bot.get('user_id') != c['max_bot_id']:
            raise ValueError('personal_max_bot_mismatch')
        app = web.Application(client_max_size=65536)
        async def accept_safe(request):
            try:
                return await b.accept(request)
            except web.HTTPException:
                raise
            except Exception:
                logging.warning('incoming_reply_pending')
                return web.json_response({'error': 'reply_not_accepted'}, status=503)
        app.router.add_post('/webhook', accept_safe)
        app.router.add_get('/health', lambda r: web.json_response({'ready': True, 'enabled': bool(c.get('enabled'))}))
        runner = web.AppRunner(app, access_log=None)
        await runner.setup()
        await web.TCPSite(runner, '127.0.0.1', c.get('port', 3117)).start()
        from cloud_copies import copy_loop
        cloud_task = asyncio.create_task(copy_loop(c, s))
        task = asyncio.create_task(b.work())
        scan_task = asyncio.create_task(b.scan_loop())
        logging.warning('bridge_ready')
        shutdown = asyncio.Event()
        for sig in (signal.SIGTERM, signal.SIGINT):
            asyncio.get_running_loop().add_signal_handler(sig, shutdown.set)
        try:
            await shutdown.wait()
        finally:
            cloud_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await cloud_task
            task.cancel()
            scan_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task
            with contextlib.suppress(asyncio.CancelledError):
                await scan_task
            await runner.cleanup()
            if client:
                await client.disconnect()
            s.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', default='/var/lib/telemax/config.json')
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--login', action='store_true')
    parser.add_argument('--enable', action='store_true')
    parser.add_argument('--qr-file', help='Закрытый PNG в папке состояния; обновление до пяти минут без QR в терминале')
    args = parser.parse_args()
    try:
        asyncio.run(main(args))
    except asyncio.TimeoutError:
        print('Время подтверждения истекло. Запусти подключение ещё раз в личном терминале.', flush=True)
        raise SystemExit(1)
    except Exception:
        print('Не удалось запустить связь. Проверь закрытые настройки или подтверди личный вход.', flush=True)
        raise SystemExit(1)
