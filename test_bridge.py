import asyncio
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace as NS
from unittest.mock import AsyncMock, Mock, patch
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer
from telethon import types

spec = importlib.util.spec_from_file_location('bridge', Path(__file__).with_name('bridge.py'))
b = importlib.util.module_from_spec(spec)
spec.loader.exec_module(b)


class BridgeTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.s = b.Store(self.tmp.name)
        self.c = {'max_owner_id': 123, 'max_bot_id': 456, 'telegram_owner_id': 789, 'enabled': True,
                  'local_token': 'test-only', 'chat_classification': {}}
        self.tg = NS(get_input_entity=AsyncMock(return_value='bound-peer'), get_entity=AsyncMock(return_value=types.User(id=20)),
                     get_messages=AsyncMock(return_value=NS(noforwards=False, media=None, ttl_period=None)),
                     upload_file=AsyncMock(return_value=types.InputFile(1, 1, 'test', '')))
        self.requests = []
        async def invoke(request):
            self.requests.append(request)
        class Telegram:
            async def __call__(_, request):
                return await invoke(request)
            def __getattr__(_, key):
                return getattr(self.tg, key)
        self.bridge = b.Bridge(self.c, self.s, Telegram())
        self.s.complete_copy('ignored', 'copy', {'chat': -10099, 'message': 81, 'topic': 7, 'classification': 'personal'})

    def tearDown(self):
        self.s.db.close()
        self.s.lock.close()
        self.tmp.cleanup()

    def event(self, attachments=None, text='Ответ'):
        return {'update_type': 'message_created', 'message': {'sender': {'user_id': 123},
            'recipient': {'chat_type': 'dialog'}, 'link': {'type': 'reply', 'message': {'mid': 'copy'}},
            'body': {'mid': 'incoming', 'text': text, 'attachments': attachments or []}}}

    async def test_history_rate_limit_resumes_same_request_without_retrying_sends(self):
        client = b.HistoryClient(None, 1, 'test', request_retries=0, flood_sleep_threshold=0)
        request = b.functions.messages.GetDialogsRequest(
            offset_date=None, offset_id=42, offset_peer=types.InputPeerEmpty(), limit=100, hash=0)
        pause = b.errors.FloodWaitError(request=request, capture=2)
        with patch.object(b.TelegramClient, '_call', AsyncMock(side_effect=[pause, 'page'])) as call, \
                patch.object(b.asyncio, 'sleep', AsyncMock()) as sleep:
            self.assertEqual(await client._call(None, request), 'page')
            self.assertEqual(call.await_count, 2)
            self.assertIs(call.call_args.args[1], request)
            self.assertEqual(call.call_args.kwargs['flood_sleep_threshold'], 0)
            sleep.assert_awaited_once_with(2)
        sender = NS(send=AsyncMock(side_effect=[pause, 'page']))
        with patch.object(b.asyncio, 'sleep', AsyncMock()) as sleep:
            self.assertEqual(await client._call(sender, request), 'page')
            self.assertEqual(sender.send.call_count, 2)
            sleep.assert_awaited_once_with(2)
        send = b.functions.messages.SendMessageRequest(types.InputPeerSelf(), 'test', random_id=1)
        with patch.object(b.TelegramClient, '_call', AsyncMock(side_effect=pause)) as call:
            with self.assertRaises(b.errors.FloodWaitError):
                await client._call(None, send)
            self.assertEqual(call.await_count, 1)
        with patch.object(b.TelegramClient, '_call', AsyncMock(side_effect=pause)) as call, \
                patch.object(b.asyncio, 'sleep', AsyncMock()):
            with self.assertRaises(b.errors.FloodWaitError):
                await client._call(None, request)
            self.assertEqual(call.await_count, 4)

    async def test_owner_private_bound_only(self):
        event = self.event()
        self.assertEqual(b.reply_input(event['message'], self.c, self.s)['message'], 81)
        for field, value in [('sender', {'user_id': 999}), ('recipient', {'chat_type': 'chat'}),
                             ('link', {'type': 'reply', 'message': {'mid': 'unknown'}}),
                             ('sender', {'user_id': 123, 'is_bot': True})]:
            changed = self.event()['message']
            changed[field] = value
            self.assertIsNone(b.reply_input(changed, self.c, self.s))

    async def test_duplicate_events_and_restart_keep_target_and_random_ids(self):
        p = b.reply_input(self.event()['message'], self.c, self.s)
        self.s.add('same', 'telegram', p)
        altered = dict(p, chat=999, random_ids=[0])
        self.s.add('same', 'telegram', altered)
        self.s.update('same', 'sending')
        self.s.db.close(); self.s.lock.close()
        self.s = b.Store(self.tmp.name)
        row = self.s.db.execute('SELECT * FROM jobs WHERE k=?', ('same',)).fetchone()
        self.assertEqual(row['state'], 'uncertain')
        self.assertEqual(json.loads(row['payload']), p)
        self.assertEqual(self.s.binding('copy')['topic'], 7)

    async def test_text_uses_exact_source_and_topic(self):
        p = b.reply_input(self.event()['message'], self.c, self.s)
        self.s.add('reply', 'telegram', p)
        await self.bridge.deliver_telegram('reply', p)
        self.assertEqual(len(self.requests), 1)
        request = self.requests[0]
        self.assertEqual(request.peer, 'bound-peer')
        self.assertEqual(request.reply_to.reply_to_msg_id, 81)
        self.assertEqual(request.reply_to.top_msg_id, 7)
        self.assertEqual(request.random_id, p['random_ids'][-1])
        self.assertEqual(self.s.db.execute("SELECT state FROM jobs WHERE k='reply'").fetchone()[0], 'done')

    async def test_group_filter_and_protected_sources(self):
        m = NS(out=False, chat_id=-77, sender_id=20, media=None, noforwards=False, ttl_period=None,
               mentioned=False, reply_to_msg_id=None)
        group = types.Channel(id=77, title='Work', photo=types.ChatPhotoEmpty(), date=None, megagroup=True)
        self.assertFalse(await self.bridge.eligible(m, group))
        m.mentioned = True
        self.assertTrue(await self.bridge.eligible(m, group))
        m.mentioned = False; m.reply_to_msg_id = 50
        self.tg.get_messages.return_value = NS(sender_id=789)
        self.assertTrue(await self.bridge.eligible(m, group))
        self.tg.get_messages.return_value = NS(sender_id=30)
        self.assertFalse(await self.bridge.eligible(m, group))
        self.tg.get_messages.return_value = None
        self.assertFalse(await self.bridge.eligible(m, group))
        self.tg.get_messages.side_effect = OSError('private detail')
        with self.assertRaises(OSError):
            await self.bridge.eligible(m, group)
        self.tg.get_messages.side_effect = None
        m.noforwards = True
        self.assertFalse(await self.bridge.eligible(m, group))
        m.noforwards = False; m.media = NS(ttl_seconds=10)
        self.assertFalse(await self.bridge.eligible(m, group))
        m.media = None; m.sender_id = 777000
        self.assertFalse(await self.bridge.eligible(m, types.User(id=777000)))
        m.sender_id = 20
        self.assertFalse(await self.bridge.eligible(m, types.User(id=20, bot=True)))

    async def test_group_mentions_survive_cleared_flag_and_preserve_reply_topic(self):
        self.tg.get_me = AsyncMock(return_value=types.User(id=789, username='Owner'))
        chats = [types.Chat(id=77, title='Service', photo=types.ChatPhotoEmpty(),
                            participants_count=2, date=None, version=1),
                 types.Channel(id=78, title='Service', photo=types.ChatPhotoEmpty(), date=None, megagroup=True),
                 types.Channel(id=79, title='Service', photo=types.ChatPhotoEmpty(), date=None, megagroup=True, forum=True)]
        for chat in chats:
            for addressed in ('username', 'user', 'reply'):
                with self.subTest(chat=type(chat).__name__, addressed=addressed, forum=getattr(chat, 'forum', False)):
                    topic = 7 if getattr(chat, 'forum', False) else None
                    entities = [types.MessageEntityMention(3, 6)] if addressed == 'username' else [
                        types.MessageEntityMentionName(3, 6, 789)] if addressed == 'user' else []
                    message = NS(id=81, chat_id=-chat.id, sender_id=20, out=False, mentioned=False,
                        noforwards=False, ttl_period=None, media=None, file=None, message='😀 @oWnEr',
                        video_note=False, voice=False, photo=None, video=None, audio=None, document=None,
                        entities=entities, reply_to_msg_id=50 if addressed == 'reply' else None,
                        reply_to=types.MessageReplyHeader(reply_to_msg_id=50, reply_to_top_id=topic,
                                                        forum_topic=bool(topic)) if topic or addressed == 'reply' else None,
                        get_sender=AsyncMock(return_value=types.User(id=20, first_name='Service')))
                    self.tg.get_messages.return_value = NS(sender_id=789)
                    self.assertTrue(await self.bridge.eligible(message, chat))
                    await self.bridge.capture(message, chat)
                    key = f'tg:{message.chat_id}:81'
                    p = json.loads(self.s.db.execute('SELECT payload FROM jobs WHERE k=?', (key,)).fetchone()[0])
                    # Each source must have its own copy identity.
                    with self.s.db:
                        self.s.db.execute('DELETE FROM copies WHERE mid=?', ('service-copy',))
                    self.s.complete_copy(key, 'service-copy', dict(p, bot_id=456))
                    event = self.event()
                    event['message']['link']['message']['mid'] = 'service-copy'
                    await self.bridge.accept_event(event)
                    row = self.s.db.execute("SELECT payload FROM jobs WHERE k='max:incoming'").fetchone()
                    reply = json.loads(row[0])
                    self.assertEqual((reply['chat'], reply['message'], reply['topic']), (message.chat_id, 81, topic))
                    self.requests.clear()
                    self.tg.get_messages.return_value = NS(noforwards=False, media=None, ttl_period=None)
                    await self.bridge.deliver_telegram('max:incoming', reply)
                    self.assertEqual(self.requests[-1].reply_to.reply_to_msg_id, 81)
                    self.assertEqual(self.requests[-1].reply_to.top_msg_id, topic)
                    with self.s.db:
                        self.s.db.execute("DELETE FROM jobs WHERE k='max:incoming'")
            message.entities = [types.MessageEntityMentionName(3, 6, 999)]
            message.reply_to_msg_id = None
            self.assertFalse(await self.bridge.eligible(message, chat))
            message.entities = [types.MessageEntityMention(3, 6)]
            message.message = '😀 @Other'
            self.assertFalse(await self.bridge.eligible(message, chat))
        self.tg.get_me.assert_awaited_once()

    async def test_video_choice_is_explicit_and_per_reply(self):
        attachments = [{'type': 'video', 'payload': {'token': 'test'}}]
        p = b.reply_input(self.event(attachments)['message'], self.c, self.s)
        self.assertIsNone(p['mode'])
        p = b.reply_input(self.event(attachments, 'кружочек\nподпись')['message'], self.c, self.s)
        self.assertEqual(p['mode'], 'round'); self.assertEqual(p['text'], 'подпись')
        p = b.reply_input(self.event(attachments, 'видео')['message'], self.c, self.s)
        self.assertEqual(p['mode'], 'video')
        self.s.add('video', 'telegram', dict(p, choice_token='safe', choice_mid='question'), 'choice_wait')
        def callback(owner=123, mid='question', mode='round'):
            return {'callback': {'user': {'user_id': owner}, 'payload': 'tg-choice:safe:' + mode},
                    'message': {'recipient': {'chat_type': 'dialog'}, 'body': {'mid': mid}}}
        await self.bridge.choose(callback(owner=999))
        await self.bridge.choose(callback(mid='other'))
        self.assertEqual(self.s.db.execute("SELECT state FROM jobs WHERE k='video'").fetchone()[0], 'choice_wait')
        await self.bridge.choose(callback())
        row = self.s.db.execute("SELECT * FROM jobs WHERE k='video'").fetchone()
        self.assertEqual(row['state'], 'pending'); self.assertEqual(json.loads(row['payload'])['mode'], 'round')
        await self.bridge.choose(callback(mode='video'))
        self.assertEqual(json.loads(self.s.db.execute("SELECT payload FROM jobs WHERE k='video'").fetchone()[0])['mode'], 'round')

    async def test_http_auth_and_durable_acceptance(self):
        app = web.Application(); app.router.add_post('/accept', self.bridge.accept)
        async with TestClient(TestServer(app)) as client:
            r = await client.post('/accept', json=self.event())
            self.assertEqual(r.status, 403)
            for _ in range(2):
                r = await client.post('/accept', json=self.event(), headers={'Authorization': 'Bearer test-only'})
                self.assertEqual(await r.json(), {'handled': True})
            self.assertEqual(self.s.db.execute("SELECT count(*) FROM jobs WHERE k='max:incoming'").fetchone()[0], 1)
            self.c['enabled'] = False
            r = await client.post('/accept', json=self.event(), headers={'Authorization': 'Bearer test-only'})
            self.assertEqual(await r.json(), {'handled': False})

    async def test_original_is_local_and_integrity_checked(self):
        p = {'chat': -77, 'message': 81, 'classification': 'personal'}
        path = self.bridge.save_original('synthetic', 0, b'original', 'photo.jpg', p)
        self.assertEqual(self.bridge.original(path), b'original')
        Path(path).write_bytes(b'changed')
        with self.assertRaises(ValueError):
            self.bridge.original(path)

    async def test_media_classification(self):
        for expected, attr in [('round', 'video_note'), ('voice', 'voice'), ('image', 'photo'), ('video', 'video'), ('audio', 'audio'), ('file', 'document')]:
            message = NS(**{k: k == attr for k in ('video_note', 'voice', 'photo', 'video', 'audio', 'document')})
            self.assertEqual(b.media_kind(message), expected)

    async def test_uncertain_max_send_is_not_repeated_after_restart(self):
        p = {'chat': 20, 'message': 81, 'topic': None, 'classification': 'personal', 'kind': None, 'text': 'private'}
        self.s.add('tg:20:81', 'max', p)
        self.bridge.api = AsyncMock(side_effect=TimeoutError())
        with self.assertRaises(TimeoutError):
            await self.bridge.deliver_max('tg:20:81', p)
        self.s.db.close(); self.s.lock.close()
        self.s = b.Store(self.tmp.name)
        self.assertEqual(self.s.db.execute("SELECT state FROM jobs WHERE k='tg:20:81'").fetchone()[0], 'uncertain')
        self.assertEqual(self.s.db.execute("SELECT state FROM jobs WHERE k='tg:20:81:part:0'").fetchone()[0], 'uncertain')

    async def test_all_media_to_telegram_with_native_attributes_and_captions(self):
        self.bridge.download_max = AsyncMock(return_value=b'original')
        async def passthrough(source, kind):
            return source
        self.bridge.convert = AsyncMock(side_effect=passthrough)
        self.bridge.probe = AsyncMock(return_value={'format': {'duration': '2'}, 'streams': [{'codec_type': 'video', 'width': 384, 'height': 384}]})
        for index, (kind, mode) in enumerate([('image', None), ('video', 'video'), ('audio', None), ('video', 'round'), ('file', None)]):
            event = self.event([{'type': kind, 'filename': 'sample', 'payload': {'url': 'https://example.org/media'}}])
            event['message']['body']['mid'] = str(index)
            p = b.reply_input(event['message'], self.c, self.s); p['mode'] = mode
            key = 'media:' + str(index); self.s.add(key, 'telegram', p)
            self.requests.clear()
            await self.bridge.deliver_telegram(key, p)
            req = self.requests[0]
            if mode == 'round':
                self.assertTrue(any(isinstance(a, types.DocumentAttributeVideo) and a.round_message for a in req.media.attributes))
                self.assertEqual(self.requests[1].message, 'Ответ')
            elif kind == 'audio':
                self.assertTrue(any(isinstance(a, types.DocumentAttributeAudio) and a.voice for a in req.media.attributes))
            elif kind == 'image':
                self.assertIsInstance(req.media, types.InputMediaUploadedPhoto)
            if mode != 'round':
                self.assertEqual(req.message, 'Ответ')
            self.assertEqual(req.reply_to.reply_to_msg_id, 81)

    async def test_two_way_copy_binding_media_and_reply_end_to_end(self):
        async def passthrough(source, kind):
            return source
        self.bridge.convert = AsyncMock(side_effect=passthrough)
        self.bridge.probe = AsyncMock(return_value={'format': {'duration': '1'}, 'streams': [{'codec_type': 'video', 'width': 384, 'height': 384}]})
        self.bridge.upload_max = AsyncMock(side_effect=lambda source, kind, name=None: {'type': kind, 'payload': {'token': 'fake'}})
        self.bridge.download_max = AsyncMock(return_value=b'max-original')
        self.tg.download_media = AsyncMock(return_value=b'tg-original')
        chat = types.User(id=20, first_name='Synthetic')
        self.tg.get_entity.return_value = chat
        for i, (kind, attribute, max_kind) in enumerate([
                (None, None, None), ('image', 'photo', 'image'), ('video', 'video', 'video'),
                ('voice', 'voice', 'audio'), ('round', 'video_note', 'video'), ('audio', 'audio', 'audio'), ('file', 'document', 'file')]):
            message = NS(id=100+i, chat_id=20, sender_id=20, out=False, noforwards=False, ttl_period=None,
                media=None if not kind else NS(ttl_seconds=None), message='caption', reply_to=None,
                file=None if not kind else NS(name='source.dat', ext='.dat', size=11),
                get_sender=AsyncMock(return_value=chat), **{k: attribute == k for k in ('photo','video','voice','video_note','audio','document')})
            self.tg.get_messages.return_value = message
            self.bridge.api = AsyncMock(return_value={'message': {'body': {'mid': 'copied-' + str(i)}}})
            await self.bridge.capture(message, chat)
            key = 'tg:20:' + str(message.id)
            row = self.s.db.execute('SELECT * FROM jobs WHERE k=?', (key,)).fetchone()
            self.assertIsNotNone(row)
            await self.bridge.deliver_max(key, json.loads(row['payload']))
            body = self.bridge.api.call_args.args[2]
            self.assertTrue(body['text'].startswith('Личный чат\nSynthetic\n'))
            self.assertTrue(body['text'].endswith('caption'))
            if max_kind:
                self.assertEqual(body['attachments'][0]['type'], max_kind)
            if kind == 'voice': self.assertIn('Голосовое', body['text'])
            if kind == 'round': self.assertIn('Кружочек', body['text'])
            binding = self.s.binding('copied-' + str(i))
            self.assertEqual((binding['chat'], binding['message']), (20, message.id))
            event = self.event([{'type': max_kind, 'payload': {'token': 'fake'}}] if max_kind else [])
            event['message']['link']['message']['mid'] = 'copied-' + str(i)
            event['message']['body']['mid'] = 'response-' + str(i)
            p = b.reply_input(event['message'], self.c, self.s)
            if max_kind == 'video': p['mode'] = 'round' if kind == 'round' else 'video'
            reply_key = 'max:response-' + str(i)
            self.s.add(reply_key, 'telegram', p)
            self.requests.clear()
            await self.bridge.deliver_telegram(reply_key, p)
            self.assertTrue(self.requests)
            self.assertTrue(all(r.reply_to.reply_to_msg_id == message.id for r in self.requests))
            self.assertEqual(self.s.db.execute('SELECT state FROM jobs WHERE k=?', (reply_key,)).fetchone()[0], 'done')

    async def test_source_header_for_all_media_and_chat_types(self):
        sender = types.User(id=20, first_name='Имя', last_name='Автора')
        chats = [(types.User(id=20), 'Личный чат'),
                 (types.Chat(id=77, title='Название группы', photo=types.ChatPhotoEmpty(),
                             participants_count=2, date=None, version=1), 'Название группы'),
                 (types.Channel(id=78, title='', photo=types.ChatPhotoEmpty(),
                                date=None, megagroup=True), 'Группа')]
        kinds = [(None, None), ('image', 'photo'), ('video', 'video'), ('voice', 'voice'),
                 ('round', 'video_note'), ('audio', 'audio'), ('file', 'document')]
        for chat, source in chats:
            for i, (kind, attribute) in enumerate(kinds):
                with self.subTest(source=source, kind=kind):
                    chat_id = 20 if isinstance(chat, types.User) else -chat.id
                    message = NS(id=500+i, chat_id=chat_id, sender_id=20, out=False,
                        noforwards=False, ttl_period=None, mentioned=True, reply_to_msg_id=None,
                        media=None if kind is None else NS(ttl_seconds=None), message='Подпись или текст',
                        reply_to=None, file=None, get_sender=AsyncMock(return_value=sender),
                        **{k: attribute == k for k in ('photo','video','voice','video_note','audio','document')})
                    await self.bridge.capture(message, chat)
                    row = self.s.db.execute('SELECT payload FROM jobs WHERE k=?',
                                           (f'tg:{chat_id}:{message.id}',)).fetchone()
                    payload = json.loads(row[0])
                    note = {'voice': 'Голосовое (аудиозапись)\n',
                            'round': 'Кружочек (видеозапись)\n'}.get(kind, '')
                    self.assertEqual(payload['text'], source + '\nИмя Автора\n' + note + 'Подпись или текст')
                    self.assertEqual(payload['kind'], kind)

    async def test_source_failure_preserves_cursor_for_replay(self):
        chat = types.User(id=20)
        dialog = NS(id=20, entity=chat)
        async def messages(*a, **k):
            yield NS(id=9)
            yield NS(id=10)
        self.tg.iter_messages = messages
        async def capture(message, chat):
            if message.id == 10:
                raise OSError('synthetic read failure')
        self.bridge.capture = capture
        with self.assertRaises(OSError):
            await self.bridge.scan_dialog(dialog, 0)
        self.assertEqual(self.s.get('cursor:20'), 9)

    async def test_official_upload_responses_and_authorization(self):
        source = Path(self.tmp.name) / 'media'
        source.write_bytes(b'synthetic-media')
        self.c['max_bot_token'] = 'test-secret'
        for kind, host, uploaded in [
                ('video', 'omub.okcdn.ru', None), ('audio', 'omu.okcdn.ru', None),
                ('image', 'iu.oneme.ru', {'photos': {'photo-id': {'token': 'image-token'}}}),
                ('file', 'fu.oneme.ru', {'token': 'file-token', 'fileId': 123})]:
            with self.subTest(kind=kind):
                self.bridge.api = AsyncMock(return_value={'url': 'https://' + host + '/upload', 'token': kind + '-token'})
                response = NS(status=200, raise_for_status=Mock(),
                              text=AsyncMock(return_value='<retval>1</retval>'),
                              json=AsyncMock(return_value=uploaded))
                context = AsyncMock()
                context.__aenter__.return_value = response
                self.bridge.http = NS(post=Mock(return_value=context))
                with patch.object(b, 'public_url', AsyncMock()):
                    result = await self.bridge.upload_max(str(source), kind)
                self.assertEqual(result, {'type': kind, 'payload': {'token': kind + '-token'}})
                options = self.bridge.http.post.call_args.kwargs
                self.assertFalse(options['allow_redirects'])
                self.assertEqual(options['headers'], {'Authorization': 'test-secret'} if kind == 'image' else {})
                if kind in ('video', 'audio'):
                    response.json.assert_not_awaited()
                    response.text.return_value = '<retval>0</retval>'
                    with patch.object(b, 'public_url', AsyncMock()), self.assertRaises(ValueError):
                        await self.bridge.upload_max(str(source), kind)
                response.status = 302
                with patch.object(b, 'public_url', AsyncMock()), self.assertRaises(ValueError):
                    await self.bridge.upload_max(str(source), kind)
        for url in ('https://evil.example/upload', 'https://iu.oneme.ru.evil.example/upload'):
            self.bridge.api = AsyncMock(return_value={'url': url})
            self.bridge.http.post.reset_mock()
            with patch.object(b, 'public_url', AsyncMock()), self.assertRaises(ValueError):
                await self.bridge.upload_max(str(source), 'image')
            self.bridge.http.post.assert_not_called()

    async def test_max_processing_reuses_uploaded_token(self):
        p = {'chat': 20, 'message': 81, 'topic': None, 'classification': 'personal', 'kind': 'video', 'text': 'caption',
             'max_attachments': [{'type': 'video', 'payload': {'token': 'processing-token'}}]}
        self.s.add('processing', 'max', p)
        self.bridge.api = AsyncMock(side_effect=b.MaxError(400, 'attachment.not.ready'))
        self.bridge.upload_max = AsyncMock()
        await self.bridge.deliver_max('processing', p)
        row = self.s.db.execute("SELECT * FROM jobs WHERE k='processing'").fetchone()
        self.assertEqual(row['state'], 'pending')
        self.assertGreater(row['retry_at'], b.time.time())
        p = json.loads(row['payload'])
        self.assertEqual(p['max_attachments'][0]['payload']['token'], 'processing-token')
        self.bridge.upload_max.assert_not_awaited()
        self.assertEqual(self.s.db.execute("SELECT state FROM jobs WHERE k='processing:part:0'").fetchone()[0], 'reserved')
        self.bridge.api = AsyncMock(return_value={'message': {'body': {'mid': 'processed'}}})
        await self.bridge.deliver_max('processing', p)
        self.bridge.upload_max.assert_not_awaited()
        self.assertEqual(self.s.binding('processed')['message'], 81)

    async def test_web_preview_text_and_protected_media(self):
        chat = types.User(id=20, first_name='Synthetic')
        for i, media in enumerate([types.MessageMediaWebPage(types.WebPageEmpty(id=1)),
                                   types.MessageMediaPhoto(ttl_seconds=5),
                                   types.MessageMediaDocument(ttl_seconds=5), NS(), None]):
            m = NS(id=200+i, chat_id=20, sender_id=20, out=False, noforwards=False,
                   ttl_period=None, media=media, message='Full https://example.org/link',
                   reply_to=None, file=None, get_sender=AsyncMock(return_value=chat),
                   **{k: i == 0 and k == 'photo' for k in ('video_note', 'voice', 'photo', 'video', 'audio', 'document')})
            await self.bridge.capture(m, chat)
            row = self.s.db.execute('SELECT payload FROM jobs WHERE k=?', (f'tg:20:{m.id}',)).fetchone()
            if i in (0, 4):
                self.assertTrue(json.loads(row[0])['text'].endswith(m.message))
                self.assertIsNone(json.loads(row[0])['kind'])
            else:
                self.assertIsNone(row)
            m.noforwards = True
            m.id += 100
            await self.bridge.capture(m, chat)
            self.assertIsNone(self.s.db.execute('SELECT payload FROM jobs WHERE k=?', (f'tg:20:{m.id}',)).fetchone())

    async def test_deleted_reply_advances_but_read_error_retries(self):
        group = types.Chat(id=77, title='Synthetic', photo=types.ChatPhotoEmpty(), participants_count=2, date=None, version=1)
        dialog = NS(id=-77, entity=group)
        async def messages(*args, **kwargs):
            for i in (9, 10):
                yield NS(id=i, chat_id=-77, sender_id=20, out=False, media=None,
                         noforwards=False, ttl_period=None, mentioned=False, reply_to_msg_id=5)
        self.tg.iter_messages = messages
        self.tg.get_messages.side_effect = OSError('secret name and text')
        with self.assertLogs(level='WARNING') as logs:
            with self.assertRaises(OSError):
                await self.bridge.scan_dialog(dialog, 0)
        self.assertIsNone(self.s.get('cursor:-77'))
        self.assertIn('failure=OSError', logs.output[0])
        self.assertNotIn('secret', logs.output[0])
        self.assertNotIn('-77', logs.output[0])
        self.tg.get_messages.side_effect = None
        self.tg.get_messages.return_value = None
        await self.bridge.scan_dialog(dialog, 0)
        self.assertEqual(self.s.get('cursor:-77'), 10)

    async def test_dialog_hints_preserve_saved_positions_and_retry(self):
        import datetime
        dialog = NS(id=20, entity=types.User(id=20), message=NS(id=10, date=datetime.datetime.fromtimestamp(10, datetime.timezone.utc)))
        calls = []
        async def messages(*args, **kwargs):
            calls.append(kwargs)
            if False:
                yield
        self.tg.iter_messages = messages
        await self.bridge.scan_dialog(dialog, 100)
        self.assertEqual(calls, [])
        self.s.set('cursor:20', 9)
        await self.bridge.scan_dialog(dialog, 100)
        self.assertEqual(calls[-1]['min_id'], 9)
        self.s.set('cursor:20', 10)
        calls.clear()
        await self.bridge.scan_dialog(dialog, 100)
        self.assertEqual(calls, [])
        self.bridge.scan_pending.add(20)
        await self.bridge.scan_dialog(dialog, 100)
        self.assertEqual(calls[-1]['min_id'], 10)
        del dialog.message
        calls.clear()
        await self.bridge.scan_dialog(dialog, 100)
        self.assertTrue(calls)

    async def test_expired_media_refresh_and_identity(self):
        from contextlib import asynccontextmanager
        attachment = {'type': 'file', 'payload': {'token': 'same', 'url': 'https://example.org/old'}}
        for status in (403, 404):
            calls = []
            @asynccontextmanager
            async def get(url, **kwargs):
                calls.append(url)
                async def chunks(size):
                    yield b'original'
                yield NS(status=status if len(calls) == 1 else 200, headers={},
                         raise_for_status=lambda: None, content=NS(iter_chunked=chunks))
            self.bridge.http = NS(get=get)
            self.bridge.api = AsyncMock(return_value={'body': {'mid': 'source', 'attachments': [
                {'type': 'file', 'payload': {'token': 'other', 'url': 'https://example.org/wrong'}},
                {'type': 'file', 'payload': {'token': 'same', 'url': 'https://example.org/new'}}]}})
            with patch.object(b, 'public_url', AsyncMock()):
                self.assertEqual(await self.bridge.download_max(attachment, 'source'), b'original')
            self.assertEqual(calls, ['https://example.org/old', 'https://example.org/new'])
        for payload in ({}, {'token': 'missing'}):
            with self.assertRaises(ValueError):
                await self.bridge.refreshed_max_url({'type': 'file', 'payload': payload}, 'source')
        self.bridge.api.return_value = {'body': {'mid': 'wrong', 'attachments': []}}
        with self.assertRaises(ValueError):
            await self.bridge.refreshed_max_url(attachment, 'source')

    async def test_video_original_and_low_resolution_fallback(self):
        attachment = {'type': 'video', 'payload': {'token': 'v'}}
        for resolution in ('mp4_240', 'mp4_144'):
            self.bridge.api = AsyncMock(side_effect=[
                {'body': {'mid': 'source', 'attachments': [attachment]}},
                {'token': 'v', 'urls': {resolution: 'https://example.org/low'}}])
            self.assertEqual(await self.bridge.refreshed_max_url(attachment, 'source'), 'https://example.org/low')
        self.bridge.api = AsyncMock(return_value={'body': {'mid': 'source', 'attachments': [
            {'type': 'video', 'payload': {'token': 'v', 'url': 'https://example.org/original'}}]}})
        self.assertEqual(await self.bridge.refreshed_max_url(attachment, 'source'), 'https://example.org/original')
        self.assertEqual(self.bridge.api.await_count, 1)

    async def test_uncertain_delivery_does_not_notify_owner(self):
        self.s.add('held', 'max', {}, 'uncertain')
        self.s.add('held:notice', 'notice', {'text': 'old uncertain notification'})
        self.bridge.notice = AsyncMock()
        self.bridge.prompt_choices = AsyncMock()
        async def stop(*args):
            self.bridge.stopping = True
        with patch.object(b.asyncio, 'sleep', stop):
            await self.bridge.work()
        self.bridge.notice.assert_not_awaited()

    async def test_explicit_refusal_keeps_actionable_notice(self):
        self.s.add('refused', 'max', {})
        self.bridge.deliver_max = AsyncMock(side_effect=b.MaxError(403, 'forbidden'))
        self.bridge.notice = AsyncMock()
        self.bridge.prompt_choices = AsyncMock()
        async def stop(*args):
            self.bridge.stopping = True
        with patch.object(b.asyncio, 'sleep', stop):
            await self.bridge.work()
        self.bridge.notice.assert_awaited_once()
        self.assertIn('Проверь доступ', self.bridge.notice.call_args.args[1])
        self.assertEqual(self.s.db.execute("SELECT state FROM jobs WHERE k='refused'").fetchone()[0], 'blocked')

    async def test_real_ffmpeg_voice_video_round(self):
        source = str(Path(self.tmp.name) / 'source.mp4')
        proc = await asyncio.create_subprocess_exec('ffmpeg', '-nostdin', '-v', 'error', '-y', '-f', 'lavfi', '-i', 'testsrc=size=160x120:rate=10',
            '-f', 'lavfi', '-i', 'sine=frequency=440', '-t', '0.5', '-c:v', 'libx264', '-pix_fmt', 'yuv420p', '-c:a', 'aac', source)
        self.assertEqual(await proc.wait(), 0)
        for kind, codec in [('voice', 'opus'), ('max_voice', 'aac'), ('video', 'h264'), ('round', 'h264')]:
            converted = await self.bridge.convert(source, kind)
            probe = await self.bridge.probe(converted)
            self.assertTrue(any(s['codec_name'] == codec for s in probe['streams']))
            if kind == 'round':
                video = next(s for s in probe['streams'] if s['codec_type'] == 'video')
                self.assertEqual((video['width'], video['height']), (384, 384))


if __name__ == '__main__':
    unittest.main()
