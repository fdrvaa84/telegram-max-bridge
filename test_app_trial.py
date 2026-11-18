"""Only synthetic provider responses; no Telegram login or form submission."""
import base64
import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import AsyncMock, Mock

from aiohttp.test_utils import TestClient, TestServer
from app_trial import Trial, SafeError, inspect_app, make_app, HTML

KEY = 'a' * 32
EXISTING = f'<title>App configuration</title><form id="app_edit_form">App api_id: 12345 App api_hash: {KEY}</form>'
MASKED = f'<title>App configuration</title><form id="app_edit_form">App api_id<button data-copy="12345"></button>App api_hash<button data-value="{KEY}"></button></form>'
CREATE = '<form id="app_create_form" action="/apps/create"><input name="hash" value="abc123"><input name="app_title"><input name="app_shortname"></form>'


class TrialTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.t = Trial(self.root)
        self.t.phone = '+19995550123'
        self.t.http = AsyncMock()

    async def asyncTearDown(self):
        await self.t.close()
        self.tmp.cleanup()

    async def test_private_bounded_diagnostics_and_nonfatal_write(self):
        for _ in range(250):
            self.t.record_failure('password_failure', ConnectionError('SECRET password cookie token'))
        path = self.root / 'failure-journal.jsonl'
        self.assertLess(path.stat().st_size, 25000)
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        rows = [json.loads(line) for line in path.read_text().splitlines()]
        self.assertEqual(rows[-1]['exception_class'], 'ConnectionError')
        self.assertTrue(rows[-1]['utc'].endswith('+00:00'))
        self.assertNotIn('SECRET', path.read_text())
        self.t.root = self.root / 'missing'
        self.t.record_failure('action_failure', RuntimeError('SECRET'))
        self.t.root = self.root

    async def test_existing_and_masked_are_read_without_create(self):
        for page in (EXISTING, MASKED):
            self.assertEqual(inspect_app(page)[0], 'existing')
        self.t.call = AsyncMock(return_value=MASKED)
        await self.t.obtain()
        self.assertEqual(self.t.call.call_args_list[0].args, ('/apps',))
        self.assertEqual(self.t.call.await_count, 1)
        self.assertFalse(self.t.created)
        self.assertFalse((self.root / 'creation-attempt.json').exists())
        restarted = Trial(self.root)
        self.assertEqual(restarted.phone, self.t.phone)
        self.assertEqual(restarted.phase, 'bridge_phone')
        with self.assertRaises(SafeError):
            await restarted.action('bridge_phone', '+19995550456')
        self.assertEqual((self.root / 'application.json').stat().st_mode & 0o777, 0o600)

    async def test_new_app_verified_and_saved(self):
        self.t.call = AsyncMock(side_effect=[CREATE, '', EXISTING])
        await self.t.obtain()
        self.assertTrue(self.t.created)
        proof = json.loads((self.root / 'preconfirmation-proof.json').read_text())
        self.assertEqual(proof['application_result'], 'created_new')
        self.assertFalse(proof['personal_login'])
        self.assertEqual(self.t.call.await_args_list[1].args[0], '/apps/create')
        self.assertEqual(json.loads((self.root / 'application.json').read_text())['api_hash'], KEY)

    async def test_refusal_never_retries_creation_even_after_restart(self):
        self.t.phase = 'read_app'
        self.t.call = AsyncMock(side_effect=[CREATE, '{"text":"ERROR SECRET"}'])
        with self.assertRaisesRegex(SafeError, 'отказал'):
            await self.t.obtain()
        restarted = Trial(self.root)
        restarted.call = AsyncMock(return_value=CREATE)
        with self.assertRaisesRegex(SafeError, 'Ранее'):
            await restarted.obtain()
        self.assertEqual(restarted.call.await_count, 1)
        self.assertFalse((self.root / 'application.json').exists())

    async def test_unknown_partial_or_error_page_is_not_absence(self):
        for page in ('ERROR SECRET', '<title>Sign in</title>', '<form id="app_edit_form">api_id 123</form>',
                     '<input name="hash" value="abc123">', '<script>'+EXISTING+'</script>'):
            self.t.call = AsyncMock(return_value=page)
            with self.assertRaises(SafeError):
                await self.t.obtain()
            self.assertEqual(self.t.call.await_count, 1)
            self.assertFalse((self.root / 'creation-attempt.json').exists())

    async def test_ambiguous_creation_only_reads_on_next_attempt(self):
        self.t.call = AsyncMock(side_effect=[CREATE, TimeoutError('secret')])
        with self.assertRaises(TimeoutError):
            await self.t.obtain()
        self.t.call = AsyncMock(return_value=EXISTING)
        await self.t.obtain()
        self.assertEqual(self.t.call.await_count, 1)
        self.assertFalse(self.t.created)  # No claim of creation after ambiguous result.

    async def test_wrong_and_expired_site_code_never_reads_apps(self):
        self.t.phase = 'site_code'
        self.t.random_hash = 'PRIVATE'
        self.t.deadline = time.monotonic() + 60
        self.t.call = AsyncMock(return_value='invalid secret')
        with self.assertRaisesRegex(SafeError, 'Код неверен'):
            await self.t.action('site_code', 'SECRET CODE')
        self.assertEqual(self.t.phase, 'site_code')
        self.assertEqual(self.t.call.await_count, 1)
        self.t.deadline = 0
        self.t.call.reset_mock()
        with self.assertRaisesRegex(SafeError, 'истекло'):
            await self.t.action('site_code', 'SECRET CODE')
        self.t.call.assert_not_called()
        self.assertIsNone(self.t.random_hash)
        self.assertEqual(list(self.root.iterdir()), [])

    async def test_explicit_consent_and_no_automatic_requests(self):
        self.t.call = AsyncMock()
        with self.assertRaises(SafeError):
            await self.t.action('site_phone', self.t.phone, False)
        self.t.call.assert_not_called()
        self.t.call.return_value = '{"random_hash":"PRIVATE"}'
        await self.t.action('site_phone', self.t.phone, True)
        self.assertEqual(self.t.phase, 'site_code')
        self.assertEqual(list(self.root.iterdir()), [])

    async def test_bridge_codes_and_password_are_not_saved(self):
        from telethon import errors
        self.t.phase = 'bridge_code'
        self.t.deadline = time.monotonic() + 60
        self.t.client = AsyncMock()
        self.t.client.is_connected = Mock(return_value=True)
        self.t.client.sign_in.side_effect = errors.PhoneCodeInvalidError(None)
        with self.assertRaisesRegex(SafeError, 'неверен'):
            await self.t.action('bridge_code', 'PRIVATE CODE')
        self.t.client.sign_in.side_effect = errors.PhoneCodeExpiredError(None)
        with self.assertRaisesRegex(SafeError, 'истёк'):
            await self.t.action('bridge_code', 'PRIVATE CODE')
        self.assertEqual(self.t.phase, 'bridge_phone')
        self.t.phase = 'bridge_code'
        self.t.client.sign_in.side_effect = errors.SessionPasswordNeededError(None)
        await self.t.action('bridge_code', 'PRIVATE CODE')
        self.assertEqual(self.t.phase, 'bridge_password')
        self.t.client.sign_in.side_effect = errors.PasswordHashInvalidError(None)
        with self.assertRaisesRegex(SafeError, 'не принял'):
            await self.t.action('bridge_password', 'PRIVATE PASSWORD')
        journal = (self.root / 'failure-journal.jsonl').read_text()
        self.assertIn('PasswordHashInvalidError', journal)
        self.assertNotIn('PRIVATE', journal)

    async def test_password_transport_failure_does_not_retry_or_change_phase(self):
        self.t.phase = 'bridge_password'
        self.t.client = AsyncMock()
        self.t.client.is_connected = Mock(return_value=True)
        self.t.client.sign_in.side_effect = ConnectionError('PRIVATE SECRET')
        with self.assertRaisesRegex(SafeError, 'Результат неизвестен'):
            await self.t.action('bridge_password', 'SYNTHETIC')
        self.t.client.sign_in.assert_awaited_once_with(password='SYNTHETIC')
        self.assertEqual(self.t.phase, 'bridge_password')
        self.assertFalse(self.t.password_pending)

    async def test_password_provider_errors_are_specific_and_never_retried(self):
        from telethon import errors
        self.t.phase = 'bridge_password'
        self.t.client = AsyncMock()
        self.t.client.is_connected = Mock(return_value=True)
        for error, message in (
                (errors.AuthKeyUnregisteredError(None), 'не означает'),
                (errors.FloodWaitError(None, capture=42), '42 сек.'),
                (errors.PasswordHashInvalidError(None), 'не принял')):
            self.t.client.sign_in.reset_mock()
            self.t.client.sign_in.side_effect = error
            with self.assertRaisesRegex(SafeError, message):
                await self.t.action('bridge_password', 'SYNTHETIC')
            self.t.client.sign_in.assert_awaited_once()
            self.assertEqual(self.t.phase, 'bridge_password')
            self.assertFalse(self.t.password_pending)

    async def test_disconnected_password_is_not_sent(self):
        self.t.phase = 'bridge_password'
        self.t.client = AsyncMock()
        self.t.client.is_connected = Mock(return_value=False)
        with self.assertRaisesRegex(SafeError, 'Пароль не отправлен'):
            await self.t.action('bridge_password', 'SYNTHETIC')
        self.t.client.sign_in.assert_not_called()
        self.t.client.connect.assert_not_called()

    async def test_concurrent_password_is_rejected_without_second_attempt(self):
        import asyncio
        started, release = asyncio.Event(), asyncio.Event()
        self.t.phase = 'bridge_password'
        self.t.client = AsyncMock()
        self.t.client.is_connected = Mock(return_value=True)
        async def pending(**kwargs):
            started.set()
            await release.wait()
            raise ConnectionError('PRIVATE')
        self.t.client.sign_in.side_effect = pending
        task = asyncio.create_task(self.t.action('bridge_password', 'SYNTHETIC'))
        await started.wait()
        try:
            with self.assertRaisesRegex(SafeError, 'уже проверяется'):
                await self.t.action('bridge_password', 'SYNTHETIC')
        finally:
            release.set()
        with self.assertRaises(SafeError):
            await task
        self.assertEqual(self.t.client.sign_in.await_count, 1)

    async def test_bridge_reuses_owner_phone_only_after_confirmation(self):
        self.t.phase = 'bridge_phone'
        self.t.keys = {'owner_phone': self.t.phone}
        self.t.client = AsyncMock()
        self.t.client.is_connected = Mock(return_value=True)
        self.t.client.is_user_authorized.return_value = False
        with self.assertRaises(SafeError):
            await self.t.action('bridge_phone', '')
        self.t.client.send_code_request.assert_not_called()
        await self.t.action('bridge_phone', '+19995550456', True)
        self.t.client.send_code_request.assert_awaited_once_with(self.t.keys['owner_phone'])
        self.assertEqual(self.t.phase, 'bridge_code')

    async def test_login_waits_for_operator_without_browser_secret_action(self):
        from types import SimpleNamespace
        self.t.call = AsyncMock(return_value=EXISTING)
        await self.t.obtain()
        self.t.client = AsyncMock()
        self.t.client.is_connected = Mock(return_value=True)
        self.t.client.get_me.return_value = SimpleNamespace(phone=self.t.phone[1:])
        await self.t.finish()
        self.assertEqual(self.t.phase, 'max_pending')
        self.assertEqual(self.t.message, 'Telegram подключён. Помощник готовит подключение MAX.')
        proof = json.loads((self.root / 'preconfirmation-proof.json').read_text())
        self.assertEqual(proof['application_result'], 'read_existing')
        self.assertTrue(proof['personal_login'])
        self.assertNotIn(self.t.phone, json.dumps(proof))
        self.assertNotIn(KEY, json.dumps(proof))
        self.assertEqual(Trial(self.root).phase, 'max_pending')
        self.t.check_max = AsyncMock()
        with self.assertRaises(SafeError):
            await self.t.action('max_token', 'PRIVATE TOKEN')
        self.t.check_max.assert_not_called()
        self.assertNotIn('max_token', HTML)
        self.assertIn("input.hidden=['read_app','bridge_phone'].includes(phase)", HTML)
        self.assertIn('Подтвердить вход пересылки', HTML)
        self.assertIn("'bridge_phone','bridge_qr'].includes(phase)", HTML)
        self.assertIn("qrStart').hidden=!['bridge_phone','bridge_code'].includes(phase)", HTML)

    async def test_browser_security_and_safe_errors(self):
        app = make_app(self.t, 'private-password', 18789)
        client = TestClient(TestServer(app))
        await client.start_server()
        self.addAsyncCleanup(client.close)
        host = {'Host': '127.0.0.1:18789'}
        r = await client.get('/', headers=host)
        self.assertEqual(r.status, 401)
        auth = {**host, 'Authorization': 'Basic '+base64.b64encode(b'owner:private-password').decode()}
        r = await client.get('/', headers=auth)
        html = await r.text()
        csrf = html.split("const csrf='")[1].split("'")[0]
        self.assertEqual(r.headers['Cache-Control'], 'no-store')
        self.assertEqual(r.headers['X-Frame-Options'], 'DENY')
        for headers in (auth, {**auth,'Origin':'http://evil.test','X-CSRF':csrf}):
            r = await client.post('/action', headers=headers, json={'action':'site_phone','value':self.t.phone,'consent':True})
            self.assertEqual(r.status, 403)
        r = await client.get('/?secret=no', headers=auth)
        self.assertEqual(r.status, 403)
        r = await client.get('/', headers={**auth,'Host':'evil.test'})
        self.assertEqual(r.status, 403)
        self.t.action = AsyncMock(side_effect=RuntimeError('PRIVATE SECRET'))
        r = await client.post('/action', headers={**auth,'Origin':'http://127.0.0.1:18789','X-CSRF':csrf}, json={'action':'site_phone','value':'PRIVATE SECRET'})
        self.assertEqual(r.status, 400)
        self.assertNotIn('PRIVATE SECRET', await r.text())
        journal = self.root / 'failure-journal.jsonl'
        row = json.loads(journal.read_text().splitlines()[-1])
        self.assertEqual(row['exception_class'], 'RuntimeError')
        self.assertEqual(row['kind'], 'action_failure')
        self.assertNotIn('PRIVATE', journal.read_text())
        self.assertNotIn(self.t.phone, journal.read_text())
        self.t.qr_png = b'synthetic'
        self.t.qr_expires = 'PRIVATE SECRET'
        failed_read = await client.get('/status', headers=auth)
        self.assertEqual(failed_read.status, 400)
        row = json.loads(journal.read_text().splitlines()[-1])
        self.assertEqual(row['kind'], 'read_failure')
        self.assertEqual(row['exception_class'], 'TypeError')
        self.assertNotIn('PRIVATE', journal.read_text())
        self.t.qr_png = None
        r = await client.get('/status', headers=auth)
        self.assertNotIn(self.t.phone, await r.text())

class QRTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        from types import SimpleNamespace
        self.tmp = tempfile.TemporaryDirectory()
        self.t = Trial(Path(self.tmp.name))
        self.t.keys = {'owner_phone': '+19995550123', 'api_id': 12345, 'api_hash': KEY}
        self.t.phone = self.t.keys['owner_phone']
        self.t.client = AsyncMock()
        self.t.client.is_connected = Mock(return_value=True)
        self.t.client.get_me.return_value = SimpleNamespace(phone='19995550123')
        self.t.qr_new = True
        self.t.phase = 'bridge_qr'

    async def asyncTearDown(self):
        await self.t.close()
        self.tmp.cleanup()

    def qr(self, wait):
        from types import SimpleNamespace
        from datetime import datetime, timezone, timedelta
        return SimpleNamespace(url='tg://login?token=SYNTHETIC',
            expires=datetime.now(timezone.utc)+timedelta(seconds=30), wait=wait)

    async def test_correct_owner(self):
        client = self.t.client
        client.qr_login.return_value = self.qr(AsyncMock())
        await self.t.run_qr()
        self.assertEqual(self.t.phase, 'max_pending')
        self.assertTrue(self.t.proof['personal_login'])
        client.log_out.assert_not_called()
        self.assertIsNone(self.t.qr_png)

    async def test_password_then_owner(self):
        from telethon import errors
        self.t.client.qr_login.return_value = self.qr(AsyncMock(side_effect=errors.SessionPasswordNeededError(None)))
        await self.t.run_qr()
        self.assertEqual(self.t.phase, 'bridge_password')
        self.assertIsNone(self.t.qr_png)
        self.t.client.disconnect.assert_not_called()
        await self.t.action('bridge_password', 'SYNTHETIC')
        self.assertTrue(self.t.proof['personal_login'])

    async def test_other_owner_logs_out_only_trial(self):
        from types import SimpleNamespace
        client = self.t.client
        client.get_me.return_value = SimpleNamespace(phone='19995550999')
        client.log_out.return_value = True
        client.qr_login.return_value = self.qr(AsyncMock())
        await self.t.run_qr()
        self.assertEqual(self.t.phase, 'bridge_phone')
        client.log_out.assert_awaited_once()
        self.assertNotIn('personal_login', self.t.proof)
        client.get_dialogs.assert_not_called()
        client.get_messages.assert_not_called()

    async def test_expired_qr_refreshes_then_network_error_stops(self):
        client = self.t.client
        client.qr_login.side_effect = [self.qr(AsyncMock(side_effect=TimeoutError())), OSError('PRIVATE')]
        await self.t.run_qr()
        self.assertEqual(client.qr_login.await_count, 2)
        self.assertEqual(self.t.phase, 'bridge_phone')
        self.assertIsNone(self.t.qr_png)
        self.assertNotIn('PRIVATE', self.t.message)
        self.assertNotIn('personal_login', self.t.proof)
        client.send_code_request.assert_not_called()

    async def test_cancel_waiter_before_switch(self):
        import asyncio
        started, stopped = asyncio.Event(), asyncio.Event()
        async def wait():
            started.set()
            try:
                await asyncio.Event().wait()
            finally:
                stopped.set()
        self.t.client.qr_login.return_value = self.qr(wait)
        self.t.client.is_user_authorized.return_value = False
        self.t.qr_task = asyncio.create_task(self.t.run_qr())
        await started.wait()
        await self.t.action('stop_qr', '')
        self.assertTrue(stopped.is_set())
        self.assertIsNone(self.t.qr_task)
        self.assertIsNone(self.t.client)
        self.assertIsNone(self.t.qr_png)
        self.assertEqual(self.t.phase, 'bridge_phone')

    async def test_missing_identity_is_error_not_absence(self):
        self.t.client.get_me.return_value = None
        self.t.client.qr_login.return_value = self.qr(AsyncMock())
        await self.t.run_qr()
        self.assertNotIn('personal_login', self.t.proof)
        self.assertIn('не подтвердил', self.t.message)

    async def test_official_delivery_types(self):
        from telethon.tl import types
        from types import SimpleNamespace
        for typ, phrase in ((types.auth.SentCodeTypeApp(5), 'сообщении Telegram'),
                            (types.auth.SentCodeTypeSms(5), 'СМС'),
                            (types.auth.SentCodeTypeCall(5), 'голосовым звонком'),
                            (types.auth.SentCodeTypeEmailCode('s***', 5), 'электронную почту')):
            message = Trial.describe_delivery(SimpleNamespace(type=typ, next_type=types.auth.CodeTypeSms(), timeout=60))
            self.assertIn(phrase, message)
            self.assertIn('60 сек.', message)
            self.assertIn('Следующий', message)
            self.assertNotIn('s***', message)

    async def test_image_route_protected_and_no_query(self):
        self.t.qr_png = b'\x89PNG\r\n\x1a\nSYNTHETIC'
        self.t.qr_expires = time.time()+30
        client = TestClient(TestServer(make_app(self.t, 'private-password', 18789)))
        await client.start_server()
        self.addAsyncCleanup(client.close)
        host = {'Host': '127.0.0.1:18789'}
        self.assertEqual((await client.get('/qr.png', headers=host)).status, 401)
        auth = {**host, 'Authorization': 'Basic '+base64.b64encode(b'owner:private-password').decode()}
        response = await client.get('/qr.png', headers=auth)
        self.assertEqual(response.status, 200)
        self.assertEqual(response.headers['Cache-Control'], 'no-store')
        self.assertEqual(response.content_type, 'image/png')
        self.assertEqual((await client.get('/qr.png?token=NO', headers=auth)).status, 403)
        self.t.qr_expires = 0
        self.assertEqual((await client.get('/qr.png', headers=auth)).status, 404)
        response = await client.get('/status', headers=auth)
        self.assertNotIn('SYNTHETIC', await response.text())

    async def test_qr_starts_only_after_button_and_keeps_application(self):
        import asyncio
        from unittest.mock import patch
        client = self.t.client
        self.t.client = None
        self.t.phase = 'bridge_phone'
        client.is_user_authorized.return_value = False
        client.qr_login.return_value = self.qr(lambda: asyncio.Event().wait())
        with patch('app_trial.LoginOnlyClient', return_value=client) as factory:
            await self.t.action('bridge_qr', '')
            await asyncio.sleep(0)
            self.assertEqual(self.t.phase, 'bridge_qr')
            self.assertTrue(factory.call_args.kwargs['receive_updates'])
            client.send_code_request.assert_not_called()
            self.assertIsNotNone(self.t.qr_task)
            await self.t.action('stop_qr', '')
        self.assertEqual(self.t.keys['owner_phone'], '+19995550123')

    async def test_total_wait_expires_without_code_requests(self):
        from unittest.mock import patch
        client = self.t.client
        with patch('app_trial.time.monotonic', side_effect=[0, 301]):
            await self.t.run_qr()
        self.assertEqual(self.t.phase, 'bridge_phone')
        self.assertIn('истекло', self.t.message)
        client.qr_login.assert_not_called()
        client.send_code_request.assert_not_called()

    async def test_login_callback_does_not_read_updates(self):
        from app_trial import LoginOnlyClient
        from types import SimpleNamespace
        fake = SimpleNamespace(_mb_entity_cache=Mock())
        user = SimpleNamespace(id=123, bot=False, access_hash=456)
        await LoginOnlyClient._on_login(fake, user)
        self.assertTrue(fake._authorized)


if __name__ == '__main__':
    unittest.main()
