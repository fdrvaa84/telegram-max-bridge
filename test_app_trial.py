"""Only synthetic provider responses; no Telegram login or form submission."""
import base64
import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import AsyncMock

from aiohttp.test_utils import TestClient, TestServer
from app_trial import Trial, SafeError, inspect_app, make_app

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
        with self.assertRaisesRegex(SafeError, 'неверен'):
            await self.t.action('bridge_password', 'PRIVATE PASSWORD')
        self.assertEqual(list(self.root.iterdir()), [])

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
        self.assertNotIn('PRIVATE SECRET', await r.text())
        r = await client.get('/status', headers=auth)
        self.assertNotIn(self.t.phone, await r.text())


if __name__ == '__main__':
    unittest.main()
