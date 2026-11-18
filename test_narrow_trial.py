import json
from datetime import datetime, timezone
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock

from bridge import Store
from narrow_trial import TrialBridge, allowed_reply, write_status


class NarrowTrialTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.tmp.name))
        self.config = {'max_chat_id': 10, 'max_owner_id': 20, 'max_bot_id': 30,
                       'allowed_peers': [40], 'activated': 1000}
        self.store.complete_copy('source', 'copy', {'chat': 40, 'message': 50,
            'topic': 60, 'classification': 'personal', 'bot_id': 30})

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def message(self):
        return {'timestamp': 1001000, 'sender': {'user_id': 20, 'is_bot': False},
                'recipient': {'chat_id': 10, 'chat_type': 'dialog'},
                'link': {'type': 'reply', 'message': {'mid': 'copy'}},
                'body': {'mid': 'reply', 'text': 'hello'}}

    async def test_only_exact_owner_fresh_known_mapping_preserves_topic(self):
        result = allowed_reply(self.message(), self.config, self.store, 1000)
        self.assertEqual((result['chat'], result['message'], result['topic']), (40, 50, 60))
        for change in ('wrong_chat', 'old', 'unknown', 'bot', 'wrong_owner', 'unapproved_source'):
            message = self.message()
            config = dict(self.config)
            if change == 'wrong_chat': message['recipient']['chat_id'] = 99
            if change == 'old': message['timestamp'] = 999000
            if change == 'unknown': message['link']['message']['mid'] = 'unrelated'
            if change == 'bot': message['sender']['is_bot'] = True
            if change == 'wrong_owner': message['sender']['user_id'] = 99
            if change == 'unapproved_source': config['allowed_peers'] = [99]
            self.assertIsNone(allowed_reply(message, config, self.store, 1000), change)

    async def test_production_control_routes_and_other_destinations_denied(self):
        bridge = TrialBridge(self.config, self.store)
        for method, route in [('POST', '/subscriptions'), ('DELETE', '/subscriptions'),
                              ('POST', '/messages?user_id=99'), ('GET', '/updates')]:
            # GET updates must also be prohibited: no competing consumer.
            with self.assertRaises(ValueError):
                await bridge.api(method, route)

    async def test_old_or_unapproved_telegram_never_read(self):
        bridge = TrialBridge(self.config, self.store, AsyncMock())
        for chat, timestamp in [(99, 1001), (40, 999)]:
            message = SimpleNamespace(chat_id=chat, date=datetime.fromtimestamp(timestamp, timezone.utc))
            await bridge.capture(message, None)
        self.assertEqual(self.store.db.execute('SELECT count(*) FROM jobs').fetchone()[0], 0)
        bridge.tg.get_messages.assert_not_called()

    async def test_ambiguous_sends_survive_restart_without_resend(self):
        self.store.add('ambiguous', 'max-part', {}, 'sending')
        self.store.close()
        self.store = Store(Path(self.tmp.name))
        self.assertEqual(self.store.db.execute("SELECT state FROM jobs WHERE k='ambiguous'").fetchone()[0], 'uncertain')

    async def test_status_replaces_existing_file(self):
        path = Path(self.tmp.name) / 'status.json'
        write_status(path, {'active': True})
        write_status(path, {'active': False})
        self.assertFalse(json.loads(path.read_text())['active'])


if __name__ == '__main__':
    unittest.main()
