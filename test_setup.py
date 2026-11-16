"""Synthetic setup, public endpoint, persistence, and optional archive checks."""
import asyncio
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import AsyncMock, patch
from aiohttp import web, ClientSession
from aiohttp.test_utils import TestClient, TestServer
import bridge
import manage
from cloud_copies import copy_pass, upload_verified


class SetupTests(unittest.IsolatedAsyncioTestCase):
    async def test_pairing_requires_secret_nonce_and_private_owner_confirmation(self):
        config = {'webhook_secret': 'synthetic-secret', 'max_bot_id': 456}
        pair = manage.Pairing(config, 'synthetic-nonce')
        app = web.Application()
        app.router.add_post('/webhook', pair.accept)
        event = {'update_type':'message_created', 'message':{
            'sender': {'user_id':123}, 'recipient':{'chat_type':'dialog','user_id':456},
            'body':{'text':'/bind synthetic-nonce'}}}
        async with TestClient(TestServer(app)) as client:
            response = await client.post('/webhook', json=event)
            self.assertEqual(response.status, 403)
            headers = {'X-Max-Bot-Api-Secret':'synthetic-secret'}
            event['message']['body']['text'] = '/bind wrong'
            await client.post('/webhook', json=event, headers=headers)
            self.assertIsNone(pair.owner)
            event['message']['body']['text'] = '/bind synthetic-nonce'
            event['message']['recipient']['chat_type'] = 'chat'
            await client.post('/webhook', json=event, headers=headers)
            self.assertIsNone(pair.owner)
            event['message']['recipient']['chat_type'] = 'dialog'
            event['message']['sender']['is_bot'] = True
            await client.post('/webhook', json=event, headers=headers)
            self.assertIsNone(pair.owner)
            event['message']['sender']['is_bot'] = False
            await client.post('/webhook', json=event, headers=headers)
            self.assertEqual(pair.owner,123)
            event['message']['sender']['user_id'] = 999
            await client.post('/webhook', json=event, headers=headers)
            self.assertEqual(pair.owner,123)
        self.assertNotIn('max_owner_id',config) # Terminal confirmation must still save it.
        expired = manage.Pairing(config, 'synthetic-nonce')
        expired.expires = 0
        self.assertIsNone(expired.owner)

    async def test_subscribe_is_verified_and_never_replaces_another_bots_endpoint(self):
        b = bridge.Bridge({'domain':'example.org','webhook_secret':'synthetic'}, None)
        b.api = AsyncMock(side_effect=[{'subscriptions':[]}, {'success':True},
                                      {'subscriptions':[{'url':'https://example.org/webhook'}]}])
        await manage.subscribe(b)
        self.assertEqual(b.api.await_count,3)
        self.assertEqual(b.api.call_args_list[1].args[2]['secret'],'synthetic')
        b.api = AsyncMock(return_value={'subscriptions':[{'url':'https://other.example.org/webhook'}]})
        with self.assertRaises(ValueError): await manage.subscribe(b)
        b.api.assert_awaited_once()

    async def test_subscribe_waits_for_receiver_readiness(self):
        calls=0
        async def health(request):
            nonlocal calls
            calls+=1
            return web.json_response({'ready': calls>=2},status=200 if calls>=2 else 503)
        app=web.Application();app.router.add_get('/health',health)
        async with TestServer(app) as server:
            with patch.object(manage.asyncio,'sleep',AsyncMock()):
                await manage.wait_local_ready({'port':server.port})
        self.assertEqual(calls,2)

    async def test_two_clouds_independent_and_durable_after_restart(self):
        with tempfile.TemporaryDirectory() as root:
            store = bridge.Store(root)
            b = bridge.Bridge({},store)
            path = b.save_original('synthetic',0,b'original','document.pdf',{'chat':20,'message':1,'classification':'personal'})
            config = {'cloud_copies':[{'endpoint':'https://one.example.org','bucket':'one'},
                                     {'endpoint':'https://two.example.org','bucket':'two'}]}
            calls=[]
            def upload(target,key,source,meta):
                calls.append(target['bucket'])
                self.assertEqual(hashlib.sha256(Path(source).read_bytes()).hexdigest(),meta['sha256'])
                if target['bucket']=='one': raise OSError('synthetic failure')
            await copy_pass(config,store,upload)
            self.assertCountEqual(calls,['one','two'])
            self.assertEqual(dict(store.db.execute('SELECT state,count(*) FROM cloud_copies GROUP BY state')),{'pending':1,'verified':1})
            store.db.close(); store.lock.close()
            store=bridge.Store(root)
            store.db.execute('UPDATE cloud_copies SET retry_at=0'); store.db.commit()
            calls.clear()
            await copy_pass(config,store,lambda target,*args:calls.append(target['bucket']))
            self.assertEqual(calls,['one'])
            self.assertEqual(store.db.execute("SELECT count(*) FROM cloud_copies WHERE state='verified'").fetchone()[0],2)
            self.assertEqual(Path(path).read_bytes(),b'original')
            store.db.close(); store.lock.close()

    async def test_telegram_ambiguous_send_stops_instead_of_repeating(self):
        from types import SimpleNamespace as NS
        with tempfile.TemporaryDirectory() as root:
            s=bridge.Store(root)
            tg=AsyncMock(side_effect=TimeoutError('synthetic'))
            tg.get_input_entity.return_value='peer'
            tg.get_messages.return_value=NS(noforwards=False,media=None,ttl_period=None)
            tg.get_entity.return_value=NS(noforwards=False)
            b=bridge.Bridge({'max_bot_id':456},s,tg)
            p={'chat':20,'message':1,'topic':7,'attachments':[],'text':'synthetic','random_ids':[1]}
            s.add('reply','telegram',p)
            with self.assertRaises(TimeoutError): await b.deliver_telegram('reply',p)
            self.assertEqual(s.db.execute("SELECT state FROM jobs WHERE k='reply'").fetchone()[0],'uncertain')
            s.db.close();s.lock.close()
            s=bridge.Store(root)
            self.assertEqual(s.db.execute("SELECT state FROM jobs WHERE k='reply'").fetchone()[0],'uncertain')
            s.db.close();s.lock.close()

    async def test_login_qr_second_password_and_persistent_session(self):
        from types import SimpleNamespace as NS
        with tempfile.TemporaryDirectory() as root:
            path=Path(root)/'config.json'
            bridge.atomic(path,json.dumps({'api_id':123,'api_hash':'a'*32,'enabled':False,
                'max_owner_id':123,'max_bot_id':456,'state_dir':root+'/state'}).encode())
            client=AsyncMock()
            client.is_user_authorized.return_value=False
            client.get_me.return_value=NS(id=789,bot=False,first_name='Synthetic',phone='synthetic')
            qr=NS(url='tg://synthetic',wait=AsyncMock(side_effect=bridge.errors.SessionPasswordNeededError(None)))
            client.qr_login.return_value=qr
            with patch.object(bridge,'HistoryClient',return_value=client) as constructor, \
                    patch.object(bridge.os,'isatty',return_value=True), \
                    patch('qrcode.QRCode.print_ascii'), \
                    patch('getpass.getpass',return_value='synthetic-password') as password, \
                    patch('builtins.input',return_value='ПОДТВЕРЖДАЮ'):
                await bridge.main(NS(config=str(path),check=False,login=True,enable=True))
            self.assertEqual(constructor.call_args.kwargs['flood_sleep_threshold'],0)
            self.assertEqual(constructor.call_args.kwargs['request_retries'],0)
            client.sign_in.assert_awaited_once_with(password='synthetic-password')
            config=bridge.load_config(path)
            self.assertEqual(config['telegram_owner_id'],789)
            self.assertTrue(config['enabled'])
            self.assertNotIn('synthetic-password',path.read_text())
            db=__import__('sqlite3').connect(root+'/state/state.sqlite')
            self.assertIsNotNone(db.execute("SELECT v FROM kv WHERE k='since'").fetchone())
            db.close()

    async def test_regular_entrypoint_runs_http_with_synthetic_bot(self):
        with tempfile.TemporaryDirectory() as root:
            config=Path(root)/'config.json'
            sock=socket.socket();sock.bind(('127.0.0.1',0));port=sock.getsockname()[1];sock.close()
            bridge.atomic(config,json.dumps({'enabled':False,'max_bot_id':456,'max_owner_id':123,
                'state_dir':root+'/state','webhook_secret':'synthetic','local_token':'synthetic','port':port}).encode())
            code='''import asyncio,sys
from argparse import Namespace
from unittest.mock import AsyncMock
import bridge
bridge.Bridge.api=AsyncMock(return_value={'user_id':456})
asyncio.run(bridge.main(Namespace(config=sys.argv[1],check=False,login=False,enable=False)))
'''
            proc=await asyncio.create_subprocess_exec(sys.executable,'-c',code,str(config),
                stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.PIPE)
            try:
                async with ClientSession() as http:
                    for _ in range(100):
                        if proc.returncode is not None: self.fail('Entry point exited before health check')
                        try:
                            async with http.get(f'http://127.0.0.1:{port}/health') as r:
                                self.assertEqual(await r.json(),{'ready':True,'enabled':False})
                                break
                        except OSError: await asyncio.sleep(.05)
                    else: self.fail('No health response')
                    async with http.post(f'http://127.0.0.1:{port}/webhook',json={}) as r:
                        self.assertEqual(r.status,403)
                    async with http.post(f'http://127.0.0.1:{port}/accept',json={}) as r:
                        self.assertEqual(r.status,404)
            finally:
                if proc.returncode is None: proc.terminate()
                out,err=await asyncio.wait_for(proc.communicate(),10)
                self.assertEqual(proc.returncode,0,err.decode())


class LocalSetupTests(unittest.TestCase):
    def test_configure_hidden_secrets_permissions_and_reentry_refusal(self):
        with tempfile.TemporaryDirectory() as root:
            path=Path(root)/'config.json'
            with patch.object(manage,'private_terminal'), patch.object(manage,'hidden',side_effect=['123','a'*32,'synthetic-token']), patch('builtins.input',return_value='example.org'):
                manage.configure(path)
                with self.assertRaises(ValueError): manage.configure(path)
            self.assertEqual(path.stat().st_mode & 0o777,0o600)
            self.assertFalse(bridge.load_config(path)['enabled'])
            result=subprocess.run([sys.executable,'bridge.py','--config',str(path),'--check'],capture_output=True,text=True)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertNotIn('synthetic-token',result.stdout)
            self.assertNotIn('a'*32,result.stdout)
            path.chmod(0o644)
            with self.assertRaises(ValueError): bridge.load_config(path)

    def test_real_private_terminal_configure_does_not_echo_secrets(self):
        import pty, select
        with tempfile.TemporaryDirectory() as root:
            path=Path(root)/'config.json'
            master,slave=pty.openpty()
            proc=subprocess.Popen([sys.executable,'manage.py','--config',str(path),'configure'],
                stdin=slave,stdout=slave,stderr=slave)
            os.close(slave)
            transcript=b''
            prompts=[('api_id с my.telegram.org/apps (ввод скрыт): ',b'123'),
                     ('api_hash (ввод скрыт): ',b'a'*32),
                     ('бота MAX (ввод скрыт): ',b'synthetic-token-private'),
                     ('Ваш домен для MAX: ',b'example.org')]
            try:
                for prompt,value in prompts:
                    deadline=time.monotonic()+10
                    while prompt.encode() not in transcript:
                        if time.monotonic()>deadline: self.fail('Private prompt not reached')
                        if select.select([master],[],[],.1)[0]: transcript+=os.read(master,65536)
                    os.write(master,value+b'\n')
                proc.wait(timeout=10)
                while select.select([master],[],[],.1)[0]:
                    try: transcript+=os.read(master,65536)
                    except OSError: break
                self.assertEqual(proc.returncode,0,transcript.decode())
                self.assertNotIn(b'synthetic-token-private',transcript)
                self.assertNotIn(b'a'*32,transcript)
                self.assertEqual(bridge.load_config(path)['max_bot_token'],'synthetic-token-private')
            finally:
                if proc.poll() is None: proc.kill();proc.wait()
                os.close(master)

    def test_domain_rejects_shell_and_config_injection(self):
        self.assertEqual(manage.domain_name('Bridge.Example.org'),'bridge.example.org')
        for value in ['https://example.org','example.org;id','example.org\n{','127.0.0.1','example.org:443','x..org','-x.org','x.org/path']:
            with self.subTest(value=value), self.assertRaises(ValueError): manage.domain_name(value)

    def test_installer_shell_syntax_and_no_private_paths(self):
        for name in ['install.sh','telemax']:
            self.assertEqual(subprocess.run(['bash','-n',name]).returncode,0)
        for name in ['bridge.py','manage.py','cloud_copies.py','install.sh','telemax']:
            data=Path(name).read_text()
            for forbidden in ['/home/', 'archive_client', 'legacy_bot']:
                self.assertNotIn(forbidden,data)


if __name__=='__main__': unittest.main()
