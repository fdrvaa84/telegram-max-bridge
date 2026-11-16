"""Optional two independent S3-compatible copies; local bytes are never deleted."""
import asyncio
import hashlib
import json
import logging
from pathlib import Path
import time


def upload_verified(target, key, path, meta):
    import boto3
    from botocore.config import Config
    client = boto3.client('s3', endpoint_url=target['endpoint'],
        aws_access_key_id=target['access_key'], aws_secret_access_key=target['secret_key'],
        region_name=target.get('region') or 'us-east-1',
        config=Config(connect_timeout=15, read_timeout=60, retries={'max_attempts': 1},
                      s3={'addressing_style': 'path'}))
    data = Path(path).read_bytes()
    if len(data) != meta['size'] or hashlib.sha256(data).hexdigest() != meta['sha256']:
        raise ValueError('local_integrity_failed')
    client.put_object(Bucket=target['bucket'], Key=key, Body=data,
                      Metadata={'sha256': meta['sha256']})
    # Read bytes back, not just caller-supplied metadata or multipart ETag.
    result = client.get_object(Bucket=target['bucket'], Key=key)
    digest, size = hashlib.sha256(), 0
    with result['Body'] as body:
        for chunk in iter(lambda: body.read(262144), b''):
            size += len(chunk)
            digest.update(chunk)
    if size != meta['size'] or digest.hexdigest() != meta['sha256']:
        raise ValueError('remote_integrity_failed')
    metadata = json.dumps(meta, ensure_ascii=False).encode()
    client.put_object(Bucket=target['bucket'], Key=key + '.json', Body=metadata)
    result = client.get_object(Bucket=target['bucket'], Key=key + '.json')
    with result['Body'] as body:
        if body.read() != metadata:
            raise ValueError('remote_metadata_failed')


async def copy_pass(config, store, uploader=upload_verified):
    targets = config.get('cloud_copies') or []
    if not targets:
        return
    if len(targets) != 2 or targets[0]['endpoint'] == targets[1]['endpoint']:
        raise ValueError('two_independent_clouds_required')
    store.db.execute('''CREATE TABLE IF NOT EXISTS cloud_copies(
        path TEXT,target TEXT,state TEXT,retry_at REAL NOT NULL DEFAULT 0,
        PRIMARY KEY(path,target))''')
    # Rediscover originals after crashes, including a crash before queue insertion.
    for path in (store.root / 'originals').glob('*/*.json'):
        original = path.with_suffix('')
        if not original.is_file():
            continue
        for target in targets:
            identity = hashlib.sha256((target['endpoint'] + '/' + target['bucket']).encode()).hexdigest()
            store.db.execute('INSERT OR IGNORE INTO cloud_copies(path,target,state) VALUES (?,?,?)',
                             (str(original), identity, 'pending'))
    store.db.commit()
    # Separate tasks: one unavailable provider cannot hold up the other.
    async def process(target):
        identity = hashlib.sha256((target['endpoint'] + '/' + target['bucket']).encode()).hexdigest()
        rows = store.db.execute("SELECT path FROM cloud_copies WHERE target=? AND state='pending' AND retry_at<=? LIMIT 10",
                                (identity, time.time())).fetchall()
        for row in rows:
            path = Path(row['path'])
            try:
                meta = json.loads(path.with_suffix('.json').read_text())
                key = 'telemax/' + '/'.join(path.parts[-2:])
                await asyncio.to_thread(uploader, target, key, path, meta)
                with store.db:
                    store.db.execute("UPDATE cloud_copies SET state='verified' WHERE path=? AND target=?",
                                     (str(path), identity))
            except Exception:
                with store.db:
                    store.db.execute('UPDATE cloud_copies SET retry_at=? WHERE path=? AND target=?',
                                     (time.time()+300, str(path), identity))
                logging.warning('cloud_copy_pending')
    await asyncio.gather(*(process(target) for target in targets))


async def copy_loop(config, store):
    while True:
        try:
            await copy_pass(config, store)
        except Exception:
            logging.warning('cloud_copy_pending')
        await asyncio.sleep(60)
