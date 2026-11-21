"""Run signed Rust, C, C++ and Wasm assembly transactions against a fresh neural-devnet."""

import hashlib
import json
import os
import re
import socket
import subprocess
import tempfile
import time
from contextlib import ExitStack
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import urlopen


ROOT = Path(__file__).resolve().parent.parent
SUFFIX = '.exe' if os.name == 'nt' else ''
TARGET = Path(os.environ.get('CARGO_TARGET_DIR', ROOT / 'target'))
NODE = Path(os.environ.get('HYPHEN_NODE_BIN_DIR', TARGET / 'debug')).resolve() / ('hyphen-node' + SUFFIX)
CLIENT = NODE.with_name('hyphen-contract' + SUFFIX)
BOB = NODE.with_name('bob-miner' + SUFFIX)
POOL = ROOT / 'HyphenPool/target' / NODE.parent.name / ('hyphen-pool-server' + SUFFIX)
MINER = ROOT / 'HyphenMiner/target' / NODE.parent.name / ('hyphen-miner' + SUFFIX)
MARKET = ROOT / 'target/contract-toolchains/limit-orders.wasm'
COLLECTION = MARKET.with_name('collection.wasm')
ADDRESS = 'hy12X1dKMPZ9KRTa4CaZ1MFGHPqCGFnjwVZAPQPKcYq5fpUPkdKn6VVomB1oRK8r7bW8s7uR9iYUQtpSdSfifsCg1P3WKdxD3'


def wait_json(url, processes, *, timeout=180, interval=0.5):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        for process in processes:
            if process.poll() is not None:
                raise RuntimeError(f'{process.args[0]} exited with {process.returncode}')
        try:
            with urlopen(url, timeout=5) as response:
                return json.load(response)
        except HTTPError as error:
            if error.code != 404:
                raise
        except (URLError, TimeoutError, ConnectionResetError):
            pass
        time.sleep(interval)
    raise TimeoutError(url)


def stop(process):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()


def test_limit_orders(work, client, confirmed):
    # Two public Ed25519 test accounts from RFC 8032 section 7.1.
    maker = bytes.fromhex('d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a')
    taker = bytes.fromhex('3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c')
    keys = {}
    for owner, seed in [(maker, '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60'),
                        (taker, '4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb')]:
        keys[owner] = work / f'{owner.hex()}.key'
        keys[owner].write_bytes(bytes.fromhex(seed))

    def u64(n):
        return n.to_bytes(8, 'little')

    data = work / 'market-input.bin'
    supply = u64(1000) + u64(500)
    data.write_bytes(supply)
    address, deploy = confirmed('deploy', MARKET, '--input', data, '--key-file', keys[maker], '--nonce', '0')
    nonces = {maker: 1, taker: 0}
    transactions = [deploy]

    def execute(signer, body, *, rejected=False, function='hyphen_execute'):
        data.write_bytes(body)
        args = ['call', address, function, '--input', data, '--key-file', keys[signer], '--nonce', str(nonces[signer])]
        if rejected:
            try:
                client(*args)
            except subprocess.CalledProcessError as error:
                if 'execution' not in error.output.lower():
                    raise
                return
            raise AssertionError('invalid market operation admitted')
        _, tx = confirmed(*args)
        transactions.append(tx)
        nonces[signer] += 1

    def query(body):
        data.write_bytes(body)
        output = dict(line.split('=', 1) for line in client('query', address, '--input', data).splitlines())
        return bytes.fromhex(output['result'])

    def state():
        return [int.from_bytes(query(bytes([1, asset]) + owner), 'little')
                for owner in (maker, taker) for asset in (0, 1)]

    assert query(b'\0') == supply and state() == [1000, 500, 0, 0]
    execute(maker, supply, rejected=True, function='init')
    terms = b'\0' + u64(100) + u64(25)
    execute(maker, b'\x02' + terms)
    order = query(b'\x02' + maker)
    assert order == u64(1) + terms and state() == [900, 500, 0, 0]
    fill = b'\x03' + maker + order
    execute(taker, fill, rejected=True)
    execute(taker, b'\x04' + u64(1), rejected=True)
    assert query(b'\x02' + maker) == order and state() == [900, 500, 0, 0]
    execute(maker, b'\x01\x01' + taker + u64(40))
    execute(taker, fill)
    assert query(b'\x02' + maker) == b'' and state() == [900, 485, 100, 15]
    execute(maker, b'\x02' + terms)
    execute(taker, fill, rejected=True)
    assert query(b'\x02' + maker) == u64(2) + terms
    execute(maker, b'\x04' + u64(2))

    def verify_settlement():
        assert query(b'\0') == supply and query(b'\x02' + maker) == b''
        assert state() == [900, 485, 100, 15]

    verify_settlement()
    return dict(address=address, transactions=transactions), verify_settlement


def test_collection(work, client, confirmed):
    issuer = bytes.fromhex('d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a')
    delegate = bytes.fromhex('3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c')
    # RFC 8032 public test accounts on a fresh chain.
    keys = [work / 'collection-issuer.key', work / 'collection-delegate.key']
    for path, seed in zip(keys, ['9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60',
                                 '4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb']):
        path.write_bytes(bytes.fromhex(seed))
    data = work / 'collection-input.bin'
    def integer(n):
        return n.to_bytes(8, 'little')
    data.write_bytes(integer(1))
    address, deploy = confirmed('deploy', COLLECTION, '--input', data, '--key-file', keys[0], '--nonce', '0')
    txs, nonces = [deploy], [1, 0]
    def call(signer, body, reject=False):
        data.write_bytes(body)
        args = ['call', address, 'hyphen_execute', '--input', data, '--key-file', keys[signer], '--nonce', str(nonces[signer])]
        if reject:
            try:
                client(*args)
            except subprocess.CalledProcessError as error:
                if 'execution' not in error.output.lower():
                    raise
                return
            raise AssertionError('collection admitted a rejected operation')
        txs.append(confirmed(*args)[1])
        nonces[signer] += 1
    def query(body):
        data.write_bytes(body)
        return bytes.fromhex(dict(line.split('=', 1) for line in client('query', address, '--input', data).splitlines())['result'])
    token = b'\x01' + integer(1)
    metadata = bytes.fromhex('af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262')
    mint = b'\x01' + issuer + metadata
    call(1, mint, reject=True)
    assert query(token) == b''
    call(0, mint)
    call(0, mint, reject=True)
    def change(op, rev, to=b''):
        return bytes([op]) + integer(1) + integer(rev) + to
    call(1, change(2, 0, delegate), reject=True)
    call(0, change(3, 0, delegate))
    call(0, change(3, 1, bytes(32)))
    call(1, change(2, 2, delegate), reject=True)
    call(0, change(3, 2, delegate))
    call(1, change(2, 2, delegate), reject=True)
    call(1, change(2, 3, delegate))
    assert query(token) == delegate + bytes(32) + metadata + integer(4)
    call(0, change(4, 4), reject=True)
    call(1, change(4, 4))
    call(1, change(2, 5, issuer), reject=True)
    def verify():
        assert query(token) == bytes(64) + metadata + integer(5)
        assert query(b'\0') == issuer + integer(1) + integer(1)
    verify()
    return dict(address=address, transactions=txs), verify


def run(collection_only=False):
    if not __debug__:
        raise RuntimeError('Contract acceptance requires Python assertions enabled.')
    work = Path(tempfile.mkdtemp(dir=ROOT / 'target', prefix='contract-rpc-'))
    print(work, flush=True)
    key = work / 'public-test-key.bin'
    key.write_bytes(b'\x42' * 32)
    wasm = ROOT / 'contracts/alice-neural/target/wasm32-unknown-unknown/release/alice_neural_contract.wasm'
    for path in (NODE, CLIENT, BOB, MINER, POOL, wasm, MARKET):
        if not path.is_file():
            raise FileNotFoundError(path)
    descriptor = bytes.fromhex(json.loads(subprocess.check_output([
        BOB, 'challenge', '--seed', '44' * 32, '--epoch', '1', '--json'
    ]))['descriptor_hex'])
    payload = b'Hyphen ABI\0\xff'
    cases = [
        ('rust', wasm, b'\x01' + descriptor, b'hyphen:chal:v1:' + (1).to_bytes(8, 'little'), descriptor),
        *[(lang, ROOT / 'target/contract-toolchains' / f'{lang}.wasm', payload, b'key', payload) for lang in ('c', 'cpp', 's')],
    ]
    for _, path, *_ in cases:
        if not path.is_file():
            raise FileNotFoundError(path)

    with ExitStack() as reserved:
        sockets = [reserved.enter_context(socket.socket()) for _ in range(10)]
        for sock in sockets:
            sock.bind(('127.0.0.1', 0))
        p2p, rpc, explorer, template, pool, api, peer_p2p, peer_rpc, peer_web, peer_tp = [s.getsockname()[1] for s in sockets]
    bind = lambda port: f'127.0.0.1:{port}'
    node_args = ['--network', 'neural-devnet', '--data-dir', work / 'node', '--listen',
                 f'/ip4/127.0.0.1/tcp/{p2p}', '--rpc-bind', bind(rpc), '--template-bind',
                 bind(template), '--explorer-bind', bind(explorer)]
    base = f'http://{bind(explorer)}/api'
    def client(*args):
        return subprocess.check_output([CLIENT, '--rpc', bind(rpc), *args], text=True, stderr=subprocess.STDOUT).strip()

    with ExitStack() as stack:
        def launch(name, executable, *args):
            with (work / f'{name}.log').open('wb') as log:
                process = subprocess.Popen([executable, *args], stdout=log, stderr=log, cwd=work)
            stack.callback(stop, process)
            return process

        node = launch('node', NODE, *node_args)
        wait_json(base + '/info', [node])
        def confirmed(*args):
            result = dict(line.split('=', 1) for line in client(*args).splitlines())
            # Subscribe after admission so the initial template includes the pending transaction.
            with ExitStack() as mining:
                server = launch('pool-' + result['transaction'], POOL, '--network', 'neural-devnet',
                                '--bind', bind(pool), '--api-bind', bind(api), '--node', bind(template),
                                '--pool-state-dir', work / 'pool', '--payout-mode', 'solo')
                mining.callback(stop, server)
                wait_json(f'http://{bind(api)}/healthz', [server, node])
                miner = launch('miner-' + result['transaction'], MINER, '--network', 'neural-devnet',
                               '--pool', bind(pool), '--threads', '1', '--wallet-address', ADDRESS)
                mining.callback(stop, miner)
                location = wait_json(base + '/tx/' + result['transaction'], [node, server, miner],
                                     timeout=600, interval=0.05)
            assert location['tx_hash'] == result['transaction'] and location['block_height'] > 0
            return result['address'], result['transaction']

        records = []
        query_input = work / 'rust-status.bin'
        query_input.write_bytes(b'\x03' + (1).to_bytes(8, 'little'))

        def query(address, language):
            args = ['--input', query_input] if language == 'rust' else []
            output = dict(line.split('=', 1) for line in client('query', address, *args).splitlines())
            expected = b'\x03' + bytes(16) if language == 'rust' else payload
            if output['result'] != expected.hex():
                raise RuntimeError(f'{language} query result differs from the ABI output')
            return output

        for index, (language, module, data, storage_key, expected) in enumerate([] if collection_only else cases):
            address, deploy = confirmed('deploy', module, '--key-file', key, '--nonce', str(2 * index), '--gas', '50000000')
            input_file = work / f'{language}.bin'
            input_file.write_bytes(data)
            _, call = confirmed('call', address, 'hyphen_execute', '--key-file', key, '--nonce',
                                str(2 * index + 1), '--input', input_file, '--gas', '50000000')
            assert client('storage', address, storage_key.hex()) == expected.hex()
            query(address, language)
            records.append(dict(language=language, address=address, deploy=deploy, call=call))
        scenario = 'collection' if collection_only else 'market'
        exercise = test_collection if collection_only else test_limit_orders
        market, verify_settlement = exercise(work, client, confirmed)
        stop(node)
        node = launch('reopened', NODE, *node_args)
        tip = wait_json(base + '/info', [node])
        verify_settlement()
        for tx in market['transactions']:
            assert wait_json(base + '/tx/' + tx, [node])['tx_hash'] == tx
        for record, (_, _, _, storage_key, expected) in zip(records, cases):
            assert client('storage', record['address'], storage_key.hex()) == expected.hex()
            record['query'] = query(record['address'], record['language'])
            assert record['query']['block'] == tip['tip_hash']
            if record['language'] == 'rust':
                alternate = dict(line.split('=', 1) for line in client('query', record['address'],
                    '--function', 'hyphen_execute', '--input', query_input).splitlines())
                assert alternate == record['query']
            else:
                rejected = subprocess.run([CLIENT, '--rpc', bind(rpc), 'query', record['address'],
                    '--function', 'hyphen_execute'], capture_output=True, text=True)
                assert rejected.returncode and 'query export changed contract storage' in rejected.stderr
                assert client('storage', record['address'], storage_key.hex()) == expected.hex()
            for field in ('deploy', 'call'):
                assert wait_json(base + '/tx/' + record[field], [node])['tx_hash'] == record[field]

        seed_log = (work / 'reopened.log').read_text(encoding='utf-8')
        peer_id = re.search(r'local peer ID: (\w+)', seed_log)[1]
        peer = launch('peer', NODE, '--network', 'neural-devnet', '--data-dir', work / 'peer',
                      '--listen', f'/ip4/127.0.0.1/tcp/{peer_p2p}', '--rpc-bind', bind(peer_rpc),
                      '--template-bind', bind(peer_tp), '--explorer-bind', bind(peer_web),
                      '--boot-nodes', f'/ip4/127.0.0.1/tcp/{p2p}/p2p/{peer_id}')
        deadline = time.monotonic() + 180
        while wait_json(f'http://{bind(peer_web)}/api/info', [node, peer])['tip_hash'] != tip['tip_hash']:
            if time.monotonic() >= deadline:
                raise TimeoutError('peer did not synchronize to reopened tip')
            time.sleep(.5)
        # Mining is stopped. The second node can only receive this signed transaction through gossip.
        pending = dict(line.split('=', 1) for line in client('deploy', cases[1][1], '--nonce',
                       str(2 * len(records)), '--key-file', key).splitlines())['transaction']
        deadline = time.monotonic() + 30
        while True:
            peer_log = (work / 'peer.log').read_text(encoding='utf-8')
            if any('Admitted peer transaction' in line and pending in line for line in peer_log.splitlines()):
                break
            if peer.poll() is not None or time.monotonic() >= deadline:
                raise RuntimeError(f'peer did not admit gossiped transaction {pending}')
            time.sleep(.25)
        hashes = {}
        for binary in (NODE, CLIENT, BOB, MINER, POOL, COLLECTION if collection_only else MARKET, *(case[1] for case in cases)):
            with binary.open('rb') as stream:
                hashes[binary.name] = hashlib.file_digest(stream, 'sha256').hexdigest()
        result = dict(height=tip['height'], tip=tip['tip_hash'], contracts=records, **{scenario: market},
                      peer_admitted=pending, sha256=hashes)
        encoded = json.dumps(result, indent=2)
        (work / 'result.json').write_text(encoded)
        print(encoded)
        return result


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--collection', action='store_true', help='exercise NFT ownership and approvals on a fresh chain')
    run(parser.parse_args().collection)
