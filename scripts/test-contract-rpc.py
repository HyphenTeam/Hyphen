"""Run signed Rust, C and Wasm assembly transactions against a fresh contract-devnet."""

import hashlib
import json
import os
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
NODE = ROOT / 'target/debug' / ('hyphen-node' + SUFFIX)
CLIENT = NODE.with_name('hyphen-contract' + SUFFIX)
BOB = NODE.with_name('bob-miner' + SUFFIX)
POOL = ROOT / 'HyphenPool/target/debug' / ('hyphen-pool-server' + SUFFIX)
MINER = ROOT / 'HyphenMiner/target/debug' / ('hyphen-miner' + SUFFIX)
ADDRESS = 'hy12X1dKMPZ9KRTa4CaZ1MFGHPqCGFnjwVZAPQPKcYq5fpUPkdKn6VVomB1oRK8r7bW8s7uR9iYUQtpSdSfifsCg1P3WKdxD3'


def wait_json(url, processes):
    deadline = time.monotonic() + 180
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
        time.sleep(0.5)
    raise TimeoutError(url)


def stop(process):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()


def run():
    work = Path(tempfile.mkdtemp(dir=ROOT / 'target', prefix='contract-rpc-'))
    print(work, flush=True)
    key = work / 'public-test-key.bin'
    key.write_bytes(b'\x42' * 32)
    wasm = ROOT / 'contracts/alice-neural/target/wasm32-unknown-unknown/release/alice_neural_contract.wasm'
    for path in (NODE, CLIENT, BOB, MINER, POOL, wasm):
        if not path.is_file():
            raise FileNotFoundError(path)
    descriptor = bytes.fromhex(json.loads(subprocess.check_output([
        BOB, 'challenge', '--seed', '44' * 32, '--epoch', '1', '--json'
    ]))['descriptor_hex'])
    payload = b'Hyphen ABI\0\xff'
    cases = [
        ('rust', wasm, b'\x01' + descriptor, b'hyphen:chal:v1:' + (1).to_bytes(8, 'little'), descriptor),
        *[(lang, ROOT / 'target/contract-toolchains' / f'{lang}.wasm', payload, b'key', payload) for lang in ('c', 's')],
    ]
    for _, path, *_ in cases:
        if not path.is_file():
            raise FileNotFoundError(path)

    with ExitStack() as reserved:
        sockets = [reserved.enter_context(socket.socket()) for _ in range(6)]
        for sock in sockets:
            sock.bind(('127.0.0.1', 0))
        p2p, rpc, explorer, template, pool, api = [s.getsockname()[1] for s in sockets]
    bind = lambda port: f'127.0.0.1:{port}'
    node_args = ['--network', 'contract-devnet', '--data-dir', work / 'node', '--listen',
                 f'/ip4/127.0.0.1/tcp/{p2p}', '--rpc-bind', bind(rpc), '--template-bind',
                 bind(template), '--explorer-bind', bind(explorer)]
    base = f'http://{bind(explorer)}/api'
    def client(*args):
        return subprocess.check_output([CLIENT, '--rpc', bind(rpc), *args], text=True).strip()

    with ExitStack() as stack:
        def launch(name, executable, *args):
            log = stack.enter_context((work / f'{name}.log').open('wb'))
            process = subprocess.Popen([executable, *args], stdout=log, stderr=log, cwd=work)
            stack.callback(stop, process)
            return process

        node = launch('node', NODE, *node_args)
        wait_json(base + '/info', [node])
        server = launch('pool', POOL, '--network', 'contract-devnet', '--bind', bind(pool),
                        '--api-bind', bind(api), '--node', bind(template), '--pool-state-dir',
                        work / 'pool', '--payout-mode', 'solo')
        wait_json(f'http://{bind(api)}/healthz', [server, node])
        miner = launch('miner', MINER, '--network', 'contract-devnet', '--pool', bind(pool),
                       '--threads', '1', '--wallet-address', ADDRESS)
        def confirmed(*args):
            result = dict(line.split('=', 1) for line in client(*args).splitlines())
            location = wait_json(base + '/tx/' + result['transaction'], [node, server, miner])
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

        for index, (language, module, data, storage_key, expected) in enumerate(cases):
            address, deploy = confirmed('deploy', module, '--key-file', key, '--nonce', str(2 * index), '--gas', '50000000')
            input_file = work / f'{language}.bin'
            input_file.write_bytes(data)
            _, call = confirmed('call', address, 'hyphen_execute', '--key-file', key, '--nonce',
                                str(2 * index + 1), '--input', input_file, '--gas', '50000000')
            assert client('storage', address, storage_key.hex()) == expected.hex()
            query(address, language)
            records.append(dict(language=language, address=address, deploy=deploy, call=call))
        for process in [miner, server, node]:
            stop(process)
        node = launch('reopened', NODE, *node_args)
        tip = wait_json(base + '/info', [node])
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
        hashes = {}
        for binary in (NODE, CLIENT, BOB, MINER, POOL, *(case[1] for case in cases)):
            with binary.open('rb') as stream:
                hashes[binary.name] = hashlib.file_digest(stream, 'sha256').hexdigest()
        result = dict(height=tip['height'], tip=tip['tip_hash'], contracts=records, sha256=hashes)
        encoded = json.dumps(result, indent=2)
        (work / 'result.json').write_text(encoded)
        print(encoded)
        return result


if __name__ == '__main__':
    run()
