"""Submit an Alice solution through the node RPC and recover it after a restart."""

import json
import runpy
import socket
import struct
import subprocess
import tempfile
import time
from contextlib import ExitStack
from pathlib import Path


def main():
    smoke = runpy.run_path(str(Path(__file__).with_name('test-contract-rpc.py')))
    node_bin, pool_bin, miner_bin, bob = (smoke[k] for k in ('NODE', 'POOL', 'MINER', 'BOB'))
    compute = node_bin.with_name('hyphen-compute' + node_bin.suffix)
    work = Path(tempfile.mkdtemp(dir=node_bin.parent.parent, prefix='compute-rpc-'))
    print(work, flush=True)
    params = ['--seed', '44' * 32, '--epoch', '1', '--json']
    desc = bytes.fromhex(json.loads(subprocess.check_output([bob, 'challenge', *params]))['descriptor_hex'])
    solved = json.loads(subprocess.check_output([bob, 'solve', *params]))
    assert solved['accepted']
    solution = b''.join(struct.pack('<q', n) for n in solved['solution'])
    (work / 'descriptor').write_bytes(desc)
    (work / 'proof').write_bytes(desc + solution)
    for name, byte in [('publisher', 14), ('worker', 15)]:
        (work / name).write_bytes(bytes([byte]) * 32)

    with ExitStack() as reserved:
        sockets = [reserved.enter_context(socket.socket()) for _ in range(6)]
        for sock in sockets:
            sock.bind(('127.0.0.1', 0))
        p2p, rpc, explorer, tp, pool, api = [s.getsockname()[1] for s in sockets]
    def bind(port):
        return f'127.0.0.1:{port}'

    def cli(*args):
        return subprocess.check_output([compute, '--rpc', bind(rpc), *args], cwd=work, text=True)

    with ExitStack() as stack:
        def launch(name, exe, *args):
            log = stack.enter_context((work / (name + '.log')).open('wb'))
            proc = subprocess.Popen([exe, '--network', 'compute-devnet', *args], cwd=work, stdout=log, stderr=log)
            stack.callback(smoke['stop'], proc)
            return proc

        node_args = ['--data-dir', work / 'node', '--listen', f'/ip4/127.0.0.1/tcp/{p2p}',
                     '--rpc-bind', bind(rpc), '--explorer-bind', bind(explorer), '--template-bind', bind(tp)]
        node = launch('node', node_bin, *node_args)
        base = f'http://{bind(explorer)}/api'
        wait = smoke['wait_json']
        wait(base + '/info', [node])
        server = launch('pool', pool_bin, '--node', bind(tp), '--bind', bind(pool), '--api-bind', bind(api),
                        '--pool-state-dir', work / 'pool', '--payout-mode', 'solo')
        wait(f'http://{bind(api)}/healthz', [node, server])
        miner = launch('miner', miner_bin, '--pool', bind(pool), '--threads', '3', '--wallet-address', smoke['ADDRESS'])
        processes = [node, server, miner]
        def confirm(*args):
            tx = dict(line.split('=', 1) for line in cli(*args).splitlines())
            location = wait(base + '/tx/' + tx['transaction'], processes)
            assert location['tx_hash'] == tx['transaction'] and location['block_height'] > 0
            return {**tx, 'height': location['block_height']}

        publish = confirm('publish', 'descriptor', '--key-file', 'publisher', '--nonce', '1', '--deadline', '200', '--reward', '1')
        task = publish['task']
        submitted = confirm('submit', task, 'proof', '--key-file', 'worker')
        record = json.loads(cli('show', task))
        deadline = record['status']['Submitted']['challenge_deadline']
        early = subprocess.run([compute, '--rpc', bind(rpc), 'finalize', task], capture_output=True, text=True)
        assert early.returncode and 'challenge period' in early.stderr.lower(), early
        end = time.monotonic() + 900
        while wait(base + '/info', processes)['height'] < deadline:
            if time.monotonic() >= end:
                raise TimeoutError(f'waiting for height {deadline}')
            time.sleep(1)
        finalized = confirm('finalize', task)
        before = json.loads(cli('show', task))
        for proc in reversed(processes):
            smoke['stop'](proc)
        reopened = launch('reopened', node_bin, *node_args)
        tip = wait(base + '/info', [reopened])
        after = json.loads(cli('show', task))
        assert after == before
        status = after['status']['Finalized']
        assert status['finalized_height'] == finalized['height'] > deadline
        assert bytes(status['result']['claim']['proof']) == desc + solution
        assert status['retain_until_height'] == finalized['height'] + after['task']['spec']['retention_blocks']
        smoke['stop'](reopened)
        local = subprocess.run([compute, 'show', task, '--data-dir', work / 'node'], cwd=work,
                               capture_output=True, check=True, text=True)
        assert json.loads(local.stdout) == after
        checked = dict(item.split('=', 1) for item in local.stderr.strip().split())
        assert checked['tip_hash'] == tip['tip_hash'] and int(checked['tip_height']) == tip['height']
        evidence = dict(publish=publish, submit=submitted, finalize=finalized, tip=tip['tip_hash'],
                        challenge_deadline=deadline, state_root=checked['state_root'], record=after)
        (work / 'result.json').write_text(json.dumps(evidence, indent=2))
        print(f"task={task} published={publish['height']} submitted={submitted['height']} finalized={finalized['height']}")


if __name__ == '__main__':
    main()
