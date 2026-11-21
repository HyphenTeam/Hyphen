"""Reorganize copies of two stopped HYN3 application databases and check public state."""
import argparse
import json
import re
import runpy
import shutil
import socket
import subprocess
import tempfile
import time
from contextlib import ExitStack
from pathlib import Path


def run(lighter, heavier):
    smoke = runpy.run_path(str(Path(__file__).with_name('test-contract-rpc.py')))
    node = smoke['NODE']
    work = Path(tempfile.mkdtemp(prefix='application-reorg-', dir=smoke['ROOT'] / 'target'))
    print(work, flush=True)
    for source, name in [(lighter, 'adopter'), (heavier, 'seed')]:
        shutil.copytree(source, work / name)
    with ExitStack() as sockets:
        reserved = [sockets.enter_context(socket.socket()) for _ in range(4)]
        for sock in reserved:
            sock.bind(('127.0.0.1', 0))
        seed_p2p, seed_web, adopter_p2p, adopter_web = [s.getsockname()[1] for s in reserved]
    with ExitStack() as processes:
        def start(name, phase, p2p, web, *more):
            with (work / (phase + '.log')).open('wb') as log:
                proc = subprocess.Popen([node, '--network', 'neural-devnet', '--data-dir', work / name,
                    '--listen', f'/ip4/127.0.0.1/tcp/{p2p}', '--explorer-bind', f'127.0.0.1:{web}',
                    '--template-bind', '127.0.0.1:0', '--rpc-bind', '127.0.0.1:0', *more], stdout=log, stderr=log)
            processes.callback(smoke['stop'], proc)
            return proc

        def api(port, proc, path):
            return smoke['wait_json'](f'http://127.0.0.1:{port}/api/{path}', [proc])

        def snapshot(port, proc):
            info = api(port, proc, 'info')
            root = api(port, proc, 'block/' + info['tip_hash'])['header']['state_root']
            return dict(tip=info['tip_hash'], height=info['height'], weight=info['cumulative_difficulty'],
                        root=root, apps=api(port, proc, 'apps?limit=100'), tasks=api(port, proc, 'science/tasks?limit=100'))

        seed = start('seed', 'seed', seed_p2p, seed_web)
        expected = snapshot(seed_web, seed)
        adopter = start('adopter', 'before', adopter_p2p, adopter_web)
        before = snapshot(adopter_web, adopter)
        assert int(before['weight']) < int(expected['weight'])
        assert (before['apps'], before['tasks']) != (expected['apps'], expected['tasks'])
        smoke['stop'](adopter)
        peer = re.search(r'local peer ID: (\w+)', (work / 'seed.log').read_text(encoding='utf-8'))[1]
        joined = start('adopter', 'joined', adopter_p2p, adopter_web, '--boot-nodes',
                       f'/ip4/127.0.0.1/tcp/{seed_p2p}/p2p/{peer}')
        deadline = time.monotonic() + 180
        while api(adopter_web, joined, 'info')['tip_hash'] != expected['tip']:
            if time.monotonic() >= deadline:
                raise TimeoutError('waiting for adoption of heavier application history')
            time.sleep(.25)
        assert snapshot(adopter_web, joined) == expected
        assert api(adopter_web, joined, 'block/' + before['tip'])['canonical'] is False
        smoke['stop'](joined)
        smoke['stop'](seed)
        reopened = start('adopter', 'reopened', adopter_p2p, adopter_web)
        assert snapshot(adopter_web, reopened) == expected
        smoke['stop'](reopened)
        archive = work / 'adopted.archive'
        def history(db, flag):
            return subprocess.check_output([node, '--network', 'neural-devnet', '--data-dir', work / db,
                                            flag, archive], text=True).strip().splitlines()[-1]
        history('adopter', '--export-history')
        replay = history('fresh', '--replay-history')
        assert f"final_hash={expected['tip']}" in replay
        fresh = start('fresh', 'replay', adopter_p2p, adopter_web)
        assert snapshot(adopter_web, fresh) == expected
        result = dict(before=before, adopted=expected, replay=replay)
        (work / 'result.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
        print(replay)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('lighter', type=Path)
    parser.add_argument('heavier', type=Path)
    args = parser.parse_args()
    run(args.lighter, args.heavier)
