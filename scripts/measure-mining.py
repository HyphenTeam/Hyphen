"""Measure release CPU and CUDA mining against a local node and SOLO pool."""

import argparse
import csv
import hashlib
import json
import os
import platform
import re
import runpy
import shutil
import socket
import statistics
import subprocess
import tempfile
import time
from contextlib import ExitStack
from datetime import datetime
from pathlib import Path


SMOKE = runpy.run_path(str(Path(__file__).with_name('test-contract-rpc.py')))
BINARIES = {name: SMOKE[name].parent.parent / 'release' / SMOKE[name].name
            for name in ('NODE', 'POOL', 'MINER')}
ANSI = re.compile(r'\x1b\[[0-9;]*m')
SOLUTION = re.compile(r'neural solution at height (\d+) after (\d+) scores '
                      r'\(backend=(\w+), search_us=(\d+)\)')


def sha256(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def gpu_energy(path, start, end):
    samples = []
    with path.open(encoding='utf-8', newline='') as stream:
        for row in csv.reader(stream):
            if len(row) != 4:
                continue
            stamp = datetime.strptime(row[0].strip(), '%Y/%m/%d %H:%M:%S.%f')
            if start <= stamp <= end:
                samples.append((stamp, float(row[1])))
    if len(samples) < 2:
        raise RuntimeError(f'Insufficient GPU sensor readings in {path}')
    joules = 0.0
    for (a, x), (b, y) in zip(samples, samples[1:]):
        seconds = (b - a).total_seconds()
        if seconds <= 0:
            raise RuntimeError(f'GPU sensor timestamps are out of order in {path}')
        joules += seconds * (x + y) / 2
    span = (samples[-1][0] - samples[0][0]).total_seconds()
    return dict(board_sensor_seconds=span, board_samples=len(samples),
                sampled_gpu_board_joules=joules, mean_gpu_board_watts=joules / span)


def measure(run, network, backend, args, gpu_uuid):
    path = run / f'{network}-{backend}'
    path.mkdir()
    with ExitStack() as reserved:
        sockets = [reserved.enter_context(socket.socket()) for _ in range(6)]
        for sock in sockets:
            sock.bind(('127.0.0.1', 0))
        p2p, rpc, explorer, template, pool, api = [s.getsockname()[1] for s in sockets]

    def endpoint(port):
        return f'127.0.0.1:{port}'

    with ExitStack() as stack:
        processes = []

        def launch(name, *options):
            log = stack.enter_context((path / f'{name}.log').open('wb'))
            process = subprocess.Popen([run / 'bin' / BINARIES[name].name, '--network', network, *options], cwd=path,
                                       env={**os.environ, 'CUDA_VISIBLE_DEVICES': gpu_uuid},
                                       stdout=log, stderr=subprocess.STDOUT)
            stack.callback(SMOKE['stop'], process)
            processes.append(process)
            return process

        launch('NODE', '--data-dir', path / 'node', '--listen', f'/ip4/127.0.0.1/tcp/{p2p}',
               '--rpc-bind', endpoint(rpc), '--template-bind', endpoint(template),
               '--explorer-bind', endpoint(explorer))
        info = f'http://{endpoint(explorer)}/api/info'
        genesis = SMOKE['wait_json'](info, processes)
        if genesis['height'] != 0:
            raise RuntimeError('Expected a fresh chain at genesis')
        launch('POOL', '--node', endpoint(template), '--bind', endpoint(pool), '--api-bind', endpoint(api),
               '--pool-state-dir', path / 'pool', '--payout-mode', 'solo', '--share-difficulty', '1')
        SMOKE['wait_json'](f'http://{endpoint(api)}/healthz', processes)

        sensor_log = stack.enter_context((path / 'gpu.csv').open('wb'))
        sensor = subprocess.Popen(['nvidia-smi', '-i', gpu_uuid, '-lms', '500', '--format=csv,noheader,nounits',
                                   '--query-gpu=timestamp,power.draw,temperature.gpu,clocks.sm'], stdout=sensor_log)
        stack.callback(SMOKE['stop'], sensor)
        options = ['--accelerator-dir', args.accelerator_dir] if backend == 'cuda' else ['--no-accelerator']
        start_wall, start = datetime.now(), time.perf_counter()
        miner = launch('MINER', '--key-file', run / 'devnet-miner.key', '--pool', endpoint(pool),
                       '--threads', '1', '--wallet-address', SMOKE['ADDRESS'], *options)
        heights = []
        while True:
            tip = SMOKE['wait_json'](info, [*processes, sensor])
            elapsed = time.perf_counter() - start
            if not heights or heights[-1]['hash'] != tip['tip_hash']:
                heights.append(dict(seconds=elapsed, height=tip['height'], hash=tip['tip_hash'],
                                    cumulative_difficulty=tip['cumulative_difficulty']))
            if elapsed >= args.seconds:
                break
            time.sleep(0.25)
        end_wall = datetime.now()
        SMOKE['stop'](miner)
        processes.remove(miner)
        balance = SMOKE['wait_json'](f'http://{endpoint(api)}/api/pool/wallet/{SMOKE["ADDRESS"]}/balance?limit=128',
                                     processes)
        if not tip['height'] or not balance['valid_shares'] or balance['invalid_shares']:
            raise RuntimeError(f'Unexpected height or share accounting in {path}')

    log = ANSI.sub('', (path / 'MINER.log').read_text(encoding='utf-8'))
    metrics = gpu_energy(path / 'gpu.csv', start_wall, end_wall)
    if backend == 'cuda':
        plugin = re.search(r'Native accelerator: cuda on .+? via (.+?) \(\d+ candidate window\)', log)
        if plugin is None or 'accelerator disabled' in log.lower():
            raise RuntimeError(f'CUDA did not serve the whole run in {path}')
        metrics['plugin_sha256'] = sha256(Path(plugin[1]))
    if network == 'neural-devnet':
        solutions = [dict(height=int(h), scores=int(n), backend=b, search_us=int(t))
                     for h, n, b, t in SOLUTION.findall(log)]
        checked_heights = {s['height'] for s in solutions if s['backend'] == backend}
        if not set(range(1, tip['height'] + 1)) <= checked_heights or any(s['backend'] != backend for s in solutions):
            raise RuntimeError(f'Missing neural search evidence for {backend} in {path}')
        metrics['neural_search_results'] = solutions
        metrics['median_search_ms'] = statistics.median(s['search_us'] for s in solutions) / 1000
    return dict(network=network, backend=backend, threads=1, seconds=elapsed, heights=heights,
                first_positive_poll_seconds=next(h['seconds'] for h in heights if h['height']),
                genesis=genesis['tip_hash'], tip_hash=tip['tip_hash'], node_height=tip['height'],
                cumulative_difficulty=tip['cumulative_difficulty'], valid_shares=balance['valid_shares'],
                invalid_shares=balance['invalid_shares'], **metrics)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--accelerator-dir', type=Path, required=True, help='Directory containing the CUDA plugin')
    parser.add_argument('--gpu', default='0', help='nvidia-smi GPU UUID or index (default 0)')
    parser.add_argument('--seconds', type=int, default=70, help='Mining time per configuration (default 70)')
    args = parser.parse_args()
    if args.seconds <= 0:
        parser.error('--seconds must be positive')
    args.accelerator_dir = args.accelerator_dir.resolve(strict=True)
    run = Path(tempfile.mkdtemp(dir=BINARIES['NODE'].parent.parent, prefix='mining-measurement-'))
    print(run, flush=True)
    bindir = run / 'bin'
    bindir.mkdir()
    for source in BINARIES.values():
        shutil.copy2(source, bindir / source.name)
    gpu = subprocess.check_output(['nvidia-smi', '-i', args.gpu, '--query-gpu=uuid,name,driver_version',
                                   '--format=csv,noheader'], text=True).strip()
    gpu_uuid, model, driver = next(csv.reader([gpu], skipinitialspace=True))
    manifest = dict(gpu=model, gpu_uuid=gpu_uuid, driver=driver, platform=platform.platform(),
                    processor=platform.processor(), requested_seconds=args.seconds,
                    executable_sha256={name: sha256(bindir / binary.name) for name, binary in BINARIES.items()})
    (run / 'manifest.json').write_text(json.dumps(manifest, indent=2), encoding='utf-8')
    (run / 'devnet-miner.key').write_bytes(bytes([111]) * 32)
    results = []
    for network in ('neural-devnet', 'devnet'):
        for backend in ('cpu', 'cuda'):
            data = measure(run, network, backend, args, gpu_uuid)
            (run / f'{network}-{backend}' / 'result.json').write_text(json.dumps(data, indent=2), encoding='utf-8')
            results.append(data)
            print(network, backend, data['node_height'], f"{data['mean_gpu_board_watts']:.2f} W", flush=True)
    (run / 'results.json').write_text(json.dumps(results, indent=2), encoding='utf-8')


if __name__ == '__main__':
    main()
