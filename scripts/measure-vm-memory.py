"""Compare two Windows release builds of the VM block_cost workload."""

import argparse
import csv
import ctypes
from ctypes import wintypes
import hashlib
import json
import os
from pathlib import Path
import statistics
import subprocess
import tempfile
import time


class ProcessMemoryCounters(ctypes.Structure):
    _fields_ = [('cb', wintypes.DWORD), ('PageFaultCount', wintypes.DWORD)] + [
        (name, ctypes.c_size_t) for name in (
            'PeakWorkingSetSize', 'WorkingSetSize', 'QuotaPeakPagedPoolUsage', 'QuotaPagedPoolUsage',
            'QuotaPeakNonPagedPoolUsage', 'QuotaNonPagedPoolUsage', 'PagefileUsage', 'PeakPagefileUsage')]


def measure(binary, memory_info):
    counters = ProcessMemoryCounters()
    counters.cb = ctypes.sizeof(counters)
    peak = 0
    with subprocess.Popen([binary], stdout=subprocess.PIPE, text=True) as child:
        while child.poll() is None:
            if memory_info(int(child._handle), ctypes.byref(counters), counters.cb):
                peak = max(peak, counters.PeakWorkingSetSize)
            elif child.poll() is None:
                child.kill()
                raise ctypes.WinError(ctypes.get_last_error())
            time.sleep(.005)
        stdout = child.stdout.read()
        if child.returncode:
            raise subprocess.CalledProcessError(child.returncode, binary, stdout)
    rows = list(csv.DictReader(stdout.splitlines()))
    if not peak or [row['profile'] for row in rows] != ['instructions', 'short_calls']:
        raise RuntimeError(f'Incomplete block_cost run for {binary}')
    return peak, rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('baseline', type=Path)
    parser.add_argument('updated', type=Path)
    parser.add_argument('--trials', type=int, default=6, help='Paired runs with alternating order')
    args = parser.parse_args()
    if os.name != 'nt' or args.trials < 1:
        parser.error('Windows and a positive trial count are required')
    binaries = {label: path.resolve(strict=True) for label, path in
                [('baseline', args.baseline), ('updated', args.updated)]}
    digests = {}
    for label, path in binaries.items():
        with path.open('rb') as stream:
            digests[label] = hashlib.file_digest(stream, 'sha256').hexdigest()
    memory_info = ctypes.WinDLL('psapi', use_last_error=True).GetProcessMemoryInfo
    memory_info.argtypes = [wintypes.HANDLE, ctypes.POINTER(ProcessMemoryCounters), wintypes.DWORD]
    memory_info.restype = wintypes.BOOL
    target = Path(__file__).resolve().parent.parent / 'target'
    target.mkdir(exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix='vm-memory-', dir=target))
    records = []
    expected = None
    for trial in range(args.trials):
        for label in (binaries if trial % 2 == 0 else reversed(binaries)):
            peak, rows = measure(binaries[label], memory_info)
            result = [tuple(row[key] for key in ('state_bytes', 'transactions', 'declared_gas', 'used_gas', 'root'))
                      for row in rows]
            if expected is not None and result != expected:
                raise RuntimeError(f'VM state or gas differs for {label} on trial {trial + 1}')
            expected = result
            records.append(dict(trial=trial + 1, version=label, peak_bytes=peak, rows=rows, binary_sha256=digests[label]))
    (work / 'result.json').write_text(json.dumps(records, indent=2), encoding='utf-8')
    print(work / 'result.json')
    for label in binaries:
        median = statistics.median(r['peak_bytes'] for r in records if r['version'] == label)
        print(f'{label} median peak working set {median / (1024 ** 2):.3f} MiB')


if __name__ == '__main__':
    main()
