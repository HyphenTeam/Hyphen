"""Recompute the C4 search trace and integer retarget measurements using Python 3."""

import json
from itertools import pairwise
from math import isqrt
from pathlib import Path

VECTORS = Path(__file__).resolve().parents[1] / 'test-vectors'
U64_MAX = (1 << 64) - 1
I128_MAX = (1 << 127) - 1


def check(actual, expected, case):
    if actual != expected:
        raise ValueError(f'{case}: got {actual}, expected {expected}')


def clamp(value, low, high):
    return min(high, max(low, value))


def divide(value, divisor):
    """Signed division truncated towards zero for positive divisors."""
    return value // divisor if value >= 0 else -((-value) // divisor)


def controller_root(n):
    # This is the frozen stopping rule, including its initial estimate.
    x = 1 << (n.bit_length() // 2)
    while (step := (x + n // x) // 2) < x:
        x = step
    return x


def dampener(times):
    n = len(times)
    if n < 6:
        return 0
    mean = sum(times) // n
    centered = [x - mean for x in times]
    var = sum(x * x for x in centered)
    cross = sum(x * y for x, y in pairwise(centered))
    if var < n or cross >= 0:
        return 0
    # Rust saturates each signed multiply. Here the intermediate negative
    # product fits i128 for all supported 30/60-header profile windows.
    left = min(I128_MAX, n ** 3 * cross ** 2)
    right = min(I128_MAX, 4 * (n - 1) ** 2 * var ** 2)
    if left <= right:
        return 0
    magnitude = n * (-cross) * 10000 // ((n - 1) * var)
    return clamp(magnitude - 20000 // controller_root(n), 0, 10000)


def retarget(stamps, difficulty, target, initial, research):
    if len(stamps) < 2 or len(stamps) != len(difficulty):
        return initial
    times = [clamp(b - a, target // 10, 6 * target) for a, b in pairwise(stamps)]
    n = len(times)
    total = sum(difficulty[1:])
    weighted = sum(i * t for i, t in enumerate(times, start=1))
    average = total // n
    base = min(U64_MAX, average * target * (n * (n + 1) // 2) // weighted) if total else initial
    previous = difficulty[-1]
    upper = max(1, min(U64_MAX, previous * 3))
    lower = max(1, previous // 3)
    if not research:
        return clamp(base, lower, upper)
    implied = base * 10000 // max(previous, 1)
    if abs(implied - 10000) <= 1000:
        ratio = clamp(implied, 9800, 10200)
    else:
        mean = sum(times) // n
        recent = max(2, n // 3)
        momentum = 0
        if n >= 6:
            fast_mean = sum(times[-recent:]) // recent
            momentum = clamp(divide((mean - fast_mean) * 10000, mean), -10000, 10000)
        factor = clamp(10000 + divide(momentum * 3000, 10000), 5000, 15000)
        ratio = 10000 + divide((target * 10000 // mean - 10000) * factor, 10000)
    proposed = clamp(divide(previous * ratio, 10000), 1, U64_MAX)
    strength = dampener(times)
    if strength:
        factor = 7000 - strength * 5000 // 10000
        proposed = previous + divide((proposed - previous) * factor, 10000)
    k = min(6, len(stamps))
    if k >= 4 and divide((stamps[-1] - stamps[-k]) * 100, (k - 1) * target) < 25:
        return upper
    return clamp(proposed, lower, upper)


def percentiles(values):
    ordered = sorted(values)
    return [ordered[(len(values) * q + 99) // 100 - 1] for q in (50, 95, 99)]


def simulate(row):
    target = 60000
    times = [target * i for i in range(60)]
    diffs = [80] * 60
    research = row['algorithm'] == 'MomentumDampedLwmaV2'
    scenario = row['scenario']
    stock = 1600 if scenario == 'release' else 0
    fresh = weight = mismatches = largest_difference = largest_error = 0
    intervals = []
    recovery = None
    first = streak = 0
    for i in range(360):
        history = times[-60:], diffs[-60:], target, 8
        d = clamp(retarget(*history, research), 1, 4096)
        other = clamp(retarget(*history, not research), 1, 4096)
        check(d, row['required_counts'][i], (scenario, i))
        check(other, row['alternate_counts_same_parent_history'][i], (scenario, i))
        largest_difference = max(largest_difference, abs(d - other))
        mismatches += d != other
        rate = {'loss': 8, 'surge': 800 if i < 12 else 80}.get(scenario, 80)
        used = min(d, stock)
        stock -= used
        ms = max(1, (d - used) * target // rate)
        intervals.append(ms)
        times.append(times[-1] + ms)
        diffs.append(d)
        fresh += d - used
        weight += d
        largest_error = max(largest_error, abs(d - rate))
        if used or (scenario == 'surge' and i < 12):
            first = i + 1
            streak = 0
        else:
            streak = streak + 1 if 54000 <= ms <= 66000 else 0
            if streak == 6 and recovery is None:
                recovery = {'blocks': i + 1 - first, 'elapsed_ms': sum(intervals[first:])}
    observed = dict(validated_weight=weight, fresh_witness_equivalents=fresh,
                    same_history_different_blocks=mismatches, same_history_max_controller_difference=largest_difference,
                    max_abs_difficulty_minus_equilibrium=largest_error, interval_ms_p50_p95_p99=percentiles(intervals),
                    recovery=recovery, elapsed_ms=sum(intervals), intervals_ms=intervals)
    for key, value in observed.items():
        check(value, row[key], (row['algorithm'], scenario, key))


def independent_search():
    # Fixed search budget of four million odd origins, independent of the
    # measured stopping position. Index k denotes the odd prime candidate 2k+1.
    first = 1_000_001
    last = first + 2 * (4_000_000 - 1)
    highest = 8 * last + 7
    prime = bytearray(b'\x01') * ((highest + 1) // 2)
    prime[0] = 0
    for p in range(3, isqrt(highest) + 1, 2):
        if prime[p // 2]:
            start = p * p // 2
            prime[start::p] = bytes((len(prime) - 1 - start) // p + 1)
    origins = []
    costs = []
    previous = first - 2
    for n in range(first, last + 1, 2):
        if prime[n // 2] and prime[n] and prime[2 * n + 1] and prime[4 * n + 3]:
            origins.append(n)
            if len(origins) % 8 == 0:
                costs.append((n - previous) // 2)
                previous = n
            if len(origins) == 512:
                return origins, costs
    raise ValueError('fixed C4 search budget exhausted')


def main():
    data = json.loads((VECTORS / 'witness-inventory-v1.json').read_bytes())
    cases = json.loads((VECTORS / 'retarget-boundaries-v1.json').read_bytes())
    for case in cases:
        research = case['profile'] == 'mainnet'
        raw = retarget(case['timestamps'], case['difficulties'], 60000 if research else 30000, 8 if research else 1, research)
        check(raw, case['expected_raw'], case['case'])
        check(clamp(raw, 1, 4096), case['expected_count'], case['case'])
    for row in data['controller']:
        simulate(row)
    origins, costs = independent_search()
    check(origins, data['origin_sequence'], 'C4 origin sequence')
    schedules = {'live': costs, 'prelaunch': [0] * 64, 'sibling': [0] * 64,
                 'withhold': costs[:32] + [sum(costs[32:])] + [0] * 31}
    for row in data['inventory']:
        post = schedules[row['schedule']]
        intervals = [1 + x for x in post]
        check(intervals, row['intervals_ms'], row['schedule'])
        check(sum(post), row['phase_candidate_tests'], row['schedule'])
        check(sum(costs) - sum(post), row['prior_candidate_tests'], row['schedule'])
        check(percentiles(intervals), row['interval_ms_p50_p95_p99'], row['schedule'])
        check(post.count(0), row['zero_search_blocks'], row['schedule'])
    known = set(origins)
    paired = sum(2 * n + 1 in known for n in origins)
    print(f'{len(cases)} retarget boundaries, 8 controller runs, 4 schedules. '
          f'{sum(costs):,} candidate tests for 512 C4 origins, {paired} adjacent window pairs.')


if __name__ == '__main__':
    main()
