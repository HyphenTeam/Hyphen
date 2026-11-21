"""Independent HYN3 vector check. Requires blake3 and pycryptodome."""

import argparse
import json
import struct
from pathlib import Path
from urllib.request import urlopen

from blake3 import blake3
from Crypto.Cipher import ChaCha20


MASK = (1 << 64) - 1
ONE = 1 << 32
VECTORS = Path(__file__).resolve().parents[1] / 'test-vectors'


def mix(x):
    x = ((x ^ (x >> 30)) * 0xbf58476d1ce4e5b9) & MASK
    x = ((x ^ (x >> 27)) * 0x94d049bb133111eb) & MASK
    return x ^ (x >> 31)


def weights(seed, height):
    cipher = ChaCha20.new(key=seed, nonce=struct.pack('<IQ', 1, height ^ (1 << 63)))
    words = struct.unpack('<2112I', cipher.encrypt(bytes(2112 * 4)))
    return [((word * 2 * scale) >> 32) - scale for word, scale in
            zip(words, [ONE // 4] * 1088 + [ONE // 8] * 1024)] + [0] * 16


def activate(x):
    a = abs(x)
    if a >= 3 * ONE:
        value = ONE
    else:
        square = a * a >> 32
        value = a * (27 * ONE + square) // (27 * ONE + 9 * square)
    return -value if x < 0 else value


def layer(inputs, matrix, bias):
    width = len(inputs)
    return [activate(b + sum((x * w) >> 32 for x, w in
                             zip(inputs, matrix[i*width:(i+1)*width])))
            for i, b in enumerate(bias)]


def score(seed, tensor, nonce):
    words = struct.unpack('<8I', seed)
    stream = 0x48595048454e5731 ^ (nonce * 0x9e3779b9 & MASK)
    inputs = [2 * (mix(words[i % 8] ^ stream ^ i) >> 32) - ONE for i in range(16)]
    hidden = layer(inputs, tensor[:1024], tensor[1024:1088])
    outputs = layer(hidden, tensor[1088:2112], tensor[2112:])
    folded = 0x9e3779b97f4a7c15
    for y in outputs:
        folded = mix(folded ^ (y & MASK))
    return mix(folded)


def scratchpad(gate):
    def keyed(data):
        return blake3(data, key=gate).digest()

    state = keyed(b'Hyphen/neural-memory/v3\0')
    cells = []
    for _ in range(32768):
        cells.append(state)
        state = keyed(state)
    for _ in range(32768):
        index = int.from_bytes(state[:2], 'little') & 32767
        state = keyed(state + cells[index])
    return blake3(b'Hyphen/neural-final/v3\0' + gate + state).digest()


def candidate(parent, height, miner, threshold, nonce, seed, tensor):
    neural = score(seed, tensor, nonce)
    gate = blake3(b'Hyphen/neural-gate/v3\0' + seed + struct.pack('<QQ', nonce, neural)).digest()
    if int.from_bytes(gate[:8], 'little') >= 1 << 60:
        return None
    digest = scratchpad(gate)
    final = int.from_bytes(digest[:8], 'little')
    if final >= threshold:
        return None
    transcript = parent + struct.pack('<QQ', height, threshold) + miner + struct.pack('<Q', nonce)
    commitment = blake3(b'Hyphen/neural-work-commitment/v1' + transcript).hexdigest()
    return dict(parent=parent.hex(), height=height, miner_key=miner.hex(), seed=seed.hex(),
                nonce=nonce, neural_score=neural, gate_digest=gate.hex(), memory_digest=digest.hex(),
                memory_score=final, threshold=threshold, commitment=commitment)


def challenge(parent, height, miner):
    seed = blake3(b'Hyphen/neural-work-seed/v1' + parent + struct.pack('<Q', height) + miner).digest()
    return seed, weights(seed, height)


def first_vector():
    identity, = json.loads((VECTORS / 'chain-identity-neural-v3.json').read_text())
    parent = bytes.fromhex(identity['genesis_hash'])
    height, miner, threshold = 1, bytes([19]) * 32, 1 << 60
    seed, tensor = challenge(parent, height, miner)
    for nonce in range(1 << 16):
        result = candidate(parent, height, miner, threshold, nonce, seed, tensor)
        if result is not None:
            return result
    raise ValueError('no solution in reference window')


def header_hash(h):
    def uint(n):
        if 0 <= n < 251:
            return bytes([n])
        for tag, width in [(251, 2), (252, 4), (253, 8)]:
            if n < 1 << (width * 8):
                return bytes([tag]) + n.to_bytes(width, 'little')
        raise ValueError('integer exceeds the header width')

    def hashes(names):
        fields = [bytes.fromhex(h[name]) for name in names.split()]
        if any(len(field) != 32 for field in fields):
            raise ValueError('wrong header digest width')
        return b''.join(fields)

    data = uint(h['version']) + uint(h['height']) + uint(h['timestamp'])
    data += hashes('prev_hash tx_root commitment_root nullifier_root state_root receipt_root uncle_root pow_commitment epoch_seed')
    data += uint(h['difficulty']) + uint(h['nonce']) + hashes('extra_nonce miner_pubkey')
    data += uint(h['total_fee_atomic']) + uint(h['reward_atomic']) + bytes([h['view_tag']]) + uint(h['declared_block_size'])
    return blake3(data).hexdigest()


def check_history(base, tip):
    """Check the PoW fields of a supplied branch back to the HYN3 genesis."""
    identity, = json.loads((VECTORS / 'chain-identity-neural-v3.json').read_text())
    blocks = []
    current = tip
    while current != identity['genesis_hash']:
        if len(current) != 64 or len(bytes.fromhex(current)) != 32:
            raise ValueError('invalid block hash')
        with urlopen(f"{base.rstrip('/')}/api/block/{current}", timeout=10) as response:
            block = json.load(response)
        header = block['header']
        if (block['hash'] != current or header_hash(header) != current or header['height'] < 1 or
                (blocks and header['height'] != blocks[-1]['header']['height'] - 1)):
            raise ValueError('discontinuous branch')
        blocks.append(block)
        current = header['prev_hash']
    history = []
    weight = 0
    for height, block in enumerate(reversed(blocks), 1):
        header = block['header']
        threshold = 1 << 60
        if height >= 18:
            scale = 1 << 96
            elapsed = min(max(history[-1]['timestamp'] - history[-17]['timestamp'], 1), 1920000)
            work = sum(scale // h['difficulty'] for h in history[-16:])
            parent_target = history[-1]['difficulty']
            threshold = max((parent_target + 3) // 4, min(1 << 62, parent_target * 4, scale * elapsed // (30000 * work)))
        if header['height'] != height or header['difficulty'] != threshold:
            raise ValueError(f'wrong height or threshold at {height}')
        miner = bytes.fromhex(header['miner_pubkey'])
        parent = bytes.fromhex(header['prev_hash'])
        result = candidate(parent, height, miner, threshold, int(block['neural_work_nonce']), *challenge(parent, height, miner))
        if result is None or result['commitment'] != header['pow_commitment']:
            raise ValueError(f'work verification failed at height {height}')
        weight += MASK // threshold
        history.append(header)
    return dict(tip=tip, checked_post_genesis_blocks=len(history), post_genesis_weight=weight)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--explorer', help='Local node HTTP origin for a branch check')
    parser.add_argument('--tip', help='Exact block hash at which to start')
    options = parser.parse_args()
    if bool(options.explorer) != bool(options.tip):
        parser.error('--explorer and --tip are used together')
    expected = json.loads((VECTORS / 'neural-block-work-v3.json').read_text())
    actual = first_vector()
    if expected != actual:
        raise SystemExit('HYN3 reference vector mismatch')
    print(f"Verified nonce {actual['nonce']} and both full BLAKE3 digests")
    if options.tip:
        print(json.dumps(check_history(options.explorer, options.tip)))
