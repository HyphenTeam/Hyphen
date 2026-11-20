"""Check the archived H-SAC v0 payment transcript with BLAKE3 and libsodium.

Requires the Python packages blake3 and rbcl. The wallet's Rust test decodes
the archived transaction and checks its output at the disclosed ordinal.
"""

import argparse
import json
import subprocess
import tempfile
import time
from pathlib import Path

import rbcl
from blake3 import blake3


def check(condition, message):
    if not condition:
        raise ValueError(message)


def transcript(proof):
    return b''.join((
        bytes([proof['version']]), bytes(proof['chain_id']), bytes(proof['txid']),
        proof['output_index'].to_bytes(4, 'big'), proof['global_index'].to_bytes(8, 'big'),
        bytes(proof['auditor']), bytes(proof['scope_hash']),
        proof['issued_at'].to_bytes(8, 'big'), proof['expires_at'].to_bytes(8, 'big'),
        bytes(proof['disclosure_nonce']), bytes(proof['commitment']), bytes(proof['one_time_pubkey']),
        proof['value'].to_bytes(8, 'big'), bytes(proof['blinding']),
    ))


def owns_output(proof):
    public = bytes(proof['one_time_pubkey'])
    nonce = bytes(proof['ownership_proof']['nonce_point'])
    response = bytes(proof['ownership_proof']['response'])
    reduce_scalar = rbcl.crypto_core_ristretto255_scalar_reduce
    if not all(p != bytes(32) and rbcl.crypto_core_ristretto255_is_valid_point(p) for p in (public, nonce)):
        return False
    if reduce_scalar(response + bytes(32)) != response:
        return False
    digest = blake3(b'HYPHEN_SAC_DISCLOSURE_CONTEXT_V0\0' + transcript(proof)).digest()
    material = b'HYPHEN_SAC_OWNERSHIP_CHALLENGE_V0' + digest + nonce + public
    challenge = reduce_scalar(blake3(material).digest(length=64))
    if challenge == bytes(32):
        return False
    expected = rbcl.crypto_core_ristretto255_add(nonce, rbcl.crypto_scalarmult_ristretto255(challenge, public))
    return rbcl.crypto_scalarmult_ristretto255_base_allow_scalar_zero(response) == expected


def verify(vector, proof, now):
    check(proof['version'] == 0 and len(transcript(proof)) == 293, 'unexpected transcript format')
    check(proof['issued_at'] <= now <= proof['expires_at'] and proof['issued_at'] < proof['expires_at'],
          'invalid disclosure validity period')
    check(blake3(bytes.fromhex(vector['transaction_hex'])).digest() == bytes(proof['txid']), 'transaction hash differs')
    generator = rbcl.crypto_core_ristretto255_from_hash(blake3(b'Hyphen_h2p_v1Hyphen_pedersen_value_generator_v1').digest(length=64))
    blinding = bytes(proof['blinding'])
    check(rbcl.crypto_core_ristretto255_scalar_reduce(blinding + bytes(32)) == blinding, 'noncanonical opening')
    amount_point = rbcl.crypto_scalarmult_ristretto255_allow_scalar_zero(proof['value'].to_bytes(32, 'little'), generator)
    blind_point = rbcl.crypto_scalarmult_ristretto255_base_allow_scalar_zero(blinding)
    check(rbcl.crypto_core_ristretto255_add(amount_point, blind_point) == bytes(proof['commitment']), 'opening differs')
    check(owns_output(proof), 'ownership equation differs')
    check(not owns_output({**proof, 'global_index': proof['global_index'] + 1}), 'accepted another index')
    check(not owns_output({**proof, 'scope_hash': bytes(32)}), 'accepted another scope')
    ownership = proof['ownership_proof']
    token = b'HYPHEN_SAC_CAPABILITY_ID_V0\0' + transcript(proof) + bytes(ownership['nonce_point']) + bytes(ownership['response'])
    return blake3(token).hexdigest()


def check_issuance(wallet_bin, vector):
    archived = vector['disclosure']
    export = {key: vector[key] for key in ('transaction_hex', 'network', 'block_hash', 'block_height',
                                            'tip_hash', 'tip_height')}
    export.update(schema='hyphen-canonical-output-v1', txid=bytes(archived['txid']).hex(),
                  chain_id=bytes(archived['chain_id']).hex(), global_index=archived['global_index'],
                  output_index=archived['output_index'])
    scope = blake3(b'Hyphen archived payment issuance test').digest()
    expiry = int(time.time()) + 3600
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / 'output.json'
        path.write_text(json.dumps(export), encoding='utf-8')
        args = [wallet_bin, path, bytes(archived['auditor']).hex(), scope.hex(), str(expiry)]
        # Public fixture seeds used by the PPLNS devnet payment run.
        issued = json.loads(subprocess.check_output(args, input=bytes([0x43]) * 64))
        wrong_wallet = subprocess.run(args, input=bytes([0x42]) * 64, capture_output=True)
        check(wrong_wallet.returncode != 0 and not wrong_wallet.stdout, 'wrong wallet issued a disclosure')
    for field in ('txid', 'chain_id', 'value', 'blinding', 'commitment', 'one_time_pubkey',
                  'global_index', 'output_index', 'auditor'):
        check(archived[field] == issued[field], f'issued {field} differs from archived payment')
    check(bytes(issued['scope_hash']) == scope and issued['expires_at'] == expiry, 'issuer changed context')
    capability = verify(vector, issued, int(time.time()))
    print(f'Verified newly issued capability {capability}')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--wallet-bin', type=Path, help='Issue a fresh disclosure with the independent hyphen-disclose binary')
    args = parser.parse_args()
    vector_path = Path(__file__).resolve().parents[1] / 'test-vectors/h-sac-payment-v0.json'
    vector = json.loads(vector_path.read_text(encoding='utf-8'))
    proof = vector['disclosure']
    check(verify(vector, proof, vector['verified_at']) == vector['capability_id'], 'archived capability ID differs')
    print(f"Verified payment {bytes(proof['txid']).hex()}, amount {proof['value']}, global index {proof['global_index']}")
    if args.wallet_bin:
        check_issuance(args.wallet_bin.resolve(strict=True), vector)


if __name__ == '__main__':
    main()
