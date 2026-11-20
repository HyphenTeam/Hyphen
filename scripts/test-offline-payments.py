"""Fund a reserve with CLSAG, exchange it offline twice, then race two valid claims."""
import json
import os
import re
import runpy
import shutil
import socket
import subprocess
import tempfile
import time
from contextlib import ExitStack
from pathlib import Path

SMOKE = runpy.run_path(str(Path(__file__).with_name('test-contract-rpc.py')))
ROOT = SMOKE['ROOT']
SUFFIX = SMOKE['SUFFIX']
STOP = SMOKE['stop']
WAIT = SMOKE['wait_json']


def windows_peak_memory(process):
    """Read OS lifetime high-water marks while Popen still owns the process handle."""
    import ctypes
    from ctypes import wintypes

    class ProcessMemoryCounters(ctypes.Structure):
        _fields_ = [('cb', wintypes.DWORD), ('page_faults', wintypes.DWORD),
                    ('peak_working_set', ctypes.c_size_t), ('working_set', ctypes.c_size_t),
                    ('pool_counters', ctypes.c_size_t * 4), ('pagefile', ctypes.c_size_t),
                    ('peak_pagefile', ctypes.c_size_t)]

    counters = ProcessMemoryCounters()
    counters.cb = ctypes.sizeof(counters)
    handle = wintypes.HANDLE(int(process._handle))
    if not ctypes.windll.psapi.GetProcessMemoryInfo(handle, ctypes.byref(counters), counters.cb):
        raise ctypes.WinError()
    return {'peak_working_set_bytes': counters.peak_working_set, 'peak_commit_bytes': counters.peak_pagefile}


def main():
    if not __debug__:
        raise RuntimeError('This acceptance test requires Python assertions enabled.')
    work = Path(tempfile.mkdtemp(prefix='offline-settlement-', dir=ROOT / 'target'))
    print(work, flush=True)
    node, pool, miner = [SMOKE[name].parent.parent / 'release' / SMOKE[name].name for name in ('NODE', 'POOL', 'MINER')]
    offline = node.with_name('hyphen-offline' + SUFFIX)
    wallet = ROOT / 'HyphenWallet/rust/target/release' / ('hyphen-reserve-wallet' + SUFFIX)
    with ExitStack() as reserved:
        sockets = [reserved.enter_context(socket.socket()) for _ in range(10)]
        for sock in sockets:
            sock.bind(('127.0.0.1', 0))
        p2p, rpc, web, templates, mining, health, peer_p2p, peer_rpc, peer_web, peer_templates = [s.getsockname()[1] for s in sockets]
    def addr(port): return f'127.0.0.1:{port}'
    measurements = []

    def run(binary, *args, seed=None, reject=None, measure=None):
        # Published devnet fixture seeds, never used for real assets.
        start_time = time.perf_counter_ns()
        with subprocess.Popen([binary, *map(str, args)], cwd=work, stdin=subprocess.PIPE,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE) as proc:
            try:
                stdout, stderr = proc.communicate(bytes([seed])*64 if seed else b'', timeout=60)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.communicate()
                raise
            elapsed = (time.perf_counter_ns() - start_time) / 1_000_000
            if measure:
                sample = {'command': args[0], 'hops': measure, 'elapsed_ms': elapsed}
                if os.name == 'nt':
                    sample.update(windows_peak_memory(proc))
                measurements.append(sample)
        if reject:
            if proc.returncode == 0 or reject not in stderr.decode():
                raise RuntimeError((args, stdout, stderr, reject))
        elif proc.returncode:
            raise RuntimeError((args, stderr.decode()))
        return stdout.decode().strip()
    def cmd(*args, **opts): return run(offline, *args, **opts)
    def pay(*args, **opts): return run(wallet, *args, **opts)
    def history(db, mode, archive):
        return run(node, '--network', 'offline-devnet', '--data-dir', db, mode, archive)

    funding, fee = 10_000_000, 1_000_000
    net = funding - fee
    reserve_addr = cmd('reserve', funding, fee, 'reserve', seed=1)
    miner_addr = pay('address', seed=9)
    payout = pay('address', seed=3)
    alternate = pay('address', seed=4)
    base = f'http://{addr(web)}/api'
    node_args = ['--listen', f'/ip4/127.0.0.1/tcp/{p2p}',
                 '--rpc-bind', addr(rpc), '--template-bind', addr(templates), '--explorer-bind', addr(web)]
    with ExitStack() as stack:
        def launch(binary, label, *args):
            log = stack.enter_context((work / (label + '.log')).open('wb'))
            p = subprocess.Popen([binary, '--network', 'offline-devnet', *args], cwd=work, stdout=log, stderr=log)
            stack.callback(STOP, p)
            return p
        def start_mining(label, n):
            p = launch(pool, 'pool-'+label, '--node', addr(templates), '--bind', addr(mining),
                       '--api-bind', addr(health), '--pool-state-dir', work/'pool', '--payout-mode', 'solo')
            WAIT(f'http://{addr(health)}/healthz', [n,p])
            m = launch(miner, 'miner-'+label, '--threads', '1', '--no-accelerator', '--pool', addr(mining), '--wallet-address', miner_addr)
            return [n,p,m]
        def start(label, mine=True, data_dir='node'):
            n = launch(node, 'node-'+label, '--data-dir', work/data_dir, *node_args)
            WAIT(base+'/info', [n])
            return start_mining(label, n) if mine else [n]

        def join_peer(label, data_dir, seed_label, seed_node, expected_tip):
            log = (work / ('node-' + seed_label + '.log')).read_text(encoding='utf-8')
            peer_id = re.search(r'local peer ID: (\w+)', log)[1]
            joined = launch(node, 'node-' + label, '--data-dir', work/data_dir,
                            '--listen', f'/ip4/127.0.0.1/tcp/{peer_p2p}', '--rpc-bind', addr(peer_rpc),
                            '--template-bind', addr(peer_templates), '--explorer-bind', addr(peer_web),
                            '--boot-nodes', f'/ip4/127.0.0.1/tcp/{p2p}/p2p/{peer_id}')
            deadline = time.monotonic() + 150
            while WAIT(f'http://{addr(peer_web)}/api/info', [seed_node, joined])['tip_hash'] != expected_tip:
                if time.monotonic() > deadline:
                    raise TimeoutError('P2P branch adoption: ' + label)
                time.sleep(.4)
            return joined
        running = start('fund')
        deadline = time.monotonic()+120
        while WAIT(base+'/info', running)['height'] < 6:
            if time.monotonic() > deadline: raise TimeoutError('mining funding inputs')
            time.sleep(.2)
        for process in reversed(running[1:]): STOP(process)
        # These independently derived wallets have no output on this chain. Each
        # creates its own reserve terms, but none can prepare a funding payment.
        empty_wallets = range(100, 132)
        for seed in empty_wallets:
            terms = f'unfunded-{seed}'
            address = cmd('reserve', funding, fee, terms, seed=seed)
            assert json.loads(pay('balance', addr(rpc), seed=seed))['balance'] == 0
            pay('prepare', addr(rpc), address, funding, fee, terms+'.tx', seed=seed,
                reject='no spendable outputs')
            assert not (work/(terms+'.tx')).exists()
        fund_hash = pay('prepare', addr(rpc), reserve_addr, funding, fee, 'funding.tx',seed=9)
        STOP(running[0])
        history('node', '--export-history', 'before-funding.archive')
        running = start('funding', False)
        assert pay('submit',addr(rpc),'funding.tx') == fund_hash
        running = start_mining('funding', running[0])
        location = WAIT(base+'/tx/'+fund_hash, running)
        for p in reversed(running): STOP(p)
        # First regular transaction, recipient ordinal zero, one reward per earlier block.
        index = int(cmd('locate','node',fund_hash))
        assert index == location['block_height'] - 1
        for seed in empty_wallets:
            terms = f'unfunded-{seed}'
            cmd('issue', 'node', terms, index, terms+'.packet', reject='reserve absent')
            assert not (work/(terms+'.packet')).exists()
        cmd('issue', 'node', 'reserve', index, 'root')
        history('node', '--export-history', 'funded.archive')
        for directory in ('sender','first.wallet','last.wallet','fork.wallet'):
            verified_db = directory + '-node'
            history(verified_db, '--replay-history', 'funded.archive')
            cmd('checkpoint', verified_db, directory+'.ck', directory)
        shutil.copytree(work/'sender',work/'rolled-back-sender')

        def transfer(previous, name, payer, recipient, journal):
            invoice = name+'.request'
            receiving = name+'.wallet'
            cmd('request', receiving+'.ck', previous, net, receiving, invoice, seed=recipient)
            public = cmd('public-key', seed=recipient)
            cmd('transfer',journal+'.ck', previous, invoice, public, net, journal, name, seed=payer)
            receipt = cmd('accept',receiving+'.ck',name,invoice,net,receiving,seed=recipient)
            assert 'new=true' in receipt
            assert 'new=false' in cmd('accept',receiving+'.ck',name,invoice,net,receiving,seed=recipient)
        transfer('root','first',1,2,'sender')
        transfer('first','last',2,3,'first.wallet')
        # A signer waiting on stdin already owns its journal. Kill it with a partial seed,
        # then reopen the same journal and verify the previously committed receipt.
        accept_args = ['accept', 'last.wallet.ck', 'last', 'last.request', str(net), 'last.wallet']
        for attempt in range(5):
            with subprocess.Popen([offline, *accept_args], cwd=work, stdin=subprocess.PIPE,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE) as holder:
                try:
                    time.sleep(.1)
                    other_read = subprocess.run([offline, *accept_args], cwd=work, input=bytes([3])*64,
                                                capture_output=True, timeout=10)
                    if other_read.returncode:
                        assert b'DatabaseAlreadyOpen' in other_read.stderr and holder.poll() is None
                        holder.stdin.write(bytes([3]))
                        holder.stdin.flush()
                        break
                    assert b'new=false' in other_read.stdout
                finally:
                    holder.kill()
                    holder.communicate()
        else:
            raise AssertionError('could not observe journal writer lock')
        assert 'new=false' in cmd(*accept_args, seed=3)
        # Measure separate cold CLI invocations, including journal reopen, crypto and storage.
        for _ in range(5):
            assert 'new=false' in cmd('accept','last.wallet.ck','last','last.request',net,'last.wallet',seed=3,measure=2)
        # A cloned two-hop holder delegates to fourteen further parties on a competing branch.
        shutil.copytree(work/'last.wallet',work/'long.wallet')
        previous = 'last'
        payer = 3
        for hop in range(3,17):
            recipient = 3 if hop == 5 else 20 + hop
            offer = f'hop-{hop}'
            request = offer + '.request'
            cmd('request','last.wallet.ck',previous,net,'long.wallet',request,seed=recipient)
            cmd('transfer','last.wallet.ck',previous,request,cmd('public-key',seed=recipient),net,'long.wallet',offer,seed=payer)
            assert 'new=true' in cmd('accept','last.wallet.ck',offer,request,net,'long.wallet',seed=recipient)
            previous, payer = offer, recipient
        cmd('accept','last.wallet.ck','last','last.request',net,'long.wallet',seed=3,reject='previous receipt')
        for _ in range(5):
            assert 'new=false' in cmd('accept','last.wallet.ck',offer,request,net,'long.wallet',seed=payer,measure=16)
        last_address = pay('address',seed=payer)
        long_claim = cmd('redeem','last.wallet.ck',offer,last_address,net,'long.wallet','long.tx',seed=payer,measure=16).split('=')[1]
        cmd('request','last.wallet.ck',offer,net,'long.wallet','hop-17.request',seed=99,reject='transfer limit')
        cmd('request','fork.wallet.ck','root',net,'fork.wallet','fork.request',seed=4)
        public = cmd('public-key',seed=4)
        cmd('transfer','sender.ck','root','fork.request',public,net,'sender','refused',seed=1,reject='conflicting decision')
        # Publication fails after the decision has committed. A retry uses a fresh output path.
        shutil.copytree(work/'rolled-back-sender', work/'retry-wallet')
        occupied = work/'occupied'
        occupied.write_bytes(b'already present')
        rejected = subprocess.run([offline, 'transfer', 'sender.ck', 'root', 'fork.request', public,
                                   str(net), 'retry-wallet', occupied], cwd=work, input=bytes([1])*64, capture_output=True)
        assert rejected.returncode and occupied.read_bytes() == b'already present'
        cmd('transfer','sender.ck','root','first.request',cmd('public-key',seed=2),net,'retry-wallet','conflict-after-reopen',seed=1,reject='conflicting decision')
        cmd('transfer','sender.ck','root','fork.request',public,net,'retry-wallet','retried',seed=1)
        cmd('transfer','sender.ck','root','fork.request',public,net,'rolled-back-sender','fork',seed=1)
        assert (work/'retried').read_bytes() == (work/'fork').read_bytes()
        signer = cmd('public-key',seed=1)
        evidence = cmd('verify-conflict','last','fork')
        assert 'signer='+signer in evidence and 'request_a=' in evidence and 'request_b=' in evidence
        cmd('verify-conflict','last','first',reject='no conflicting signed requests')
        cmd('verify-conflict','last','last',reject='no conflicting signed requests')
        cmd('accept','fork.wallet.ck','fork','fork.request',net,'fork.wallet',seed=4)
        cmd('accept','last.wallet.ck','last','fork.request',net,'last.wallet',seed=3,reject='retained request')
        cmd('request','last.wallet.ck','root',net+1,'last.wallet','wrong-amount',seed=3,reject='amount')
        cmd('redeem','last.wallet.ck','last',payout,net,'last.wallet','wrong-key',seed=1,reject='current holder')
        cmd('request','sender.ck','last',net,'last.wallet','wrong-checkpoint',seed=3,reject='authentication failed')
        cmd('refresh','node','last',index,'refreshed')
        signed = cmd('redeem','last.wallet.ck','refreshed',payout,net,'last.wallet','win.tx',seed=3,measure=2).split('=')[1]
        lost = cmd('redeem','fork.wallet.ck','fork',alternate,net,'fork.wallet','lose.tx',seed=4).split('=')[1]
        def confirm(db, packet='last', invoice='last.request', address=payout, amount=net, *args, **options):
            return cmd('confirm', db, packet, invoice, address, amount, *args, **options)
        def online(port=rpc, packet='last', invoice='last.request', address=payout, amount=net, *args, **options):
            return cmd('confirm-online', '--rpc', addr(port), packet, invoice, address, amount, *args, **options)
        confirm('node', reject='no confirmed settlement')
        assert 'status=funded_unsettled' in cmd('status','node','last')
        running = start('settle',False)
        # Submit the maximum-depth claim first to exercise ordinary RPC admission.
        assert cmd('submit','long.tx','--rpc',addr(rpc)).endswith(long_claim)
        cmd('submit','win.tx','--rpc',addr(rpc),reject='replacement')
        STOP(running[0])
        running = start('settle-short',False)
        assert cmd('submit','win.tx','--rpc',addr(rpc)).endswith(signed)
        online(reject='no confirmed settlement')
        cmd('submit','lose.tx','--rpc',addr(rpc),reject='replacement')
        # Keep the node and its mempool alive while starting the pool and miner.
        p = launch(pool, 'pool-settle','--node',addr(templates),'--bind',addr(mining),'--api-bind',addr(health),'--pool-state-dir',work/'pool','--payout-mode','solo')
        WAIT(f'http://{addr(health)}/healthz',[p])
        m = launch(miner,'miner-settle','--threads','1','--no-accelerator','--pool',addr(mining),'--wallet-address',miner_addr)
        confirmed = WAIT(base+'/tx/'+signed, [*running,p,m]); STOP(m); STOP(p)
        STOP(running[0]); running=start('reopen',False)
        cmd('submit','lose.tx','--rpc',addr(rpc),reject='already spent')
        cmd('submit','win.tx','--rpc',addr(rpc),reject='already spent')
        balance = json.loads(pay('balance',addr(rpc),seed=3))
        losing = json.loads(pay('balance',addr(rpc),seed=4))
        assert balance['balance'] == net and losing['balance'] == 0
        assert [o['received_tx_hash'] for o in balance['outputs']] == [signed]
        first_tip = WAIT(base+'/info',running)
        live_receipt = online()
        for _ in range(2):
            online(rpc, 'fork', 'fork.request', alternate, net, '--save-settlement', 'observed.tx', reject='signer='+signer)
        assert (work/'observed.tx').read_bytes() == (work/'win.tx').read_bytes()
        assert 'signer='+signer in cmd('verify-conflict','fork','observed.tx','--settlement')
        cmd('verify-conflict','last','observed.tx','--settlement',reject='no conflicting signed requests')
        former_holder = 'redeemed_and_delegated_by=' + cmd('public-key',seed=3)
        online(packet=offer, invoice=request, address=last_address, reject=former_holder)
        assert former_holder in cmd('verify-conflict',offer,'observed.tx','--settlement')
        online(invoice='fork.request', reject='retained request')
        online(amount=net+1, reject='expected amount')
        online(address=alternate, reject='expected payout address')
        online(rpc, 'last', 'last.request', payout, net, '--min-confirmations', first_tip['height']+1,
               reject='insufficient settlement confirmations')
        STOP(running[0]); cmd('checkpoint','node','settled.ck','fork.wallet')
        assert 'status=confirmed ' in cmd('status','node','last','--expected-tx',signed)
        verified = confirm('node')
        assert verified == live_receipt
        assert 'transaction='+signed in verified and f'net_atomic={net}' in verified
        assert confirm('node') == verified
        depth = int(re.search(r'\bconfirmations=(\d+)', verified)[1])
        confirm('node', 'last', 'last.request', payout, net, '--min-confirmations', depth+1,
                reject='insufficient settlement confirmations')
        confirm('node', invoice='fork.request', reject='retained request')
        confirm('node', amount=net+1, reject='expected amount')
        confirm('node', address=alternate, reject='expected payout address')
        confirm('node', 'fork', 'fork.request', alternate, reject='competing receipt')
        assert 'status=conflicting_claim_confirmed ' in cmd('status','node','fork','--expected-tx',signed)
        assert 'status=conflicting_claim_confirmed ' in cmd('status','node','fork','--expected-tx',lost)
        cmd('checkpoint','fork.wallet-node','old.ck','fork.wallet',reject='regress')
        cmd('request','fork.wallet.ck','fork',net,'fork.wallet','replaced',seed=4,reject='wallet pin')
        cmd('request','settled.ck','fork',net,'fork.wallet','spent',seed=4,reject='already settled')
        history('node','--export-history','settled.archive')
        replay_report = history('independent-settlement','--replay-history','settled.archive').splitlines()[-1]
        assert cmd('status','node','last','--expected-tx',signed) == cmd('status','independent-settlement','last','--expected-tx',signed)

        # Start a disconnected node at the common funded parent and settle the other branch.
        other = start('other',False,data_dir='sender-node')[0]
        assert cmd('submit','lose.tx','--rpc',addr(rpc)).endswith(lost)
        other_pool = launch(pool,'pool-other','--node',addr(templates),'--bind',addr(mining),'--api-bind',addr(health),'--pool-state-dir',work/'pool-other','--payout-mode','solo')
        WAIT(f'http://{addr(health)}/healthz',[other,other_pool])
        other_miner = launch(miner,'miner-other','--threads','1','--no-accelerator','--pool',addr(mining),'--wallet-address',miner_addr)
        WAIT(base+'/tx/'+lost,[other,other_pool,other_miner])
        deadline = time.monotonic()+120
        while int(WAIT(base+'/info',[other,other_pool,other_miner])['cumulative_difficulty']) <= int(first_tip['cumulative_difficulty']):
            if time.monotonic() > deadline: raise TimeoutError('waiting for heavier competing settlement history')
            time.sleep(.2)
        STOP(other_miner); STOP(other_pool)
        heavier = WAIT(base+'/info',[other])
        original = join_peer('rejoin', 'node', 'other', other, heavier['tip_hash'])
        reverted = json.loads(pay('balance',addr(peer_rpc),seed=3))['balance']
        adopted = json.loads(pay('balance',addr(peer_rpc),seed=4))['balance']
        assert reverted == 0 and adopted == net
        online(peer_rpc, reject='signer='+signer)
        live_adopted = online(peer_rpc, 'fork', 'fork.request', alternate)
        overwritten = subprocess.run([offline, 'confirm-online', '--rpc', addr(peer_rpc), 'fork', 'fork.request', alternate,
                                      str(net), '--save-settlement', 'observed.tx'], cwd=work, capture_output=True)
        assert overwritten.returncode and (work/'observed.tx').read_bytes() == (work/'win.tx').read_bytes()
        STOP(original); STOP(other)
        assert 'status=conflicting_claim_confirmed ' in cmd('status','node','last','--expected-tx',signed)
        assert 'status=confirmed ' in cmd('status','node','fork','--expected-tx',lost)
        confirm('node', reject='competing receipt')
        adopted_receipt = confirm('node', 'fork', 'fork.request', alternate)
        assert adopted_receipt == live_adopted
        assert 'transaction='+lost in adopted_receipt
        history('node','--export-history','reorg.archive')
        reorg_replay = history('independent-reorg','--replay-history','reorg.archive').splitlines()[-1]
        assert f"final_hash={heavier['tip_hash']}" in reorg_replay
        # Spend the adopted payout with the ordinary wallet, including a change output.
        running = start('spend')
        outgoing = net - 2 * fee
        spend = pay('prepare',addr(rpc),pay('address',seed=5),outgoing,fee,'ordinary-spend.tx',seed=4)
        assert pay('submit',addr(rpc),'ordinary-spend.tx') == spend
        WAIT(base+'/tx/'+spend,running)
        for process in reversed(running[1:]): STOP(process)
        change = json.loads(pay('balance',addr(rpc),seed=4))['balance']
        received = json.loads(pay('balance',addr(rpc),seed=5))['balance']
        assert change == fee and received == outgoing
        STOP(running[0])

        # Reconfirm the saved funding transaction at a later output index on a fresh branch.
        history('later-funding', '--replay-history', 'before-funding.archive')
        running = start('later', data_dir='later-funding')
        deadline = time.monotonic() + 150
        while True:
            later_tip = WAIT(base+'/info', running)
            if later_tip['height'] >= location['block_height'] and int(later_tip['cumulative_difficulty']) > int(first_tip['cumulative_difficulty']):
                break
            if time.monotonic() > deadline:
                raise TimeoutError('waiting for a heavier history before reconfirmation')
            time.sleep(.2)
        assert pay('submit', addr(rpc), 'funding.tx') == fund_hash
        moved = WAIT(base+'/tx/'+fund_hash, running)
        for process in reversed(running[1:]): STOP(process)
        moved_tip = WAIT(base+'/info', running[:1])
        joined = join_peer('relocated', 'independent-settlement', 'later', running[0], moved_tip['tip_hash'])
        assert json.loads(pay('balance', addr(peer_rpc), seed=3))['balance'] == 0
        online(peer_rpc, reject='no confirmed settlement')
        STOP(joined); STOP(running[0])
        moved_index = int(cmd('locate', 'independent-settlement', fund_hash))
        assert moved_index > index and moved['block_height'] > location['block_height']
        assert 'funding_absent_at_index' in cmd('status', 'independent-settlement', 'last')
        cmd('refresh', 'independent-settlement', 'last', moved_index, 'moved.packet')
        cmd('checkpoint', 'independent-settlement', 'moved.ck', 'last.wallet')
        assert 'new=false' in cmd('accept', 'moved.ck', 'moved.packet', 'last.request', net, 'last.wallet', seed=3)
        moved_claim = cmd('redeem', 'moved.ck', 'moved.packet', payout, net, 'last.wallet', 'moved.tx', seed=3).split('=')[1]
        running = start('settle-moved', False, 'independent-settlement')
        assert cmd('submit', 'moved.tx', '--rpc', addr(rpc)).endswith(moved_claim)
        running = start_mining('settle-moved', running[0])
        moved_settlement = WAIT(base+'/tx/'+moved_claim, running)
        for process in reversed(running[1:]): STOP(process)
        assert json.loads(pay('balance', addr(rpc), seed=3))['balance'] == net
        live_relocated = online()
        STOP(running[0])
        history('independent-settlement', '--export-history', 'relocated.archive')
        moved_report = history('relocated-replay', '--replay-history', 'relocated.archive').splitlines()[-1]
        moved_status = cmd('status', 'independent-settlement', 'moved.packet', '--expected-tx', moved_claim)
        assert 'status=confirmed ' in moved_status
        assert moved_status == cmd('status', 'relocated-replay', 'moved.packet', '--expected-tx', moved_claim)
        relocated_receipt = confirm('relocated-replay')  # locally retained packet still has the old index
        assert live_relocated == relocated_receipt
        assert 'transaction='+moved_claim in relocated_receipt
        def reserve_spend(report): return re.search(r'\breserve_spend=([0-9a-f]{64})\b', report)[1]
        assert reserve_spend(verified) == reserve_spend(adopted_receipt) == reserve_spend(relocated_receipt)
        result = dict(funding=fund_hash, funding_height=location['block_height'], reserve_index=index,
                      unfunded_wallets_rejected=len(empty_wallets), verified_receipt=verified,
                       adopted_receipt=adopted_receipt, relocated_receipt=relocated_receipt, conflict_evidence=evidence,
                      locked=funding, fee=fee, winner=signed, claim_height=confirmed['block_height'],
                      winner_balance=balance['balance'], conflicting_balance=losing['balance'],
                      final_replay=replay_report, measurements=measurements,
                      p2p_reorg=dict(previous_tip=first_tip['tip_hash'], new_tip=heavier['tip_hash'], winner=lost,
                                     previous_winner_balance=reverted,new_winner_balance=adopted,replay=reorg_replay),
                      ordinary_spend=dict(transaction=spend,received=received,change=change,fee=fee),
                      relocation=dict(index=moved_index, funding_height=moved['block_height'], claim=moved_claim,
                                      claim_height=moved_settlement['block_height'], replay=moved_report, balance=net),
                      max_hops_packet_bytes=(work/offer).stat().st_size, max_hops_signed_bytes=(work/'long.tx').stat().st_size,
                      packet_bytes=(work/'last').stat().st_size, signed_bytes=(work/'win.tx').stat().st_size)
        (work/'result.json').write_text(json.dumps(result,indent=2),encoding='utf-8'); print(json.dumps(result))

if __name__ == '__main__':
    main()
