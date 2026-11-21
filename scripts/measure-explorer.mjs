// Run with Node 22+ and Chrome. Both URLs must serve the same stopped-mining history.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';

const [chrome, baseline, updated, applications] = process.argv.slice(2);
if (!updated) throw Error('Usage: node measure-explorer.mjs CHROME BASELINE_URL UPDATED_URL [APPLICATION_HISTORY_URL]');
const profile = await mkdtemp(join(tmpdir(), 'hyphen-render-'));
const proc = spawn(chrome, ['--headless=new', '--remote-debugging-port=0', '--no-first-run',
  '--disable-extensions', '--disable-features=BackForwardCache', `--user-data-dir=${profile}`, '--window-size=1280,800', 'about:blank'],
{ stdio: ['ignore', 'ignore', 'pipe'] });
const closed = once(proc, 'close');
try {
  const devtools = await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(Error('Chrome startup timed out')), 15000);
    proc.stderr.on('data', chunk => {
      const match = String(chunk).match(/DevTools listening on ws:\/\/(127\.0\.0\.1:\d+)/);
      if (match) { clearTimeout(timer); resolve(`http://${match[1]}`); }
    });
  });
  const [page] = (await (await fetch(`${devtools}/json/list`)).json()).filter(t => t.type === 'page');
  const socket = new WebSocket(page.webSocketDebuggerUrl);
  await once(socket, 'open');
  let serial = 0;
  const calls = new Map();
  const errors = [];
  socket.addEventListener('message', ({data}) => {
    const msg = JSON.parse(data);
    if (msg.id) { calls.get(msg.id)?.(msg); calls.delete(msg.id); }
    if (msg.method === 'Runtime.exceptionThrown') errors.push(msg.params.exceptionDetails.text);
  });
  async function send(method, params = {}) {
    const id = ++serial;
    const pending = new Promise(resolve => calls.set(id, resolve));
    socket.send(JSON.stringify({id, method, params}));
    const res = await pending;
    if (res.error) throw Error(JSON.stringify(res.error));
    return res.result;
  }
  async function evaluate(expression) {
    const r = await send('Runtime.evaluate', {expression, returnByValue: true, awaitPromise: true});
    if (r.exceptionDetails) throw Error(r.exceptionDetails.exception?.description || r.exceptionDetails.text);
    return r.result.value;
  }
  async function until(expression) {
    const end = Date.now() + 10000;
    while (!await evaluate(expression)) {
      if (Date.now() > end) throw Error(`Timed out waiting for ${expression}`);
      await delay(25);
    }
  }
  await send('Runtime.enable');
  await send('Page.enable');
  await send('Page.addScriptToEvaluateOnNewDocument', {source: `
    window.measure = {draws:0, reallocations:0, transitions:0};
    const original = CanvasRenderingContext2D.prototype.setTransform;
    CanvasRenderingContext2D.prototype.setTransform = function(...args) {
      ++measure.draws; return original.apply(this, args);
    };
    for (const key of ['width','height']) {
      const d = Object.getOwnPropertyDescriptor(HTMLCanvasElement.prototype,key);
      Object.defineProperty(HTMLCanvasElement.prototype,key,{...d,set(v){++measure.reallocations;d.set.call(this,v)}});
    }
    const switchView = document.startViewTransition.bind(document);
    function taggedObject() {
      const el = document.querySelector('[style*="chain-object"]');
      return el && { tag: el.tagName, text: el.textContent };
    }
    document.startViewTransition = update => {
      ++measure.transitions;
      const old = taggedObject();
      const run = switchView(update);
      window.measuredPassage = run.ready.then(async () => {
        const next = taggedObject();
        const animated = document.getAnimations().some(animation =>
          animation.effect?.pseudoElement === '::view-transition-group(chain-object)' ||
          animation.animationName?.includes('chain-object'));
        await run.finished;
        return {old, next, animated};
      }).catch(() => null);
      return run;
    };
  `});
  const results = {};
  for (const [label, url] of Object.entries({baseline, updated})) {
    await send('Page.navigate', {url: new URL('/#/stack', url).href});
    await until(`location.origin === ${JSON.stringify(new URL(url).origin)} && document.querySelector('.stack-tools code')?.textContent.length === 64`);
    await delay(300);
    if (label === 'updated') {
      await evaluate(`(() => { const layout=document.querySelector('.stack-layout-choice'); window.initialLayout=layout.value; layout.value='grid'; layout.dispatchEvent(new Event('change')); return new Promise(resolve=>requestAnimationFrame(()=>resolve(true))); })()`);
    }
    results[label] = await evaluate(`(async () => {
      const before = {...measure}, slider = document.querySelector('.stack-tools input');
      const start = performance.now();
      for (let i=0;i<120;i++) {slider.value = i; slider.dispatchEvent(new Event('input'));}
      const dispatchMs = performance.now()-start;
      await new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)));
      const draws = measure.draws-before.draws, reallocations = measure.reallocations-before.reallocations;
      const idle = measure.draws; await new Promise(r => setTimeout(r, 500));
      const windowData = await (await fetch('/api/blocks?branches=1&limit=20')).json();
      return {tip:windowData.blocks[0].hash, options:document.querySelector('select').length, draws,
        reallocations, dispatchMs, idleDraws:measure.draws-idle};
    })()`);
    assert.equal(results[label].idleDraws, 0);
    await send('HeapProfiler.collectGarbage');
    results[label].heap = await send('Runtime.getHeapUsage');
    results[label].canvasBytes = await evaluate(`document.querySelector('canvas').width * document.querySelector('canvas').height * 4`);
  }
  const geometry = await evaluate(`(async () => {
    const data = await (await fetch('/api/blocks?branches=1&limit=20')).json();
    const layout = document.querySelector('.stack-layout-choice');
    layout.value=window.initialLayout; layout.dispatchEvent(new Event('change'));
    await new Promise(resolve => requestAnimationFrame(resolve));
    const blocks = data.blocks.concat(data.forks.blocks);
    const cards = new Map(Array.from(document.querySelectorAll('.chain-block'), c=>[c.dataset.hash,c]));
    const expected = blocks.filter(b=>cards.has(b.prev_hash));
    const edges = Array.from(document.querySelectorAll('.chain-edge'));
    const exact = edges.length === expected.length && expected.every(b=>{
      const edge = edges.find(e=>e.dataset.child===b.hash && e.dataset.parent===b.prev_hash);
      if (!edge) return false;
      const box=edge.getBoundingClientRect(), child=cards.get(b.hash).getBoundingClientRect(), parent=cards.get(b.prev_hash).getBoundingClientRect();
      const centers=[child.y+child.height/2,parent.y+parent.height/2];
      return Math.abs(box.left-child.right)<1 && Math.abs(box.right-parent.left)<1 &&
        Math.abs(box.top-Math.min(...centers))<2 && Math.abs(box.bottom-Math.max(...centers))<=2;
    });
    const selectable = blocks.every(b=>{const c=cards.get(b.hash); if (!c) return false; c.click();
      return c.getAttribute('aria-pressed')==='true' && document.querySelector('.stack-tools code').textContent===b.hash;});
    return {layout:layout.value, edges:edges.length, exact, selectable, nodes:cards.size, expectedNodes:blocks.length};
  })()`);
  assert.equal(geometry.layout, 'chain'); assert.equal(geometry.nodes, geometry.expectedNodes);
  assert.ok(geometry.selectable && geometry.exact && geometry.edges > 0, JSON.stringify(geometry));
  results.chainGeometry = geometry;
  await evaluate(`(() => { const layout=document.querySelector('.stack-layout-choice'); layout.value='grid'; layout.dispatchEvent(new Event('change')); return new Promise(resolve=>requestAnimationFrame(()=>resolve(true))); })()`);
  assert.equal(results.baseline.tip, results.updated.tip);
  assert.equal(results.baseline.options, results.updated.options);
  assert.equal(results.updated.draws, 1);
  assert.equal(results.updated.reallocations, 0);
  const oldTip = await evaluate(`(() => { const s=document.querySelector('select');
    const opt=Array.from(s.options).find(o=>o.text.includes('Validated fork')); s.value=opt.value;
    s.dispatchEvent(new Event('change')); return s.value; })()`);
  await evaluate(`location.hash='/block/${oldTip}'`);
  await until(`document.querySelector('h1')?.textContent.startsWith('Height') && document.querySelector('main').textContent.includes('Validated fork')`);
  const toDetail = await evaluate('window.measuredPassage');
  assert.deepEqual(toDetail.old, {tag:'CODE', text:oldTip});
  assert.equal(toDetail.next.tag, 'H1');
  assert.ok(toDetail.animated);
  const threshold = await evaluate(`Array.from(document.querySelectorAll('dt')).find(e=>e.textContent==='Work threshold').nextElementSibling.textContent`);
  const header = await (await fetch(new URL('/api/block/' + oldTip, updated))).text();
  assert.equal(threshold.replaceAll(',', ''), JSON.parse(header, (k,v,ctx)=>k==='difficulty' ? ctx.source : v).header.difficulty);
  await evaluate(`location.hash='/stack'`);
  await until(`document.querySelector('select')?.value==='${oldTip}'`);
  const toStack = await evaluate('window.measuredPassage');
  assert.deepEqual(toStack.old, toDetail.next);
  assert.deepEqual(toStack.next, toDetail.old);
  assert.ok(toStack.animated);
  assert.equal(await evaluate(`document.querySelector('.stack-tools input').value`), '119');
  await evaluate(`(() => { const network=window.fetch; window.fetch = async (...args) => {
    if (String(args[0]).includes('/api/science/tasks')) await new Promise(r=>setTimeout(r,400));
    return network(...args);
  }; location.hash='/science'; })()`);
  await until(`document.querySelector('main').getAttribute('aria-busy') === 'true'`);
  assert.equal(await evaluate(`document.querySelector('h1').textContent`), 'Block stack');
  await evaluate(`location.hash='/apps'`);
  await until(`document.querySelector('h1')?.textContent === 'On-chain applications'`);
  await delay(500);
  assert.equal(await evaluate(`document.querySelector('h1').textContent`), 'On-chain applications');
  await send('Emulation.setEmulatedMedia', {features:[{name:'prefers-reduced-motion',value:'reduce'}]});
  const count = await evaluate('measure.transitions');
  assert.ok(count > 0);
  await evaluate(`location.hash='/stack'`);
  await until(`document.querySelector('h1')?.textContent === 'Block stack'`);
  assert.equal(await evaluate('measure.transitions'), count);
  await delay(200);
  const other = await send('Target.createTarget', {url:'about:blank'});
  await send('Target.activateTarget', {targetId:other.targetId});
  await until('document.hidden');
  const hiddenStart = await evaluate('measure.draws');
  await evaluate(`document.querySelector('.stack-tools input').dispatchEvent(new Event('input'))`);
  await delay(500);
  assert.equal(await evaluate('measure.draws'), hiddenStart);
  await send('Target.activateTarget', {targetId:page.id});
  await until(`!document.hidden && measure.draws > ${hiddenStart}`);
  await send('Target.closeTarget', {targetId:other.targetId});
  await send('Page.reload', {ignoreCache:true});
  await until(`performance.getEntriesByType('navigation')[0]?.type==='reload' && document.querySelector('select')?.value==='${oldTip}'`);
  assert.equal(await evaluate(`document.querySelector('.stack-tools input').value`), '119');
  results.controlWidths = [];
  for (const width of [390, 1280]) {
    await send('Emulation.setDeviceMetricsOverride', {width, height:800, deviceScaleFactor:1, mobile:false});
    await until(`innerWidth === ${width}`);
    const fits = await evaluate(`(() => {
      const panel=document.querySelector('.stack-tools'), bounds=panel.getBoundingClientRect();
      return bounds.right <= innerWidth && panel.scrollWidth <= panel.clientWidth &&
        Array.from(panel.querySelectorAll('select, input, code, output, button, a')).every(el => {
          const r=el.getBoundingClientRect(); return !el.getClientRects().length || (r.left >= bounds.left && r.right <= bounds.right);
        });
    })()`);
    assert.ok(fits, 'Stack controls exceed the panel at width ' + width);
    assert.ok(await evaluate(`(() => {
      const layout=document.querySelector('.stack-layout-choice'); layout.value='chain'; layout.dispatchEvent(new Event('change'));
      const region=document.querySelector('.chain-scroll'), cards=[...region.querySelectorAll('button')];
      return region.scrollWidth>region.clientWidth && document.documentElement.scrollWidth<=innerWidth && cards.every(card=>{
        document.querySelector('.stack-tools select').value=card.dataset.hash;
        document.querySelector('.stack-tools select').dispatchEvent(new Event('change'));
        const box=card.getBoundingClientRect(), frame=region.getBoundingClientRect();
        return box.width>=120 && box.left>=frame.left-1 && box.right<=frame.left+region.clientWidth+1;
      });
    })()`), 'Block selection must reveal its card at width ' + width);
    results.controlWidths.push(width);
  }
  await send('Emulation.clearDeviceMetricsOverride');
  if (applications) {
    await send('Emulation.setEmulatedMedia', {features:[]});
    const pairs = [];
    const blockPage = await (await fetch(new URL('/api/blocks?limit=20', applications))).json();
    const containingBlock = blockPage.blocks.find(block => block.tx_count > 0);
    assert.ok(containingBlock, 'Application history needs a block containing a transaction');
    for (const [list, prefix, container] of [
      ['/', '/block/', 'tbody'], ['/apps', '/app/', 'tbody'], ['/science', '/science/task/', 'tbody'],
      ['/block/' + containingBlock.hash, '/tx/', '.object-list'],
    ]) {
      await send('Page.navigate', {url:new URL('/#' + list, applications).href});
      const link = `document.querySelector('main ${container} a[href^="#${prefix}"]')`;
      await until(`location.origin === ${JSON.stringify(new URL(applications).origin)} && !!${link}`);
      const objectText = await evaluate(`${link}.textContent`);
      const hash = await evaluate(`(() => { const a=${link}; a.click(); return a.hash; })()`);
      await until(`location.hash===${JSON.stringify(hash)} && document.querySelector('main')?.getAttribute('aria-busy') === 'false' && !${link} && !!window.measuredPassage`);
      const forward = await evaluate('window.measuredPassage');
      assert.ok(forward.animated && forward.old.tag === 'A' && forward.next.tag === 'H1');
      assert.equal(forward.old.text, objectText);
      if (prefix === '/science/task/' || prefix === '/app/') {
        const object = await (await fetch(new URL('/api' + hash.slice(1), applications))).json();
        const fields = await evaluate(`Object.fromEntries([...document.querySelectorAll('main article:first-of-type dt')].map(dt=>[dt.textContent,dt.nextElementSibling.textContent]))`);
        if (prefix === '/science/task/') {
          const status = await evaluate(`document.querySelector('main .status').textContent`);
          assert.equal(status, object.status);
          assert.equal(fields['Task ID'], object.task_id);
          assert.equal(fields.Published, '#' + object.published_height);
          if (object.finalized_height != null) assert.equal(fields.Finalized, '#' + object.finalized_height);
          assert.equal(fields["Publisher's declared reward"], object.reward + ' HPN');
        } else {
          assert.equal(fields.Contract, object.address);
          assert.equal(fields['Code hash'], object.code_hash);
          assert.equal(fields.Deployer, object.deployer);
          assert.equal(fields.Deployed, '#' + object.deployed_height);
        }
      }
      if (prefix === '/tx/') {
        const transactionId = hash.slice(('#' + prefix).length);
        assert.match(transactionId, /^[0-9a-f]{64}$/);
        assert.ok(objectText.includes(transactionId));
        const detailId = await evaluate(`Array.from(document.querySelectorAll('dt')).find(e => e.textContent === 'Transaction hash').nextElementSibling.textContent`);
        assert.equal(detailId, transactionId);
      }
      await evaluate('history.back()');
      await until(`!!${link}`);
      const back = await evaluate('window.measuredPassage');
      assert.ok(back.animated);
      assert.deepEqual(back.old, forward.next);
      assert.deepEqual(back.next, forward.old);
      pairs.push({list, detail:hash, heading:forward.next.text});
    }
    results.listDetailRoundTrips = pairs;
    results.canonicalLists = [];
    for (const [origin, populated] of [[updated, false], [applications, true]]) {
      for (const [path, endpoint, items] of [['/apps', '/api/apps', 'contracts'], ['/science', '/api/science/tasks', 'tasks']]) {
        await send('Page.navigate', {url:new URL('/#' + path, origin).href});
        const heading = path === '/apps' ? 'On-chain applications' : 'Verifiable scientific work';
        await until(`location.origin === ${JSON.stringify(new URL(origin).origin)} && location.hash === ${JSON.stringify('#' + path)} && document.querySelector('h1')?.textContent === ${JSON.stringify(heading)} && document.querySelector('[data-tip]') && document.querySelector('main').getAttribute('aria-busy') === 'false'`);
        const observed = await evaluate(`(async () => {
          const url = ${JSON.stringify(endpoint)};
          const body = await (await fetch(url + '?limit=20')).json();
          const tag = document.querySelector('[data-tip]');
          const checked = await fetch(url + '?limit=20&known_tip=' + tag.dataset.tip);
          await route(false);
          return {height:body.chain.height, tip:tag.dataset.tip, matches:tag.dataset.tip === body.chain.tip_hash,
            total:body.total, entries:body[${JSON.stringify(items)}].length, rows:document.querySelectorAll('main tbody tr').length,
            status:checked.status, preserved:tag === document.querySelector('[data-tip]')};
        })()`);
        assert.ok(observed.matches && observed.preserved, JSON.stringify({path, origin, observed}));
        assert.equal(observed.status, 204);
        assert.equal(observed.total > 0, populated);
        assert.equal(observed.rows, observed.entries);
        // Restore a stale page offset as can happen when a reorg shortens the list.
        const pageVariable = path === '/apps' ? 'appsPage' : 'sciencePage';
        const restored = await evaluate(`(async () => { ${pageVariable} = Math.ceil(${observed.total} / PAGE_SIZE) + 1;
          await route(false); return {page:${pageVariable}, rows:document.querySelectorAll('main tbody tr').length}; })()`);
        assert.equal(restored.page, Math.max(0, Math.ceil(observed.total / 20) - 1));
        assert.equal(restored.rows, observed.rows);
        results.canonicalLists.push({path, ...observed, restoredPage:restored.page});
      }
    }
  }
  assert.deepEqual(errors, []);
  console.log(JSON.stringify({...results, chrome:(await send('Browser.getVersion')).product,
    fork:oldTip, toDetail, toStack, threshold, rapidNavigation:true, reducedMotion:true, hiddenDraws:0,
    resumed:true, reloadSelection:true, pageErrors:errors}, null, 2));
  socket.close();
} finally {
  proc.kill();
  await closed;
  await rm(profile, {recursive:true, force:true, maxRetries:10, retryDelay:100});
}
