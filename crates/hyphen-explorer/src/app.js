'use strict';

const PAGE_SIZE = 20;
const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();
const content = document.getElementById('content');
const wasmState = document.getElementById('wasmState');
let wasm = null;
let blockPage = 0;
let sciencePage = 0;
let appsPage = 0;
let refreshTimer = null;
let stackPage = 0;
const stackView = { angle: '35', hash: null };
// Keep the tab's last public block selection across reloads without writing on every input.
const stackStorageKey = 'hyphen.explorer.stack.v1';
try {
  const saved = JSON.parse(sessionStorage.getItem(stackStorageKey));
  if (saved && Number.isSafeInteger(saved.page) && saved.page >= 0 && /^[0-9a-f]{64}$/.test(saved.hash) &&
      Number.isInteger(saved.angle) && Math.abs(saved.angle) <= 180) {
    stackPage = saved.page;
    stackView.hash = saved.hash;
    stackView.angle = String(saved.angle);
  }
} catch { /* Unavailable session storage or an obsolete tab record. */ }
window.addEventListener('pagehide', () => {
  if (!stackView.hash) return;
  try {
    sessionStorage.setItem(stackStorageKey, JSON.stringify({ page: stackPage, hash: stackView.hash, angle: Number(stackView.angle) }));
  } catch { /* The current view remains usable with storage disabled. */ }
});
let activeRequest;
let disposeView;
let currentView;

async function api(path, signal) {
  const response = await fetch(path, { signal, headers: { Accept: 'application/json' } });
  if (!response.ok) {
    const body = await response.json().catch(() => ({ error: response.statusText }));
    throw new Error(body.error || `HTTP ${response.status}`);
  }
  return response;
}

function wasmRender(view, payload) {
  if (!wasm) throw new Error('Rust WASM runtime is unavailable');
  const input = textEncoder.encode(payload);
  const inputPointer = wasm.hyphen_alloc(input.length);
  new Uint8Array(wasm.memory.buffer, inputPointer, input.length).set(input);
  let packed;
  try {
    packed = wasm.hyphen_render(view, inputPointer, input.length, Date.now());
  } finally {
    wasm.hyphen_free(inputPointer, input.length);
  }
  const outputPointer = Number(packed & 0xffffffffn);
  const outputLength = Number(packed >> 32n);
  try {
    return textDecoder.decode(new Uint8Array(wasm.memory.buffer, outputPointer, outputLength));
  } finally {
    wasm.hyphen_free(outputPointer, outputLength);
  }
}

function showError(error) {
  disposeView?.();
  disposeView = undefined;
  const panel = document.createElement('div');
  panel.className = 'error';
  panel.setAttribute('role', 'alert');
  panel.textContent = error.message || String(error);
  content.replaceChildren(panel);
}

function routePath() {
  return (location.hash.slice(1) || '/').replace(/\/+$/, '') || '/';
}

async function route(animate = true) {
  if (!wasm) return;
  clearTimeout(refreshTimer);
  activeRequest?.abort();
  const { signal } = activeRequest = new AbortController();
  const path = routePath();
  const section = path === '/stack' ? 'stack' : path.startsWith('/science') ? 'science'
    : path === '/apps' || path.startsWith('/app/') ? 'apps' : 'home';
  aurora.select(section);
  content.setAttribute('aria-busy', 'true');
  const id = encodeURIComponent(path.split('/').at(-1));
  const pages = {
    '/science': [1, `/api/science/tasks?offset=${sciencePage * PAGE_SIZE}&limit=${PAGE_SIZE}`],
    '/apps': [5, `/api/apps?offset=${appsPage * PAGE_SIZE}&limit=${PAGE_SIZE}`],
  };
  const detail = [[ '/science/task/', 2, '/api/science/task/' ], [ '/block/', 3, '/api/block/' ],
    [ '/tx/', 4, '/api/tx/' ], [ '/app/', 6, '/api/app/' ]].find(([prefix]) => path.startsWith(prefix));
  try {
    let html, stack;
    if (path === '/') {
      const [info, blocks] = await Promise.all(['/api/info', `/api/blocks?page=${blockPage}&limit=${PAGE_SIZE}`]
        .map(async url => (await api(url, signal)).text()));
      // Preserve the server's integer tokens until Rust deserializes the view.
      html = wasmRender(0, `{"info":${info},"blocks":${blocks}}`);
    } else if (path === '/stack') {
      stack = await (await api(`/api/blocks?page=${stackPage}&limit=${PAGE_SIZE}&branches=1`, signal)).json();
    } else {
      const entry = pages[path] || (detail && [detail[1], detail[2] + id]);
      if (!entry) throw new Error('Unknown explorer route');
      const payload = await api(entry[1], signal);
      html = wasmRender(entry[0], await payload.text());
    }
    if (signal.aborted) return;
    await aurora.replace(() => {
      if (signal.aborted) return;
      disposeView?.();
      disposeView = undefined;
      if (stack) disposeView = renderBlockStack(content, stack.blocks, stackPage, stack.forks, stackView);
      else content.innerHTML = html;
      currentView = path;
    }, animate && currentView !== undefined, currentView, path);
  } catch (error) {
    if (!signal.aborted) showError(error);
  } finally {
    if (!signal.aborted) {
      content.setAttribute('aria-busy', 'false');
      if (path === '/' && !document.hidden) refreshTimer = setTimeout(() => route(false), 15000);
    }
  }
}

content.addEventListener('click', event => {
  const button = event.target.closest('[data-action]');
  if (!button || button.disabled) return;
  if (button.dataset.action === 'older') blockPage += 1;
  if (button.dataset.action === 'newer') blockPage = Math.max(0, blockPage - 1);
  if (button.dataset.action === 'science-older') sciencePage += 1;
  if (button.dataset.action === 'science-newer') sciencePage = Math.max(0, sciencePage - 1);
  if (button.dataset.action === 'apps-older') appsPage += 1;
  if (button.dataset.action === 'apps-newer') appsPage = Math.max(0, appsPage - 1);
  if (button.dataset.action === 'stack-older') stackPage += 1;
  if (button.dataset.action === 'stack-newer') stackPage = Math.max(0, stackPage - 1);
  route().catch(showError);
});

document.getElementById('searchForm').addEventListener('submit', async event => {
  event.preventDefault();
  const query = document.getElementById('searchInput').value.trim();
  if (!query) return;
  activeRequest?.abort();
  clearTimeout(refreshTimer);
  const { signal } = activeRequest = new AbortController();
  content.setAttribute('aria-busy', 'true');
  try {
    const result = await (await api(`/api/search?q=${encodeURIComponent(query)}`, signal)).json();
    if (signal.aborted) return;
    const prefix = {block: '/block/', tx: '/tx/', science_task: '/science/task/', app: '/app/'}[result.result_type];
    if (!prefix) throw new Error('No matching public chain object');
    const next = prefix + encodeURIComponent(result.hash || result.height);
    if (next === routePath()) await route(false);
    else location.hash = next;
  } catch (error) {
    if (!signal.aborted) showError(error);
  } finally {
    if (!signal.aborted) content.setAttribute('aria-busy', 'false');
  }
});

document.addEventListener('visibilitychange', () => {
  clearTimeout(refreshTimer);
  if (!document.hidden && routePath() === '/') route(false);
});

window.addEventListener('hashchange', () => route().catch(showError));

async function boot() {
  const response = await fetch('/hyphen_explorer_web.wasm');
  if (!response.ok) throw new Error(`WASM load failed: HTTP ${response.status}`);
  const instance = await WebAssembly.instantiateStreaming(response, {});
  wasm = instance.instance.exports;
  for (const name of ['memory', 'hyphen_alloc', 'hyphen_free', 'hyphen_render']) {
    if (!(name in wasm)) throw new Error(`WASM ABI export missing: ${name}`);
  }
  wasmState.textContent = 'WASM ACTIVE';
  wasmState.classList.add('ready');
  await route();
}

boot().catch(showError);
