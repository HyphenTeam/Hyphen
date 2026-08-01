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

async function api(path) {
  const response = await fetch(path, { headers: { Accept: 'application/json' } });
  if (!response.ok) {
    const body = await response.json().catch(() => ({ error: response.statusText }));
    throw new Error(body.error || `HTTP ${response.status}`);
  }
  return response.json();
}

function wasmRender(view, payload) {
  if (!wasm) throw new Error('Rust WASM runtime is unavailable');
  const input = textEncoder.encode(JSON.stringify(payload));
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

function loading(label) {
  content.innerHTML = `<div class="loading">${label}</div>`;
}

function showError(error) {
  const message = String(error && error.message ? error.message : error)
    .replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;').replaceAll("'", '&#39;');
  content.innerHTML = `<div class="error">${message}</div>`;
}

function routePath() {
  return (location.hash.slice(1) || '/').replace(/\/+$/, '') || '/';
}

function selectTab(name) {
  document.querySelectorAll('[data-route]').forEach(link => {
    link.classList.toggle('active', link.dataset.route === name);
  });
}

async function showHome() {
  selectTab('home');
  loading('READING CANONICAL TIP');
  const [info, blocks] = await Promise.all([
    api('/api/info'),
    api(`/api/blocks?page=${blockPage}&limit=${PAGE_SIZE}`)
  ]);
  content.innerHTML = wasmRender(0, { info, blocks });
}

async function showScience() {
  selectTab('science');
  loading('READING SCIENTIFIC WORK STATE');
  const offset = sciencePage * PAGE_SIZE;
  const tasks = await api(`/api/science/tasks?offset=${offset}&limit=${PAGE_SIZE}`);
  content.innerHTML = wasmRender(1, tasks);
}

async function showTask(id) {
  selectTab('science');
  loading('VERIFYING TASK COMMITMENTS');
  const task = await api(`/api/science/task/${encodeURIComponent(id)}`);
  content.innerHTML = wasmRender(2, task);
}

async function showBlock(id) {
  selectTab('home');
  loading('READING BLOCK AND STATE ROOTS');
  const block = await api(`/api/block/${encodeURIComponent(id)}`);
  content.innerHTML = wasmRender(3, block);
}

async function showTransaction(hash) {
  selectTab('home');
  loading('READING TRANSACTION INCLUSION');
  const transaction = await api(`/api/tx/${encodeURIComponent(hash)}`);
  content.innerHTML = wasmRender(4, transaction);
}

async function showApplications() {
  selectTab('apps');
  loading('READING WASM APPLICATION INDEX');
  const offset = appsPage * PAGE_SIZE;
  const applications = await api(`/api/apps?offset=${offset}&limit=${PAGE_SIZE}`);
  content.innerHTML = wasmRender(5, applications);
}

async function showApplication(address) {
  selectTab('apps');
  loading('READING IMMUTABLE CONTRACT METADATA');
  const application = await api(`/api/app/${encodeURIComponent(address)}`);
  content.innerHTML = wasmRender(6, application);
}

async function route() {
  clearTimeout(refreshTimer);
  const path = routePath();
  try {
    if (path === '/') {
      await showHome();
      refreshTimer = setTimeout(() => route().catch(showError), 15000);
    } else if (path === '/science') {
      await showScience();
    } else if (path.startsWith('/science/task/')) {
      await showTask(path.slice('/science/task/'.length));
    } else if (path.startsWith('/block/')) {
      await showBlock(path.slice('/block/'.length));
    } else if (path.startsWith('/tx/')) {
      await showTransaction(path.slice('/tx/'.length));
    } else if (path === '/apps') {
      await showApplications();
    } else if (path.startsWith('/app/')) {
      await showApplication(path.slice('/app/'.length));
    } else {
      throw new Error('Unknown explorer route');
    }
  } catch (error) {
    showError(error);
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
  route().catch(showError);
});

document.getElementById('searchForm').addEventListener('submit', async event => {
  event.preventDefault();
  const query = document.getElementById('searchInput').value.trim();
  if (!query) return;
  loading('RESOLVING CHAIN OBJECT');
  try {
    const result = await api(`/api/search?q=${encodeURIComponent(query)}`);
    if (result.result_type === 'block') location.hash = `/block/${result.hash || result.height}`;
    else if (result.result_type === 'tx') location.hash = `/tx/${result.hash}`;
    else if (result.result_type === 'science_task') location.hash = `/science/task/${result.hash}`;
    else if (result.result_type === 'app') location.hash = `/app/${result.hash}`;
    else throw new Error('No matching public chain object');
  } catch (error) {
    showError(error);
  }
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
