'use strict';

function renderBlockStack(container, canonical, page, forks, view) {
  container.innerHTML = `<div class="section-head"><h1>Block stack</h1></div>
    <section class="stack-layout"><canvas width="900" height="500" aria-label="Block positions and parent links"></canvas>
    <div class="stack-tools"><label>Block height<select></select></label>
    <output></output><code></code><label>View angle<input type="range" min="-180" max="180" value="35"></label>
    <a>Open block details</a><div class="stack-pager"><button data-action="stack-newer">Newer</button>
    <button data-action="stack-older">Older</button><button data-action="stack-refresh">Refresh</button></div></div></section>`;
  const canvas = container.querySelector('canvas');
  const select = container.querySelector('select');
  const angle = container.querySelector('input');
  const output = container.querySelector('output');
  const details = container.querySelector('.stack-tools a');
  container.querySelector('[data-action="stack-newer"]').disabled = page === 0;
  container.querySelector('[data-action="stack-older"]').disabled = !canonical.length || canonical.at(-1).cell.z === '0';
  if (!canonical.length) {
    output.textContent = 'No canonical blocks in this window.';
    details.hidden = true;
    return;
  }
  const blocks = canonical.concat(forks.blocks);
  const labels = { detached: 'Validated fork', staged: 'Staged body' };
  const label = block => block.recent_sibling ? 'Validated fork · recent sibling' : labels[block.status] || 'Canonical';
  const colors = { detached: '#dd95a8', staged: '#a6a7ad' };
  if (forks.truncated) container.querySelector('.stack-tools').append('Showing the first eight forks per height.');
  blocks.forEach(b => {
    select.add(new Option(`#${b.cell.z} · ${b.hash.slice(0, 8)} · ${label(b)}`, b.hash));
  });
  const index = blocks.findIndex(b => b.hash === view.hash);
  if (index >= 0) select.selectedIndex = index;
  angle.value = view.angle;
  const base = BigInt(canonical.at(-1).cell.z);
  const span = Math.max(...blocks.map(b => Number(BigInt(b.cell.z) - base)));
  const ctx = canvas.getContext('2d');
  const hashLabel = container.querySelector('.stack-tools code');
  function describe() {
    const selected = blocks[select.selectedIndex];
    view.hash = selected.hash;
    const cell = selected.cell;
    details.href = `#/block/${encodeURIComponent(selected.hash)}`;
    details.hidden = selected.status === 'staged';
    output.textContent = `X ${cell.x}  ·  Y ${cell.y}  ·  Z ${cell.z} · ${label(selected)}`;
    hashLabel.textContent = selected.hash;
  }
  function draw() {
    if (!ctx || !canvas.isConnected) return;
    const cell = blocks[select.selectedIndex].cell;
    const w = canvas.clientWidth, h = canvas.clientHeight;
    const density = Math.min(window.devicePixelRatio || 1, 2);
    const width = Math.round(w * density), height = Math.round(h * density);
    if (canvas.width !== width) canvas.width = width;
    if (canvas.height !== height) canvas.height = height;
    ctx.setTransform(density, 0, 0, density, 0, 0);
    ctx.clearRect(0, 0, w, h);
    const a = Number(angle.value) * Math.PI / 180;
    const scale = Math.min(w / 25, h / 23);
    const lift = Math.min(scale, h * 0.49 / Math.max(span, 1));
    function project(x, y, z) {
      x -= 7.5;
      y -= 7.5;
      return [w / 2 + scale * (x * Math.cos(a) - y * Math.sin(a)),
        h / 2 + span * lift / 2 + scale * 0.43 * (x * Math.sin(a) + y * Math.cos(a)) - z * lift];
    }
    function line(p, q, color) {
      ctx.strokeStyle = color;
      ctx.beginPath(); ctx.moveTo(...p); ctx.lineTo(...q); ctx.stroke();
    }
    for (let i = 0; i <= 15; i++) {
      line(project(i, 0, 0), project(i, 15, 0), '#24333a');
      line(project(0, i, 0), project(15, i, 0), '#24333a');
    }
    const level = Number(BigInt(cell.z) - base);
    if (level > 0) {
      const corners = [[0, 0], [15, 0], [15, 15], [0, 15]].map(([x, y]) => project(x, y, level));
      ctx.setLineDash([4, 6]);
      corners.forEach((p, i) => line(p, corners[(i + 1) % 4], '#464237'));
      ctx.setLineDash([]);
    }
    const points = blocks.map(b => project(b.cell.x, b.cell.y, Number(BigInt(b.cell.z) - base)));
    const byHash = new Map(blocks.map((b, i) => [b.hash, points[i]]));
    blocks.forEach((b, i) => {
      const parent = byHash.get(b.prev_hash);
      if (parent) line(points[i], parent, colors[b.status] || '#549ca9');
    });
    function face(vertices, color) {
      ctx.beginPath();
      ctx.moveTo(...vertices[0]);
      vertices.slice(1).forEach(p => ctx.lineTo(...p));
      ctx.closePath(); ctx.fillStyle = color; ctx.fill();
    }
    const ordered = blocks.map((block, i) => ({block, depth: points[i][1]})).sort((p, q) => p.depth - q.depth);
    for (const {block} of ordered) {
      const {x, y, z} = block.cell;
      const top = [[-0.32,-0.32],[0.32,-0.32],[0.32,0.32],[-0.32,0.32]].map(
        ([dx, dy]) => project(x + dx, y + dy, Number(BigInt(z) - base)));
      const bottom = top.map(([px, py]) => [px, py + scale * 0.32]);
      for (let i = 0; i < 4; i++) {
        const next = (i + 1) % 4;
        if (top[next][0] < top[i][0]) face([top[i], top[next], bottom[next], bottom[i]],
          block.status === 'detached' ? '#915f73' : block.status === 'staged' ? '#65686e' : '#397e7b');
      }
      face(top, colors[block.status] || '#79daca');
    }
    const [x, y] = points[select.selectedIndex];
    line(project(cell.x, cell.y, 0), [x, y], '#987740');
    ctx.strokeStyle = '#f1bd57'; ctx.strokeRect(x - 7, y - 7, 14, 14);
    ctx.font = '12px monospace'; ctx.fillStyle = '#f1bd57'; ctx.fillText(`#${cell.z}`, x + 10, y - 9);
  }
  const invalidate = () => aurora.schedule(draw);
  angle.addEventListener('input', () => { view.angle = angle.value; invalidate(); });
  select.addEventListener('change', () => { describe(); invalidate(); });
  const resize = new ResizeObserver(invalidate);
  resize.observe(canvas);
  describe();
  invalidate();
  return () => { resize.disconnect(); aurora.cancel(draw); };
}
