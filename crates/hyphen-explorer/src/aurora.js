'use strict';

// One demand-driven frame queue for navigation and block geometry.
const aurora = (() => {
  const pending = new Set();
  const reduced = matchMedia('(prefers-reduced-motion: reduce)');
  let frame = 0;
  function flush(time) {
    frame = 0;
    const batch = Array.from(pending);
    pending.clear();
    for (const paint of batch) paint(time);
  }
  function schedule(paint) {
    pending.add(paint);
    if (!frame && !document.hidden) frame = requestAnimationFrame(flush);
  }
  document.addEventListener('visibilitychange', () => {
    if (frame) cancelAnimationFrame(frame);
    frame = pending.size && !document.hidden ? requestAnimationFrame(flush) : 0;
  });
  const tabs = document.querySelector('.tabs');
  const indicator = document.querySelector('.tab-indicator');
  const links = Array.from(tabs.querySelectorAll('a'));
  function align() {
    const link = tabs.querySelector('[aria-current="page"]');
    if (!link) return;
    indicator.style.transform = `translateX(${link.offsetLeft}px) scaleX(${link.offsetWidth})`;
  }
  const size = new ResizeObserver(() => schedule(align));
  size.observe(tabs);
  for (const link of links) size.observe(link);
  function select(section) {
    for (const link of links) {
      const active = link.dataset.route === section;
      link.classList.toggle('active', active);
      if (active) link.setAttribute('aria-current', 'page');
      else link.removeAttribute('aria-current');
    }
    schedule(align);
  }
  let transition;
  let tagged;
  function tag(element) {
    if (tagged) tagged.style.viewTransitionName = '';
    tagged = element;
    if (tagged) tagged.style.viewTransitionName = 'chain-object';
  }
  function linkTo(path) {
    const main = document.getElementById('content');
    const link = Array.from(main.querySelectorAll('a[href^="#/"]')).find(a => a.hash === '#' + path && !a.hidden);
    return link?.closest('.stack-tools')?.querySelector('code') || link;
  }
  const detail = path => /^\/(block|tx|app|science\/task)\//.test(path);
  const heading = () => document.querySelector('#content h1');
  document.addEventListener('visibilitychange', () => { if (document.hidden) transition?.skipTransition(); });
  reduced.addEventListener('change', () => { if (reduced.matches) transition?.skipTransition(); });
  function replace(update, animate, from, to) {
    transition?.skipTransition();
    transition = undefined;
    tag(undefined);
    if (animate && !document.hidden && !reduced.matches && document.startViewTransition) {
      document.documentElement.classList.add('changing-view');
      // A block lists its transactions. Keep the transaction as the shared object in both directions.
      const returningToBlock = from?.startsWith('/tx/') && to.startsWith('/block/');
      const destination = from !== to && detail(to) && !returningToBlock && linkTo(to);
      const old = destination || (from !== to && detail(from) && heading());
      tag(old);
      const run = document.startViewTransition(() => {
        if (transition === run) tag(undefined);
        update();
        if (old && transition === run) {
          tag(destination ? heading() : linkTo(from));
        }
      });
      transition = run;
      run.finished.catch(() => {}).then(() => {
        if (transition !== run) return;
        document.documentElement.classList.remove('changing-view');
        tag(undefined);
        transition = undefined;
      });
      return run.updateCallbackDone;
    }
    document.documentElement.classList.remove('changing-view');
    update();
    return Promise.resolve();
  }
  function cancel(paint) {
    pending.delete(paint);
    if (!pending.size && frame) {
      cancelAnimationFrame(frame);
      frame = 0;
    }
  }
  return { schedule, cancel, select, replace };
})();
