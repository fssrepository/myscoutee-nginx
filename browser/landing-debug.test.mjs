import { readFileSync } from 'node:fs';
import vm from 'node:vm';
import test from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { createRequire } from 'node:module';
import { resolve } from 'node:path';
const frontend = process.env.MYSCOUTEE_FRONTEND_ROOT || resolve(import.meta.dirname, '../../myscoutee-backend/frontend');
const { JSDOM } = createRequire(resolve(frontend, 'package.json'))('jsdom');
const html = readFileSync(resolve(frontend, 'src/index.html'), 'utf8');
const recorder = new JSDOM(html).window.document.getElementById('myscoutee-landing-debug-recorder');
const source = readFileSync(new URL('./landing.js', import.meta.url), 'utf8');
test('the external recorder downloads without blocking HTML parsing', () => {
  assert.ok(recorder.hasAttribute('async'));
  assert.equal(recorder.textContent.trim(), '');
});
function runtime({ enabled = '1', path = '/', beacon = true, initialVisibility = 'visible',
  prerendering = false, nav = null, paints = [], context = '[0,0]', timingThrows = false } = {}) {
  let now = 0, visible = initialVisibility, next = 0, ready = 'loading', focused = true;
  const activation = { hasBeenActive: false, isActive: false };
  const timers = new Map(), handlers = new Map(), packets = [], fetches = [];
  function target(prefix) { return {
    addEventListener(name, fn) { handlers.set(prefix + name, fn); },
    removeEventListener(name, fn) { if (handlers.get(prefix + name) === fn) handlers.delete(prefix + name); }
  }; }
  const document = { ...target('d:'), getElementById: id => ({ textContent: id === 'myscoutee-landing-debug' ? enabled : context }),
    get visibilityState() { return visible; }, get readyState() { return ready; }, hasFocus: () => focused,
    get prerendering() { return prerendering; } };
  const window = target('w:');
  const store = () => { throw Error('Storage must never be accessed'); };
  const vmContext = vm.createContext({ window, document, location: { pathname: path }, crypto: webcrypto,
    performance: { now: () => now, getEntriesByType(type) {
      if (timingThrows) throw Error('Unavailable timing API');
      return type === 'navigation' ? nav ? [nav] : [] : paints;
    } }, Uint32Array, localStorage: new Proxy({}, { get: store }),
    sessionStorage: new Proxy({}, { get: store }), indexedDB: new Proxy({}, { get: store }),
    setTimeout(fn, delay) { const id = ++next; timers.set(id, { fn, at: now + delay }); return id; },
    clearTimeout(id) { timers.delete(id); },
    navigator: { userActivation: activation, sendBeacon(url, body) { packets.push({ url, body, data: JSON.parse(new URL(url, 'https://test/').searchParams.get('d')) }); return beacon; } },
    fetch(url, options) { fetches.push({ url, options }); return Promise.resolve(); }
  });
  vm.runInContext(source, vmContext);
  return { window, packets, fetches, timers, handlers, activation,
    state(values) { if (values.ready !== undefined) ready = values.ready;
      if (values.focused !== undefined) focused = values.focused;
      if (values.prerendering !== undefined) prerendering = values.prerendering; },
    at(ms, run = true) { now = ms; if (run) for (const [id, t] of [...timers]) if (t.at <= now && timers.delete(id)) t.fn(); },
    event(name, event = {}) { handlers.get(name)?.(event); },
    visibility(state) { visible = state; handlers.get('d:visibilitychange')?.(); }
  };
}
test('disabled or non-landing documents install nothing', () => {
  for (const options of [{ enabled: '0' }, { enabled: '<!--# echo -->' }, { path: '/game' }]) {
    const r = runtime(options); assert.equal(r.handlers.size, 0); assert.equal(r.timers.size, 0); assert.equal(r.packets.length, 0);
  }
});
test('four idle summaries at 15/30/45/60 seconds then all monitoring is released', () => {
  const r = runtime();
  for (const ms of [15000, 30000, 45000, 60000]) r.at(ms);
  assert.deepEqual(r.packets.map(p => p.data.ms), [15000, 30000, 45000, 60000]);
  assert.equal(r.packets[3].data.reason, 'end'); assert.equal(r.packets[3].data.interactionMs, null);
  assert.equal(r.timers.size, 0); assert.equal(r.handlers.size, 0); assert.equal(r.window.__myscouteeLandingDebug, undefined);
  r.at(120000); assert.equal(r.packets.length, 4);
});
test('a 5ms departure flushes immediately before Angular and does not wait for the first tick', () => {
  const r = runtime(); r.at(5, false); r.event('w:pagehide');
  assert.equal(r.packets.length, 1); assert.equal(r.packets[0].data.ms, 5); assert.equal(r.packets[0].data.reason, 'pagehide');
  assert.equal(r.handlers.size, 0); assert.equal(r.timers.size, 0);
});
test('hidden native popup flushes early, distinct pagehide is retained, and a returning popup can complete', () => {
  const r = runtime(); r.at(20, false); r.visibility('hidden'); r.at(3000, false); r.visibility('visible');
  r.window.__myscouteeLandingDebug.mark('auth.success'); r.at(15000);
  assert.equal(r.packets[0].data.reason, 'hidden');
  assert.ok(r.packets[1].data.marks.some(m => m[1] === 'auth.success'));
  assert.equal(r.packets[1].data.visibleMs, 12020);
  const early = runtime(); early.at(5, false); early.visibility('hidden'); early.event('w:pagehide');
  assert.equal(early.packets.length, 2); assert.equal(early.handlers.size, 0);
  assert.equal(early.packets[1].data.page.events[0][1], 'pagehide');
});
test('one-second hiding and thirty-second-later departure retain load state, focus and exact hidden duration', () => {
  const r = runtime({ nav: { type: 'navigate', responseStart: 150, responseEnd: 250, domInteractive: 0,
    domContentLoadedEventStart: 0, loadEventStart: 0, activationStart: 0, workerStart: 0 } });
  r.at(1000, false); r.state({ focused: false }); r.visibility('hidden');
  const first = r.packets[0].data.page;
  assert.ok(first.initial & 1); assert.ok(first.initial & 2);
  assert.equal(first.state & (1 | 2 | 32 | 64), 0); assert.equal(first.hiddenForMs, 0);
  assert.equal(first.timing.responseEnd, 250); assert.equal(first.timing.domInteractive, 0);
  r.at(1500, false); r.state({ ready: 'interactive' }); r.event('d:readystatechange');
  r.window.__myscouteeLandingDebug.mark('bootstrap.ready');
  r.at(31000, false); r.event('w:pagehide', { persisted: false });
  const last = r.packets.at(-1).data;
  assert.equal(last.page.hiddenForMs, 30000); assert.ok(last.page.state & 32);
  assert.equal(last.page.events.at(-1)[1], 'pagehide');
  assert.equal(last.interactionMs, null); assert.equal(last.errorCount, 0);
});
test('prerender activation, original request hints and content paint are separately observable', () => {
  const nav = { type: 'navigate', deliveryType: 'navigational-prefetch', activationStart: 0, name: 'https://test/PRIVATE?token=SECRET' };
  const r = runtime({ initialVisibility: 'hidden', prerendering: true, nav, context: '[2,0]' });
  assert.equal(r.packets.length, 1); assert.ok(r.packets[0].data.page.initial & 4);
  assert.deepEqual(r.packets[0].data.page.context, [2, 0]);
  r.at(2000, false); nav.activationStart = 2000; r.state({ prerendering: false, ready: 'complete' });
  r.event('d:prerenderingchange'); r.visibility('visible'); r.at(15000);
  const p = r.packets.at(-1).data.page;
  assert.equal(p.timing.activationStart, 2000); assert.equal(p.state & 4, 0); assert.ok(p.state & 64);
  assert.ok(p.events.some(e => e[1] === 'activated'));
  assert.doesNotMatch(decodeURIComponent(r.packets.at(-1).url), /PRIVATE|SECRET|https/);
  const painted = runtime({ paints: [{ name: 'first-contentful-paint', startTime: 555 }, { name: 'PRIVATE', startTime: 9 }] });
  painted.at(15000); assert.deepEqual(painted.packets[0].data.page.timing, { 'first-contentful-paint': 555 });
});
test('freeze flushes without an unload listener and cached departures preserve persisted state', () => {
  const r = runtime(); r.at(1000, false); r.visibility('hidden'); r.at(2000, false); r.event('d:freeze');
  assert.equal(r.packets.at(-1).data.reason, 'freeze');
  assert.equal(r.packets.at(-1).data.page.events.at(-1)[1], 'freeze');
  assert.equal(r.handlers.has('w:beforeunload'), false); assert.equal(r.handlers.has('w:unload'), false);
  r.at(3000, false); r.event('d:resume'); r.event('w:pagehide', { persisted: true });
  assert.equal(r.packets.at(-1).data.page.events.at(-1)[1], 'pagehide.cached');
  assert.equal(r.handlers.size, 0); assert.equal(r.timers.size, 0);
});
test('lifecycle bursts keep twelve samples, at most eight reports and the terminal slot', () => {
  const r = runtime({ context: '[1,1]' });
  for (let i = 0; i < 1000; i++) { r.event('w:focus'); r.event('w:blur'); }
  for (let ms = 2000; ms < 60000; ms += 2000) { r.at(ms, false); r.event('d:freeze'); }
  r.at(60000);
  assert.ok(r.packets.length <= 8); assert.equal(r.packets.at(-1).data.reason, 'end');
  assert.ok(r.packets[0].data.page.events.length <= 12); assert.ok(r.packets[0].data.dropped > 0);
  assert.deepEqual(r.packets[0].data.page.context, [1, 1]);
  for (const p of r.packets) assert.ok(p.url.length < 3550);
});
test('unsupported timing and invalid embedded headers cannot interfere with reporting', () => {
  const r = runtime({ timingThrows: true, context: '["PRIVATE", 1]', prerendering: null });
  r.at(5, false); r.event('w:pagehide');
  assert.deepEqual(r.packets[0].data.page.timing, {}); assert.deepEqual(r.packets[0].data.page.context, [0, 0]);
  assert.equal(r.packets[0].data.page.state & 128, 0);
  assert.doesNotMatch(r.packets[0].url, /PRIVATE/);
});
test('a resumed lifecycle event after the deadline stops immediately without restarting measurement', () => {
  const r = runtime(); r.at(90000, false); r.event('d:resume');
  assert.equal(r.packets.length, 1); assert.equal(r.packets[0].data.reason, 'end');
  assert.equal(r.packets[0].data.ms, 60000); assert.equal(r.handlers.size, 0); assert.equal(r.timers.size, 0);
});
test('only trusted interaction is counted, with semantic marks and no typed text', () => {
  const r = runtime(); r.at(12, false); r.event('d:click', { isTrusted: false, type: 'click' });
  r.event('d:keydown', { isTrusted: true, type: 'keydown', key: 'PRIVATE_PASSWORD' });
  r.window.__myscouteeLandingDebug.mark('login.click'); r.window.__myscouteeLandingDebug.mark('PRIVATE_EMAIL'); r.at(15000);
  assert.equal(r.packets[0].data.interactionMs, 12); assert.equal(r.packets[0].data.counts.key, 1);
  assert.deepEqual(r.packets[0].data.marks, [[12, 'login.click']]);
  assert.doesNotMatch(r.packets[0].url, /PRIVATE/);
});
test('repeated errors keep one bounded detail and omit raw credentials and URL paths', () => {
  const r = runtime();
  for (let i = 0; i < 1000; i++) r.window.__myscouteeLandingDebug.error({ name: 'TypeError',
    message: 'Failed to load https://test/private?token=secret for private@example.com token=secret-token',
    stack: 'TypeError: PRIVATE_HEADER\n    at load (https://test/private/chunk-ABC.js:12:34)\n    at https://test/main-XYZ.js:1:99' });
  for (let i = 0; i < 1000; i++) r.window.__myscouteeLandingDebug.mark(i % 2 ? 'setup.open' : 'setup.close');
  r.at(15000); const p = r.packets[0];
  assert.equal(p.data.errors.length, 1); assert.equal(p.data.errorCount, 100); assert.equal(p.data.errors[0].file, 'chunk-ABC.js');
  assert.equal(p.data.errors[0].detail.message, 'Failed to load [url] for [email] [credential]');
  assert.deepEqual(p.data.errors[0].detail.stack, ['load chunk-ABC.js:12:34', 'main-XYZ.js:1:99']);
  assert.ok(p.url.length < 3550); assert.ok(p.data.dropped > 0);
  assert.doesNotMatch(decodeURIComponent(p.url), /PRIVATE_HEADER|secret-token|https|example.com|private\//);
});
test('browser, Promise and Angular errors retain useful messages and distinguish their source', () => {
  const r = runtime();
  r.event('w:error', { error: { name: 'TypeError', message: "Cannot read properties of undefined (reading 'name')",
    stack: 'TypeError: message\n    at render (https://test/chunk-ABC.js:3:9)' }, filename: 'https://test/injected.js', lineno: 1, colno: 11853 });
  r.event('w:unhandledrejection', { reason: 'The operation was aborted.' });
  r.window.__myscouteeLandingDebug.error({ ngOriginalError: { name: 'Error', message: 'Notification cleanup failed' } });
  r.at(15000);
  const errors = r.packets[0].data.errors;
  assert.equal(errors[0].detail.message, 'Cannot read properties of undefined (reading [value])');
  assert.equal(errors[0].file, 'chunk-ABC.js');
  assert.equal(errors[0].column, 11853);
  assert.deepEqual(errors.map(e => e.detail.source), ['window', 'promise', 'angular']);
  assert.equal(errors[1].detail.message, 'The operation was aborted.');
  assert.equal(errors[2].detail.message, 'Notification cleanup failed');
});
test('early ErrorEvents without an Error object and external inline frames remain diagnosable', () => {
  const r = runtime();
  r.event('w:error', { message: 'Script error.', filename: '', lineno: 0, colno: 0 });
  r.event('w:unhandledrejection', { reason: { message: 'Bridge disconnected',
    stack: 'Error: PRIVATE\n    at bridge (https://instagram.test/private/bridge.js:1:11853)\n    at <anonymous>:1:20\nresume@https://test/main-XYZ.js:5:10\n    at ignored (https://test/chunk-ABC.js:9:20)' } });
  r.at(5, false); r.event('w:pagehide');
  const errors = r.packets[0].data.errors;
  assert.equal(errors[0].detail.message, 'Script error.');
  assert.deepEqual(errors[1].detail.stack, ['bridge bridge.js:1:11853', '<anonymous>:1:20', 'resume main-XYZ.js:5:10']);
  assert.doesNotMatch(decodeURIComponent(r.packets[0].url), /instagram|PRIVATE|ignored/);
});
test('many distinct long diagnostics retain the first detail within the unchanged request limit', () => {
  const r = runtime();
  for (let i = 0; i < 20; i++) r.window.__myscouteeLandingDebug.error({ message: 'Á'.repeat(512) + i,
    stack: `Error\n    at render (https://test/chunk-${i}.js:1:2)\n    at load (https://test/main-XYZ.js:3:4)` });
  for (let i = 0; i < 24; i++) r.window.__myscouteeLandingDebug.mark(i % 2 ? 'notifications.request' : 'notifications.granted');
  r.at(15000); const p = r.packets[0];
  assert.ok(p.url.length < 3550); assert.equal(p.data.errors.length, 4);
  assert.ok(p.data.errors[0].detail); assert.ok(p.data.errors[0].detail.message.length <= 160);
  assert.ok(p.data.errors[0].detail.stack.length <= 3); assert.ok(p.data.dropped > 0);
});
test('throwing error getters cannot interrupt the application or prevent later reports', () => {
  const r = runtime();
  assert.doesNotThrow(() => r.window.__myscouteeLandingDebug.error({ get message() { throw Error('broken getter'); } }));
  r.window.__myscouteeLandingDebug.mark('landing.rendered'); r.at(15000);
  assert.equal(r.packets[0].data.errorCount, 1);
  assert.deepEqual(r.packets[0].data.marks, [[0, 'landing.rendered']]);
});
test('diagnostic messages redact quoted values, credentials, identifiers, addresses and coordinates', () => {
  const r = runtime();
  r.window.__myscouteeLandingDebug.error({ message: 'Cannot read "PRIVATE_VALUE" password=PRIVATE_PASS Bearer PRIVATE_BEARER 123e4567-e89b-12d3-a456-426614174000 192.0.2.1 47.123456\n\x1b[31m' });
  r.at(15000); const message = r.packets[0].data.errors[0].detail.message;
  assert.match(message, /Cannot read \[value\]/);
  assert.doesNotMatch(message, /PRIVATE|123e4567|192\.0\.2\.1|47\.123456|\x1b/);
});
test('a throttled timer closes at the one-minute deadline without a burst of overdue ticks', () => {
  const r = runtime(); r.at(90000);
  assert.equal(r.packets.length, 1); assert.equal(r.packets[0].data.ms, 60000); assert.equal(r.handlers.size, 0);
});
test('bounded native visibility bursts retain a final send slot', () => {
  const r = runtime();
  for (let ms = 2000; ms < 60000; ms += 2000) { r.at(ms); r.visibility('hidden'); r.visibility('visible'); }
  r.at(60000); assert.ok(r.packets.length <= 8); assert.equal(r.packets.at(-1).data.reason, 'end');
});
test('a rejected beacon uses one small keepalive POST without persistence or retry', () => {
  const r = runtime({ beacon: false }); r.at(5, false); r.event('w:pagehide');
  assert.equal(r.fetches.length, 1); assert.equal(r.fetches[0].options.keepalive, true); assert.equal(r.fetches[0].options.body, '');
});
