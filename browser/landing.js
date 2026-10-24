// A temporary nginx-owned probe. No storage, polling, DOM observer or backend.
(function () {
  var flag = document.getElementById('myscoutee-landing-debug');
  if (!flag || flag.textContent.trim() !== '1' || !/^\/(?:entry\/?|index\.html)?$/.test(location.pathname)) return;
  var started = performance.now(), visibleSince = document.visibilityState === 'hidden' ? null : started;
  var visibleMs = 0, stopped = false, seq = 0, dropped = 0, errorCount = 0, interactionMs = null;
  var marks = [], errors = [], timers = [], listeners = [], seen = Object.create(null);
  var counts = { pointer: 0, key: 0, click: 0 }, lastSent = -1000;
  var lifecycle = [], hiddenSince = visibleSince === null ? started : null, context = [0, 0];
  try {
    var embedded = JSON.parse(document.getElementById('myscoutee-landing-debug-context').textContent);
    if (Array.isArray(embedded) && [0, 1, 2].indexOf(embedded[0]) >= 0 && [0, 1].indexOf(embedded[1]) >= 0) context = embedded.slice(0, 2);
  } catch (_) { /* Non-SSI environments have no request context. */ }
  var id = '';
  try {
    var random = new Uint32Array(2); crypto.getRandomValues(random);
    id = Array.from(random, function (n) { return n.toString(16).padStart(8, '0'); }).join('');
  } catch (_) { return; }
  var allowed = ('bootstrap.ready bootstrap.failed route.ready landing.rendered landing.content.failed ' +
    'login.click about.open partners.open countries.open bug.open article.open ' +
    'privacy.open privacy.close privacy.accepted privacy.rejected terms.open terms.close ' +
    'auth.open auth.close auth.success auth.failed auth.cancelled auth.blocked auth.network ' +
    'auth.google auth.facebook auth.email auth.popup.request auth.email.verification ' +
    'setup.open setup.close setup.save setup.failed location.request location.granted location.denied ' +
    'location.prompt location.unavailable location.timeout location.cancelled location.unsupported ' +
    'notifications.request notifications.granted notifications.denied notifications.default ' +
    'browser.request browser.unsupported install.request install.accepted install.dismissed ' +
    'network.offline network.online visible hidden').split(' ');
  function elapsed() { return Math.min(60000, Math.max(0, Math.round(performance.now() - started))); }
  function pageState() {
    // Fixed bits, decoded by the traffic tool; no DOM text, URLs or identifiers.
    var state = 0;
    try {
      if (document.visibilityState === 'visible') state |= 1;
      if (document.hasFocus && document.hasFocus()) state |= 2;
      if (document.prerendering === true) state |= 4;
      if (navigator.userActivation) {
        state |= 256;
        if (navigator.userActivation.hasBeenActive) state |= 8;
        if (navigator.userActivation.isActive) state |= 16;
      }
      if (document.readyState === 'interactive') state |= 32;
      if (document.readyState === 'complete') state |= 64;
      if (typeof document.prerendering === 'boolean') state |= 128;
      if (document.wasDiscarded === true) state |= 512;
      if (window.top && window.top !== window) state |= 1024;
    } catch (_) { /* An unavailable diagnostic property must not affect startup. */ }
    return state;
  }
  var initialState = pageState();
  function life(name) {
    if (stopped) return;
    var item = [elapsed(), name, pageState()], previous = lifecycle[lifecycle.length - 1];
    if (previous && previous[1] === name && previous[2] === item[2]) return;
    if (lifecycle.length >= 12) { lifecycle.splice(1, 1); dropped++; }
    lifecycle.push(item);
    if (performance.now() - started >= 60000) finish('end');
  }
  function pageSnapshot() {
    var page = { initial: initialState, state: pageState(), context: context,
      offsetMs: Math.min(10000000, Math.round(started)),
      hiddenForMs: hiddenSince === null ? 0 : Math.min(60000, Math.max(0, Math.round(performance.now() - hiddenSince))),
      navigation: 'unknown', delivery: '', timing: {}, events: lifecycle };
    try {
      var nav = performance.getEntriesByType('navigation')[0];
      if (nav) {
        if (/^(navigate|reload|back_forward)$/.test(nav.type)) page.navigation = nav.type;
        if (/^(cache|navigational-prefetch)$/.test(nav.deliveryType)) page.delivery = nav.deliveryType;
        ['responseStart', 'responseEnd', 'domInteractive', 'domContentLoadedEventStart', 'loadEventStart', 'activationStart', 'workerStart'].forEach(function (key) {
          var value = nav[key];
          if (typeof value === 'number' && isFinite(value) && value >= 0) page.timing[key] = Math.min(10000000, Math.round(value));
        });
      }
      performance.getEntriesByType('paint').slice(0, 4).forEach(function (entry) {
        if (/^(first-paint|first-contentful-paint)$/.test(entry.name) && typeof entry.startTime === 'number' && isFinite(entry.startTime)) {
          page.timing[entry.name] = Math.min(10000000, Math.max(0, Math.round(entry.startTime)));
        }
      });
    } catch (_) { /* Missing/unsupported timing APIs are left absent, not guessed. */ }
    return page;
  }
  function mark(name) {
    if (stopped || allowed.indexOf(name) < 0) return;
    if (performance.now() - started >= 60000) { finish('end'); return; }
    // Bound all memory and repeated permission/background state notifications.
    if (marks.length && marks[marks.length - 1][1] === name) return;
    if (marks.length < 24) marks.push([elapsed(), name]); else dropped++;
  }
  function errorText(text) {
    return text.slice(0, 1024)
      .replace(/(?:https?|wss?|file|blob|data|chrome-extension):[^\s"'<>)]*|www\.[^\s"'<>)]*/gi, '[url]')
      .replace(/\b(?:Bearer|Basic)\s+\S+/gi, '[credential]')
      .replace(/\b[\w.+%-]+@[\w.-]+\.[A-Za-z]{2,}\b/g, '[email]')
      .replace(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g, '[ip]')
      .replace(/\b(?:password|passwd|token|secret|authorization|cookie|email|userId|uid)\s*[:=]\s*(?:"[^"]*"|'[^']*'|[^\s,;]+)/gi, '[credential]')
      .replace(/"[^"\r\n]*"|'[^'\r\n]*'|`[^`\r\n]*`/g, '[value]')
      .replace(/\b[A-Za-z0-9_+\/.=-]{24,}\b/g, '[id]')
      .replace(/\b\d{5,}\b|\b\d+\.\d{3,}\b/g, '[number]')
      .replace(/[\u0000-\u0020\u007f-\u009f]+/g, ' ').trim().slice(0, 160);
  }
  function error(value, filename, line, column, origin) {
    if (stopped || errorCount >= 100) return;
    errorCount++;
    try {
      value = value && (value.ngOriginalError || value.rejection || value);
      var name = value && value.name;
      name = /^(?:[A-Za-z]{1,24}Error|Error|DOMException)$/.test(name) ? name : 'Error';
      var message = String(typeof value === 'string' ? value : value && value.message || '').slice(0, 512), hash = 2166136261;
      for (var i = 0; i < message.length; i++) hash = Math.imul(hash ^ message.charCodeAt(i), 16777619);
      var stack = String(value && value.stack || '').slice(0, 2048);
      var pattern = /((?:main|chunk|polyfills)-[A-Za-z0-9_-]+\.js)(?::(\d+):(\d+))?/;
      var match = String(filename || '').slice(0, 512).match(pattern) || stack.match(pattern);
      var item = { name: name, code: (hash >>> 0).toString(16), file: match ? match[1] : '',
        line: Math.min(10000000, Number(line || match && match[2]) || 0),
        column: Math.min(10000000, Number(column || match && match[3]) || 0), ms: elapsed() };
      var key = JSON.stringify([item.name, item.code, item.file, item.line, item.column]);
      if (seen[key]) return;
      seen[key] = true;
      if (errors.length >= 4) { dropped++; return; }
      // Keep useful diagnostics without URL paths, query values or raw stack headers.
      var frames = [];
      stack.split('\n').slice(0, 8).forEach(function (frame) {
        var location = frame.match(/(?:^|[\/@(\s])([A-Za-z0-9_-]{1,64}\.m?js|<anonymous>):(\d{1,8}):(\d{1,8})(?:\)?$|[?\s])/);
        if (!location || frames.length >= 3) return;
        var method = frame.replace(/^\s*at\s+/, '').match(/^\s*([A-Za-z_$][A-Za-z0-9_.$<>]{0,63})(?:\s|\(|@)/);
        frames.push((method ? method[1] + ' ' : '') + location[1] + ':' + location[2] + ':' + location[3]);
      });
      item.detail = { source: /^(window|promise|resource)$/.test(origin) ? origin : 'angular',
        message: errorText(message), stack: frames };
      errors.push(item);
    } catch (_) { /* Reporting must never cause a second application error. */ }
  }
  function send(reason) {
    if (stopped || seq >= 8) return;
    var now = performance.now();
    // Keep a final send slot even if native dialogs repeatedly hide the page.
    if ((reason === 'hidden' || reason === 'tick' || reason === 'freeze') && seq >= 7) return;
    if (reason === 'hidden' && now - lastSent < 1000) return;
    var packet = { v: 1, id: id, seq: ++seq, ms: elapsed(), reason: reason,
      visibleMs: Math.min(elapsed(), Math.round(visibleMs + (visibleSince === null ? 0 : now - visibleSince))),
      interactionMs: interactionMs, counts: counts, errorCount: errorCount, marks: marks, errors: errors, dropped: dropped,
      page: pageSnapshot() };
    var query = encodeURIComponent(JSON.stringify(packet));
    while (query.length > 3500 && packet.page.events.length > 4) {
      packet.page.events.splice(1, 1); packet.dropped++; query = encodeURIComponent(JSON.stringify(packet));
    }
    // Prefer one detailed error plus the surrounding milestones over repeated stacks.
    for (var i = packet.errors.length - 1; query.length > 3500 && i > 0; i--) {
      delete packet.errors[i].detail; query = encodeURIComponent(JSON.stringify(packet));
    }
    while (query.length > 3500 && packet.marks.length) {
      packet.marks.pop(); packet.dropped++; query = encodeURIComponent(JSON.stringify(packet));
    }
    while (query.length > 3500 && packet.errors.length) {
      packet.errors.pop(); packet.dropped++; query = encodeURIComponent(JSON.stringify(packet));
    }
    var url = '/__landing-debug?d=' + query;
    try {
      var queued = navigator.sendBeacon && navigator.sendBeacon(url, '');
      if (!queued) fetch(url, { method: 'POST', body: '', keepalive: true, cache: 'no-store', credentials: 'omit' }).catch(function () {});
    } catch (_) { /* The initial HTML request remains in the normal access log. */ }
    lastSent = now; marks = []; errors = []; lifecycle = [];
  }
  function finish(reason) {
    if (stopped) return;
    // A distinct pagehide sample retains persisted/cache information even after hidden.
    if (performance.now() - lastSent >= 100 || marks.length || errors.length || lifecycle.length) send(reason);
    stopped = true;
    timers.forEach(function (timer) { clearTimeout(timer); });
    listeners.forEach(function (item) { item[0].removeEventListener(item[1], item[2], true); });
    marks = []; errors = []; lifecycle = []; seen = Object.create(null);
    delete window.__myscouteeLandingDebug;
  }
  function listen(target, name, handler) {
    target.addEventListener(name, handler, { capture: true, passive: true });
    listeners.push([target, name, handler]);
  }
  function interaction(event) {
    if (!event.isTrusted || stopped) return;
    if (performance.now() - started >= 60000) { finish('end'); return; }
    if (interactionMs === null) interactionMs = elapsed();
    var kind = event.type === 'keydown' ? 'key' : event.type === 'click' ? 'click' : 'pointer';
    counts[kind] = Math.min(65535, counts[kind] + 1);
  }
  window.__myscouteeLandingDebug = { mark: mark, error: error, finish: function () { finish('route'); } };
  life('init');
  listen(document, 'pointerdown', interaction); listen(document, 'keydown', interaction); listen(document, 'click', interaction);
  listen(window, 'error', function (event) {
    if (event.target && /^(SCRIPT|LINK)$/.test(event.target.tagName)) {
      error({ name: 'ResourceError' }, event.target.src || event.target.href, 0, 0, 'resource');
    } else error(event.error || { message: event.message }, event.filename, event.lineno, event.colno, 'window');
  });
  listen(window, 'unhandledrejection', function (event) { error(event.reason, '', 0, 0, 'promise'); });
  listen(window, 'offline', function () { mark('network.offline'); });
  listen(window, 'online', function () { mark('network.online'); });
  listen(document, 'visibilitychange', function () {
    if (document.visibilityState === 'hidden') {
      if (visibleSince !== null) visibleMs += performance.now() - visibleSince;
      if (hiddenSince === null) hiddenSince = performance.now();
      visibleSince = null; life('hidden'); mark('hidden'); send('hidden');
    } else { visibleSince = performance.now(); hiddenSince = null; life('visible'); mark('visible'); }
  });
  listen(document, 'readystatechange', function () { life('ready'); });
  listen(document, 'DOMContentLoaded', function () { life('dom'); });
  listen(window, 'load', function () { life('load'); });
  listen(window, 'focus', function () { life('focus'); });
  listen(window, 'blur', function () { life('blur'); });
  listen(document, 'prerenderingchange', function () { life('activated'); });
  listen(document, 'freeze', function () { life('freeze'); send('freeze'); });
  listen(document, 'resume', function () { life('resume'); });
  listen(window, 'pageshow', function (event) { life(event.persisted ? 'pageshow.cached' : 'pageshow'); });
  listen(window, 'pagehide', function (event) { life(event.persisted ? 'pagehide.cached' : 'pagehide'); finish('pagehide'); });
  [15000, 30000, 45000, 60000].forEach(function (delay) {
    timers.push(setTimeout(function () {
      if (delay === 60000 || performance.now() - started >= 60000) finish('end'); else send('tick');
    }, delay));
  });
  if (document.visibilityState === 'hidden') send('hidden');
})();
