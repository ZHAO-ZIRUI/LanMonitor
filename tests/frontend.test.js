'use strict';

// Run the real client in Node's VM with a small DOM and controllable network.
// No browser, scanner, external service, or third-party test package is needed.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');
const source = fs.readFileSync(path.join(__dirname, '../static/app.js'), 'utf8').replace(/\npoll\(\);\s*$/, '\n');

function deferred() {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}

function harness() {
  const elements = new Map();
  let activeElement = null;
  class Element {
    constructor() {
      this.children = [];
      this.dataset = {};
      this.attributes = {};
      this.hidden = false;
      this.open = false;
      this.value = '';
      this.textContent = '';
      this.className = '';
      this.offsetParent = {};
      const classes = new Set();
      this.classList = {
        add: value => classes.add(value), remove: value => classes.delete(value),
        contains: value => classes.has(value),
        toggle(value, state) {
          const enabled = state === undefined ? !classes.has(value) : state;
          if (enabled) classes.add(value); else classes.delete(value);
          return enabled;
        },
      };
    }
    append(...children) { this.children.push(...children); }
    replaceChildren(...children) { this.children = children; }
    addEventListener() {}
    setAttribute(name, value) { this.attributes[name] = value; }
    querySelector(selector) {
      let found = this.children.find(child => selector.startsWith('.') ? child.className === selector.slice(1) : child.tagName === selector);
      if (!found) { found = new Element(); found.tagName = selector; this.children.push(found); }
      return found;
    }
    querySelectorAll() { return []; }
    focus() { activeElement = this; }
    showModal() { this.open = true; }
    close() { this.open = false; }
    reportValidity() { return true; }
  }
  const element = id => {
    if (!elements.has(id)) elements.set(id, new Element());
    return elements.get(id);
  };
  const document = {
    getElementById: element,
    querySelector: element,
    createElement: () => new Element(),
    createDocumentFragment: () => new Element(),
    addEventListener() {},
    get activeElement() { return activeElement; },
  };
  const requests = [];
  const timers = new Map();
  let timerId = 0;
  const context = vm.createContext({
    document, AbortController, console,
    fetch(url, options) {
      const result = deferred();
      requests.push({ url, options, ...result });
      return result.promise;
    },
    setTimeout(callback, delay) { const id = ++timerId; timers.set(id, { callback, delay }); return id; },
    clearTimeout(id) { timers.delete(id); },
    setInterval() { return ++timerId; },
  });
  vm.runInContext(source, context, { filename: 'static/app.js' });
  return {
    element, requests, timers,
    run: expression => vm.runInContext(expression, context),
    respond(index, value) { requests[index].resolve({ ok: true, json: async () => value }); },
    read: expression => JSON.parse(JSON.stringify(vm.runInContext(expression, context))),
  };
}

function host(octet, values = {}) {
  return { octet, ip: `192.168.100.${octet}`, reserved: false, infrastructure: false, ...values };
}
function state(instance, revision, hosts = [], settings = {}, settingsRevision = 1) {
  return { instance, revision, full: true, hosts, now: Date.now() / 1000,
    scanner: { started_at: instance, error: null }, settings, settings_revision: settingsRevision };
}
async function initialize(h, value = state('a', 1)) {
  const initial = h.run('poll()');
  h.respond(h.requests.length - 1, value);
  await initial;
}

test('settings form controls match the current client settings schema', () => {
  const html = fs.readFileSync(path.join(__dirname, '../static/index.html'), 'utf8');
  const form = html.match(/<form\b[^>]*id="settings-form"[^>]*>([\s\S]*?)<\/form>/)[1];
  const controls = [...form.matchAll(/<(?:input|select)\b[^>]*\bname="([^"]+)"/g)].map(match => match[1]);
  const h = harness();
  assert.deepEqual(controls.sort(), h.read('Object.keys(settings)').sort());
});

test('poll timeout covers a stalled response body and frees polling', async () => {
  const h = harness();
  const polling = h.run('poll()');
  const request = h.requests[0];
  const bodyStarted = deferred();
  request.resolve({ ok: true, json: () => new Promise((resolve, reject) => {
    request.options.signal.addEventListener('abort', () => reject(Object.assign(new Error('aborted'), { name: 'AbortError' })));
    bodyStarted.resolve();
  }) });
  await bodyStarted.promise;
  const timeout = [...h.timers.values()].find(timer => timer.delay === 5000);
  assert.ok(timeout, 'deadline remains registered after response headers');
  timeout.callback();
  await polling;
  assert.equal(h.read('pollInFlight'), false);
  assert.equal(h.read('connected'), false);
  assert.equal(h.timers.size, 1, 'only the next poll remains scheduled');
});

test('poll is single flight even if settings change while a request is pending', async () => {
  const h = harness();
  const first = h.run('poll()');
  h.run('settings.refresh_interval = 1; schedulePoll()');
  await h.run('poll()');
  assert.equal(h.requests.length, 1);
  assert.equal(h.timers.size, 1, 'only the current request deadline is active');
  h.respond(0, state('a', 1));
  await first;
  assert.deepEqual([...h.timers.values()].map(timer => timer.delay), [1000]);
});

test('reordered host mutation cannot overwrite a newer poll', async () => {
  const h = harness();
  await initialize(h, state('a', 1, [host(20)]));
  h.run('openDrawer(20)');
  const mutation = h.run("mutate('PATCH', { reserved: true })");
  const polling = h.run('poll()');
  h.respond(2, state('a', 3, [host(20, { reserved: false })]));
  await polling;
  h.respond(1, { instance: 'a', revision: 2, host: host(20, { reserved: true }) });
  await mutation;
  assert.equal(h.read('hosts.get(20).reserved'), false);
  assert.equal(h.read('revision'), 3);
  assert.equal(h.read('pendingChanges.size'), 0);
});

test('mutation preserves the poll cursor and survives an older poll response', async () => {
  const h = harness();
  await initialize(h, state('a', 1, [host(20)]));
  h.run('openDrawer(20)');
  const polling = h.run('poll()');
  const mutation = h.run("mutate('PATCH', { reserved: true })");
  h.respond(2, { instance: 'a', revision: 4, host: host(20, { reserved: true }) });
  await mutation;
  assert.equal(h.read('revision'), 1);
  h.respond(1, state('a', 2, [host(20)]));
  await polling;
  assert.equal(h.read('hosts.get(20).reserved'), true);
  assert.equal(h.read('revision'), 2);
  const next = h.run('poll()');
  assert.match(h.requests[3].url, /since=2/);
  h.respond(3, state('a', 5, [host(20, { reserved: false })]));
  await next;
  assert.equal(h.read('hosts.get(20).reserved'), false);
  assert.equal(h.read('pendingChanges.size'), 0);
});

test('restart resets settings revision and rejects delayed previous-instance responses', async () => {
  const h = harness();
  await initialize(h, state('a', 20, [host(20)], { refresh_interval: 30 }, 900));
  h.run('openDrawer(20)');
  const mutation = h.run("mutate('PATCH', { reserved: true })");
  const polling = h.run('poll()');
  h.respond(2, state('b', 1, [host(20)], { refresh_interval: 1 }, 2));
  await polling;
  h.respond(1, { instance: 'a', revision: 21, host: host(20, { reserved: true }) });
  await mutation;
  assert.equal(h.read('serverInstance'), 'b');
  assert.equal(h.read('settingsRevision'), 2);
  assert.equal(h.read('settings.refresh_interval'), 1);
  assert.equal(h.read('hosts.get(20).reserved'), false);
  assert.equal(h.read('revision'), 1);
});

test('restart discovered by settings forces full polling and drops old in-flight poll', async () => {
  const h = harness();
  await initialize(h, state('a', 20, [host(20)], { refresh_interval: 30 }, 900));
  const polling = h.run('poll()');
  const settings = h.run('openSettings()');
  h.respond(2, { instance: 'b', scanner: { started_at: 'b' }, settings_revision: 2,
    settings: { refresh_interval: 1 }, service: { host: 'localhost', port: 8000, subnet: '192.168.100.0/24' } });
  await settings;
  h.respond(1, state('a', 21, [host(20, { reserved: true })]));
  await polling;
  assert.equal(h.read('revision'), null);
  assert.equal(h.read('connected'), true);
  assert.equal(h.read('settings.refresh_interval'), 1);
  const fresh = h.run('poll()');
  assert.equal(h.requests[3].url, '/api/state');
  h.respond(3, state('b', 1, [host(20)]));
  await fresh;
  assert.equal(h.read('revision'), 1);
});

test('history snapshot cannot restore records after a more recent poll', async () => {
  const h = harness();
  await initialize(h, state('a', 1, [host(20)]));
  h.run("historyConfirmation = { scope: 'all' }");
  const clearing = h.run('clearHistory()');
  const polling = h.run('poll()');
  h.respond(2, state('a', 4, [host(20, { reserved: true })]));
  await polling;
  h.respond(1, { instance: 'a', scope: 'all', state: { instance: 'a', revision: 3, hosts: [host(20)] } });
  await clearing;
  assert.equal(h.read('hosts.get(20).reserved'), true);
  assert.equal(h.read('revision'), 4);
});

test('history clear prevents an older poll restoring cleared records', async () => {
  const h = harness();
  await initialize(h, state('a', 1, [host(20, { reserved: true })]));
  const polling = h.run('poll()');
  h.run("historyConfirmation = { scope: 'all' }");
  const clearing = h.run('clearHistory()');
  h.respond(2, { instance: 'a', scope: 'all', state: { instance: 'a', revision: 3, hosts: [host(20)] } });
  await clearing;
  h.respond(1, state('a', 2, [host(20, { reserved: true })]));
  await polling;
  assert.equal(h.read('hosts.get(20).reserved'), false);
  assert.equal(h.read('revision'), 3);
});

test('DELETE uses mutation headers and the same bounded request helper', async () => {
  const h = harness();
  await initialize(h, state('a', 1, [host(20)]));
  h.run('openDrawer(20)');
  const deletion = h.run("mutate('DELETE')");
  const request = h.requests[1];
  assert.equal(request.options.headers['X-LanMonitor'], '1');
  assert.equal(request.options.method, 'DELETE');
  assert.ok(request.options.signal);
  h.respond(1, { instance: 'a', revision: 2, host: host(20) });
  await deletion;
  assert.equal(h.read('actionBusy'), false);
});

test('future timestamps are offline and invalid dates cannot break rendering', () => {
  const h = harness();
  assert.equal(h.run('isOnline({ last_seen: currentTime() + 3600 })'), false);
  assert.equal(h.run('timeText(Infinity)'), '—');
  assert.equal(h.run('timeText(1e20)'), '—');
});

test('legacy mutation responses remain usable and force a full poll without weakening revision guards', async () => {
  const h = harness();
  await initialize(h, state('a', 1, [host(20)]));
  h.run('openDrawer(20)');
  const mutation = h.run("mutate('PATCH', { reserved: true })");
  const polling = h.run('poll()');
  h.respond(2, state('a', 3, [host(20)]));
  await polling;
  h.respond(1, { revision: 2, host: host(20, { reserved: true }) });
  await mutation;
  assert.equal(h.read('hosts.get(20).reserved'), false, 'legacy response must preserve newer poll data');
  assert.equal(h.read('revision'), 3);
  assert.equal(h.element('toast').textContent, '标记已保存');
  const confirming = h.run('poll()');
  assert.equal(h.requests[3].url, '/api/state');
  h.respond(3, state('a', 3, [host(20)]));
  await confirming;
  assert.equal(h.read('fullPollRequired'), null);
  const olderPoll = h.run('poll()');
  h.run("historyConfirmation = { scope: 'all' }");
  const clearing = h.run('clearHistory()');
  h.respond(5, { scope: 'all', state: { revision: 4, hosts: [host(20)] } });
  await clearing;
  assert.equal(h.read('historyConfirmation'), null, 'legacy clear completed successfully');
  h.respond(4, state('a', 3, [host(20)]));
  await olderPoll;
  assert.notEqual(h.read('fullPollRequired'), null, 'poll sent before the legacy response cannot consume its full-sync request');
  const cleared = h.run('poll()');
  assert.equal(h.requests[6].url, '/api/state');
  h.respond(6, state('a', 4, [host(20)]));
  await cleared;
});

test('legacy response cannot cross a detected restart or bypass identity checks on other endpoints', async () => {
  const h = harness();
  await initialize(h, state('a', 1, [host(20)]));
  h.run('openDrawer(20)');
  const mutation = h.run("mutate('PATCH', { reserved: true })");
  const polling = h.run('poll()');
  h.respond(2, state('b', 1, [host(20)]));
  await polling;
  h.respond(1, { revision: 2, host: host(20, { reserved: true }) });
  await mutation;
  assert.equal(h.read('serverInstance'), 'b');
  assert.equal(h.read('hosts.get(20).reserved'), false);
  assert.equal(h.element('toast').textContent, '服务已重启，请重试');
  const unrelated = h.run("requestJSON('/api/settings')");
  h.respond(3, { settings: {}, settings_revision: 1 });
  await assert.rejects(unrelated, /服务响应格式无效/);
});
