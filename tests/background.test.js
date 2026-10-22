"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const vm = require("node:vm");
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const A = require("../src/assess.js");
const source = fs.readFileSync(path.join(__dirname, "../src/background.js"), "utf8");
const flush = async () => {
  for (let i = 0; i < 12; i++) await new Promise(setImmediate);
};
function harness() {
  const listeners = {},
    session = {},
    local = {},
    created = [],
    removed = [],
    timers = new Map(),
    sent = [];
  let now = Date.now(),
    nextTimer = 0,
    nextWindow = 0;
  const event = (name) => ({
    addListener: (fn) => {
      listeners[name] = fn;
    },
  });
  const area = (store) => ({
    get: async (keys) =>
      Object.fromEntries(
        (keys === null ? Object.keys(store) : Array.isArray(keys) ? keys : [keys])
          .filter((k) => k in store)
          .map((k) => [k, structuredClone(store[k])])
      ),
    set: async (data) => {
      Object.assign(store, structuredClone(data));
    },
    remove: async (key) => {
      delete store[key];
    },
  });
  const chrome = {
    runtime: {
      getURL: (p) => "chrome-extension://test/" + p,
      onMessage: event("message"),
      onInstalled: event("installed"),
      openOptionsPage: async () => {},
    },
    storage: { session: area(session), local: area(local) },
    tabs: {
      query: async () => [{ id: 1, url: "https://site.example/path" }],
      get: async () => ({ id: 1, url: "https://site.example/path" }),
      sendMessage: async (id, msg) => {
        sent.push({ id, msg });
      },
      onRemoved: event("tabRemoved"),
      onUpdated: event("tabUpdated"),
    },
    windows: {
      create: async (options) => {
        const win = { id: ++nextWindow, ...options };
        created.push(win);
        return win;
      },
      remove: async (id) => {
        removed.push(id);
        queueMicrotask(() => listeners.windowRemoved?.(id));
      },
      onRemoved: event("windowRemoved"),
    },
    webRequest: { onHeadersReceived: event("headers"), onBeforeRequest: event("before") },
    action: {
      setBadgeText: async () => {},
      setBadgeBackgroundColor: async () => {},
      setTitle: async () => {},
    },
  };
  class ClockDate extends Date {
    static now() {
      return now;
    }
  }
  const context = vm.createContext({
    chrome,
    PHProtectAssess: A,
    URL,
    AbortController,
    console,
    crypto: crypto.webcrypto,
    Date: ClockDate,
    setTimeout: (fn, delay) => {
      const id = ++nextTimer;
      timers.set(id, { fn, at: now + delay });
      return id;
    },
    clearTimeout: (id) => timers.delete(id),
    fetch: async () => ({
      status: 200,
      headers: new Map([["x-powered-by", "PHP/8.4.27"]]),
      body: { cancel: async () => {} },
    }),
  });
  vm.runInContext(source, context);
  const web = {
    tab: { id: 1, url: "https://site.example/path" },
    url: "https://frame.example/",
    frameId: 3,
  };
  const own = { url: "chrome-extension://test/warning.html" };
  const send = (msg, sender = own) =>
    new Promise((resolve) => {
      const result = listeners.message(msg, sender, resolve);
      if (result !== true) resolve(undefined);
    });
  const risk = (code = "approve-unlimited", sender = web) =>
    send({ type: "risk", kind: "signature", verdict: { code, f: {} } }, sender);
  const params = (win) => Object.fromEntries(new URL(win.url).searchParams);
  const advance = async (ms) => {
    now += ms;
    for (const [id, t] of [...timers])
      if (t.at <= now) {
        timers.delete(id);
        t.fn();
      }
    await flush();
  };
  return {
    send,
    risk,
    params,
    advance,
    web,
    own,
    listeners,
    session,
    local,
    created,
    removed,
    sent,
    context,
  };
}
test("current warning can be read; forged and unacknowledged decisions cannot allow", async () => {
  const h = harness();
  const decision = h.risk();
  await flush();
  assert.equal(h.created.length, 1);
  const q = h.params(h.created[0]);
  const info = await h.send({ type: "pending?", ...q });
  assert.equal(info.verdict.title, "Unlimited token approval");
  assert.equal(await h.send({ type: "pending?", ...q, token: "forged" }), null);
  assert.equal(
    await h.send({ type: "decide", ...q, allow: true, acknowledged: true }, h.web),
    undefined
  );
  assert.equal((await h.send({ type: "decide", ...q, allow: true })).ok, false);
  assert.equal((await h.send({ type: "decide", ...q, allow: true, acknowledged: true })).ok, true);
  assert.equal((await decision).allow, true);
});
test("unknown codes and inherited property names fail closed", async () => {
  const h = harness();
  for (const code of ["unknown", "__proto__", "toString"])
    assert.equal((await h.risk(code)).allow, false);
  assert.equal(h.created.length, 0);
});
test("subframes share one warning queue per tab", async () => {
  const h = harness(),
    first = h.risk(),
    second = h.risk("approve", { ...h.web, frameId: 9 });
  await flush();
  assert.equal(h.created.length, 1);
  const q = h.params(h.created[0]);
  assert.equal((await h.send({ type: "pending?", ...q })).queue, 1);
  await h.send({ type: "decide", ...q, allow: false });
  assert.equal((await first).allow, false);
  await flush();
  assert.equal(h.created.length, 2);
  await h.send({ type: "decide", ...h.params(h.created[1]), allow: true });
  assert.equal((await second).allow, true);
});
test("queue expiry denies every request and does not permit a stale approval", async () => {
  const h = harness(),
    first = h.risk(),
    second = h.risk("approve");
  await flush();
  const q = h.params(h.created[0]);
  await h.advance(180001);
  assert.equal((await first).allow, false);
  assert.equal((await second).allow, false);
  assert.equal((await h.send({ type: "decide", ...q, allow: true, acknowledged: true })).ok, false);
});
test("a closed decision window denies the intercepted request", async () => {
  const h = harness(),
    decision = h.risk();
  await flush();
  h.listeners.windowRemoved(h.created[0].id);
  assert.equal((await decision).allow, false);
});
test("navigation cancels decisions and replaces old evidence", async () => {
  const h = harness(),
    decision = h.risk();
  await flush();
  h.listeners.before({ tabId: 1, url: "https://next.example/" });
  assert.equal((await decision).allow, false);
  await flush();
  assert.equal(h.session.tab_1.host, "next.example");
  assert.equal(h.session.tab_1.phpVersions.length, 0);
});
test("medium exceptions never allow high-risk requests", async () => {
  const h = harness();
  await h.send({ type: "set", key: "trusted", value: true, host: "site.example" });
  assert.equal((await h.risk("approve")).allow, true);
  const high = h.risk();
  await flush();
  assert.equal(h.created.length, 1);
  await h.send({ type: "decide", ...h.params(h.created[0]), allow: false });
  assert.equal((await high).allow, false);
});
test("global changes broadcast to all tabs even when a host was supplied", async () => {
  const h = harness();
  await h.send({ type: "set", key: "wallet", value: false, host: "different.example" });
  assert.ok(h.sent.some(({ id, msg }) => id === 1 && msg.settings?.wallet === false));
});
test("concurrent audit, event and header writes preserve all evidence", async () => {
  const h = harness();
  await flush();
  h.listeners.headers({
    tabId: 1,
    url: "https://site.example/path",
    responseHeaders: [{ name: "X-Powered-By", value: "PHP/8.2.34" }],
  });
  const audit = h.send(
    { type: "audit", findings: [{ code: "pw-http", value: "site.example" }] },
    h.web
  );
  await h.send({ type: "event", code: "clip-read" }, h.web);
  await audit;
  await flush();
  assert.equal(h.session.tab_1.assessment.status, "vulnerable");
  assert.equal(h.session.tab_1.audit.high, 1);
  assert.equal(h.session.tab_1.events[0].code, "clip-read");
});
test("disabled auditing rejects new findings", async () => {
  const h = harness();
  await h.send({ type: "set", key: "audit", value: false });
  assert.equal((await h.send({ type: "audit", findings: [{ code: "pw-http" }] }, h.web)).ok, false);
});
test("content scripts cannot change settings or read another tab status", async () => {
  const h = harness();
  await flush();
  assert.equal(await h.send({ type: "set", key: "wallet", value: false }, h.web), undefined);
  h.session.tab_999 = { assessment: { status: "vulnerable" } };
  const status = await h.send({ type: "status?", tabId: 999, host: "other.example" }, h.web);
  assert.equal(status.risky, false);
  assert.equal(status.settings.wallet, true);
});
test("header refresh replaces old versions instead of retaining a stale vulnerable verdict", async () => {
  const h = harness();
  await flush();
  h.listeners.headers({
    tabId: 1,
    url: "https://site.example/path",
    responseHeaders: [{ name: "X-Powered-By", value: "PHP/8.2.34" }],
  });
  await flush();
  const result = await h.send({ type: "recheck", tabId: 1 });
  assert.equal(result.ok, true);
  assert.equal(h.session.tab_1.assessment.status, "patched");
  assert.deepEqual(h.session.tab_1.phpVersions, ["8.4.27"]);
});
test("late loading status does not erase received headers", async () => {
  const h = harness();
  await flush();
  h.listeners.headers({
    tabId: 1,
    url: "https://site.example/path",
    responseHeaders: [{ name: "X-Powered-By", value: "PHP/8.2.34" }],
  });
  await flush();
  h.listeners.tabUpdated(1, { status: "loading" });
  await flush();
  assert.equal(h.session.tab_1.assessment.status, "vulnerable");
});
test("reset restores defaults and removes every saved exception", async () => {
  const h = harness();
  await h.send({ type: "set", key: "trusted", value: true, host: "site.example" });
  await h.send({ type: "set", key: "wallet", value: false });
  assert.equal((await h.send({ type: "reset-preferences" })).ok, true);
  const status = await h.send({ type: "status?", tabId: 1, host: "site.example" });
  assert.equal(status.trusted, false);
  assert.equal(status.settings.wallet, true);
});
