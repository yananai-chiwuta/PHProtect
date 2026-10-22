"use strict";
// Page-audit model tests. Every case is a plain object: no DOM needed.
const test = require("node:test");
const assert = require("node:assert/strict");
const A = require("../src/audit.js");
const H = require("../src/homograph.js");

const base = (extra) => ({
  url: "https://shop.example/checkout",
  host: "shop.example",
  ...(extra || {}),
});
const codes = (model, hostCheck) => A.auditModel(model, hostCheck).map((f) => f.code);

test("a clean HTTPS page has no findings", () => {
  assert.deepEqual(A.auditModel(base()), []);
});

test("about:blank and srcdoc frames are skipped, not marked insecure", () => {
  assert.deepEqual(A.auditModel({ url: "about:blank" }), []);
  assert.deepEqual(A.auditModel({ url: "about:srcdoc" }), []);
});

test("HTTP page and password handling", () => {
  const model = base({
    url: "http://shop.example/",
    forms: [{ action: "http://shop.example/login", passwords: 1, autocomplete: false }],
  });
  const found = A.auditModel(model);
  const byCode = Object.fromEntries(found.map((f) => [f.code, f]));
  assert.equal(byCode["http-page"].severity, "medium");
  assert.equal(byCode["pw-http"].severity, "high");
  assert.equal(byCode["pw-no-autocomplete"].severity, "info");
});

test("password form posting to another origin is high risk", () => {
  const found = A.auditModel(
    base({
      forms: [{ action: "https://collect.example/login", passwords: 1, autocomplete: true }],
    })
  );
  assert.equal(found.length, 1);
  assert.equal(found[0].code, "pw-cross-origin");
  assert.equal(found[0].value, "https://collect.example");
});

test("forms without passwords do not raise password findings", () => {
  assert.deepEqual(
    codes(base({ forms: [{ action: "http://x.example/", passwords: 0, autocomplete: false }] })),
    []
  );
});

test("many forms are noted once", () => {
  const forms = Array.from({ length: 4 }, () => ({ action: "", passwords: 0, autocomplete: true }));
  assert.deepEqual(codes(base({ forms })), ["many-forms"]);
});

test("hidden and normal cross-origin frames rank differently", () => {
  const hidden = A.auditModel(base({ iframes: [{ src: "https://evil.example/x", hidden: true }] }));
  assert.equal(hidden[0].code, "hidden-iframe");
  assert.equal(hidden[0].severity, "high");
  const normal = A.auditModel(base({ iframes: [{ src: "https://cdn.example/x", hidden: false }] }));
  assert.equal(normal[0].code, "cross-origin-iframe");
  assert.equal(normal[0].severity, "info");
  assert.deepEqual(codes(base({ iframes: [{ src: "/local", hidden: true }] })), []);
});

test("a cross-origin base element is a hijack signal", () => {
  const found = A.auditModel(base({ baseHref: "https://cdn.example/" }));
  assert.equal(found[0].code, "base-hijack");
  assert.equal(found[0].value, "https://cdn.example");
});

test("ClickFix wording needs a command nearby", () => {
  assert.deepEqual(
    codes(
      base({ text: "Verify you are human, then press Win + R and paste powershell in there." })
    ),
    ["clickfix-text"]
  );
  assert.deepEqual(codes(base({ text: "Verify you are human." })), []);
  assert.deepEqual(codes(base({ text: "Run this in powershell" })), []);
  assert.deepEqual(codes(base({ text: "Press Win+R and run powershell -enc ABC" })), [
    "clickfix-text",
  ]);
});

test("a hidden command box is reported", () => {
  assert.deepEqual(codes(base({ hiddenBoxes: ["powershell -w hidden -enc SQBFAFgA"] })), [
    "hidden-textarea",
  ]);
  assert.deepEqual(codes(base({ hiddenBoxes: ["hello there"] })), []);
});

test("obfuscation and wallet hooks use the inline script", () => {
  const escaped = "\\x41".repeat(401);
  assert.deepEqual(codes(base({ inline: escaped })), ["obfuscated-script"]);
  assert.deepEqual(codes(base({ inline: "eval(atob('ZQB2AGEAbAA=='))" })), ["obfuscated-script"]);
  assert.deepEqual(codes(base({ inline: "provider.request({ method: 'eth_requestAccounts' })" })), [
    "wallet-hooks",
  ]);
});

test("third-party script count and mixed content", () => {
  const scripts = Array.from({ length: 5 }, (_, i) => `https://s${i}.example/a.js`);
  assert.deepEqual(codes(base({ scripts })), ["foreign-scripts"]);
  assert.deepEqual(codes(base({ scripts: ["http://cdn.example/a.js"] })), ["mixed-content"]);
});

test("cross-origin meta refresh and foreign installer downloads", () => {
  const refresh = A.auditModel(base({ metaRefresh: "https://elsewhere.example/" }));
  assert.equal(refresh[0].code, "meta-refresh");
  const download = A.auditModel(base({ links: [{ href: "https://dl.example/setup.exe" }] }));
  assert.equal(download[0].code, "foreign-download");
  assert.deepEqual(codes(base({ links: [{ href: "/local/setup.exe" }] })), []);
});

test("hostname checks are merged in", () => {
  const found = A.auditModel(
    base({ host: "xn--pple-43d.com", url: "https://xn--pple-43d.com/" }),
    H.checkHost
  );
  assert.ok(found.some((f) => f.code === "brand-lookalike"));
});

test("findings are bounded and values are short", () => {
  const forms = Array.from({ length: 40 }, () => ({
    action: "https://x.example/",
    passwords: 1,
    autocomplete: false,
  }));
  const found = A.auditModel(base({ forms, iframes: [], scripts: [], links: [], text: "" }));
  assert.ok(found.length <= 30);
  assert.ok(found.every((f) => f.value.length <= 80));
});

test("bad models never throw", () => {
  assert.deepEqual(A.auditModel(null), []);
  assert.deepEqual(A.auditModel({ url: "not a url" }), []);
  assert.deepEqual(A.auditModel({ url: "https://x.example", forms: [null] }), []);
  assert.deepEqual(A.auditModel({ url: "https://x.example", iframes: [null] }), []);
  assert.deepEqual(A.auditModel({ url: "https://x.example", links: [null] }), []);
});

test("origin helper refuses junk", () => {
  assert.equal(A.originOf("https://a.example/x"), "https://a.example");
  assert.equal(A.originOf("nope"), "");
  assert.equal(A.originOf(null), "");
});
