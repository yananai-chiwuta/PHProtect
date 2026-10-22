"use strict";
// Homograph and lookalike detection. FN are worse than FP here, so the brand
// list is small and every positive case is pinned.
const test = require("node:test");
const assert = require("node:assert/strict");
const H = require("../src/homograph.js");

const codes = (host) => H.checkHost(host).map((f) => f.code);

test("punycode decodes a confusable label", () => {
  // "pаypal" with a Cyrillic а, not the ASCII spelling.
  assert.equal(H.decodePunycode("pypal-4ve"), "p\u0430ypal");
  assert.equal(H.decodePunycode("e1afmkfd"), "пример");
});

test("skeleton folds confusables, digits and doubled letters", () => {
  assert.equal(H.skeleton("P\u0430YPAL"), "paypal");
  assert.equal(H.skeleton("paypa1"), "paypal");
  assert.equal(H.skeleton("app1e"), "aple");
  assert.equal(H.skeleton("micros0ft"), "micros0ft".replace("0", "o"));
});

test("scripts are classified for mixed-alphabet checks", () => {
  assert.equal(H.scriptOf("a".codePointAt(0)), "latin");
  assert.equal(H.scriptOf("\u0430".codePointAt(0)), "cyrillic");
  assert.equal(H.scriptOf("\u03b1".codePointAt(0)), "greek");
  assert.equal(H.scriptOf("\u4e00".codePointAt(0)), "han");
});

test("a home-brand domain is quiet", () => {
  assert.deepEqual(H.checkHost("paypal.com"), []);
  assert.deepEqual(H.checkHost("www.google.com"), []);
  assert.deepEqual(H.checkHost("mail.google.com"), []);
});

test("a Cyrillic lookalike is caught as a mixed script and a lookalike", () => {
  const found = H.checkHost("xn--pple-43d.com");
  assert.ok(found.some((f) => f.code === "mixed-script" && f.severity === "high"));
  assert.ok(found.some((f) => f.code === "brand-lookalike" && f.severity === "high"));
  assert.match(found.find((f) => f.code === "brand-lookalike").value, /apple/);
});

test("brand plus qualifier is a medium warning", () => {
  const found = H.checkHost("paypal-secure.com");
  assert.equal(found.length, 1);
  assert.equal(found[0].code, "brand-in-name");
  assert.equal(found[0].severity, "medium");
});

test("a punycode-encoded brand lookalike is caught", () => {
  assert.ok(codes("xn--pypal-4ve.com").includes("brand-lookalike"));
});

test("IPs, empty hosts and ordinary domains are ignored", () => {
  assert.deepEqual(H.checkHost("192.168.1.1"), []);
  assert.deepEqual(H.checkHost("[::1]"), []);
  assert.deepEqual(H.checkHost(""), []);
  assert.deepEqual(H.checkHost(null), []);
  assert.deepEqual(H.checkHost("example.com"), []);
  assert.equal(H.isIp("10.0.0.1"), true);
  assert.equal(H.isIp("[::1]"), true);
  assert.equal(H.isIp("example.com"), false);
});

test("broken punycode is reported but never throws", () => {
  assert.ok(codes("xn---.com").includes("broken-punycode"));
  assert.doesNotThrow(() => H.checkHost("xn--.com"));
  assert.doesNotThrow(() => H.checkHost("xn--zzzz.com"));
});

test("case and a trailing dot do not matter", () => {
  assert.deepEqual(H.checkHost("PAYPAL.COM."), []);
});
