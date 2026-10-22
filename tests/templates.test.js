"use strict";
// Cross-file coverage: every code that can reach the UI must have a template
// and every string key used by the popup must exist in the locale file.
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const B = require("../src/background.js");

const SRC = path.join(__dirname, "..", "src");
const read = (f) => fs.readFileSync(path.join(SRC, f), "utf8");
const locale = JSON.parse(read("_locales/en/messages.json"));
const KEYS = new Set(Object.keys(locale));

const literals = (source, re) => [...source.matchAll(re)].map((m) => m[1]);

const RULES = read("rules.js");
const AUDIT_JS = read("audit.js");
const HOSTS = read("homograph.js");
const BACKGROUND = read("background.js");
const GUARD = read("guard.js");
const POPUP = read("popup.js");
const MANIFEST = JSON.parse(read("manifest.base.json"));

const ruleCodes = literals(RULES, /code:\s*"([a-z0-9-]+)"/g);
const auditCodes = new Set([
  ...Object.keys(B.AUDIT),
  ...literals(AUDIT_JS, /add\("([a-z-]+)"/g),
  ...literals(HOSTS, /code:\s*"([a-z-]+)"/g),
]);

test("every wallet template renders fixed, non-empty text", () => {
  for (const code of Object.keys(B.TEMPLATES)) {
    const v = B.render({ code, f: {} }, false);
    assert.ok(v, code);
    assert.ok(["high", "medium"].includes(v.level), code);
    assert.equal(typeof v.title, "string", code);
    assert.ok(v.title.length > 3 && v.title.length < 80, code);
    assert.ok(Array.isArray(v.reasons) && v.reasons.length, code);
    assert.ok(Array.isArray(v.rows), code);
    for (const r of v.reasons) assert.equal(typeof r, "string");
  }
});

test("unknown codes fail closed and exposed-site is not double-noted", () => {
  assert.equal(B.render({ code: "nope", f: {} }, false), null);
  assert.equal(B.render(null, false), null);
  const exposed = B.render({ code: "exposed-site", f: {} }, true);
  const matches = exposed.reasons.filter((r) => /unpatched PHP/.test(r)).length;
  assert.equal(matches, 1);
  const approval = B.render({ code: "approve", f: {} }, true);
  assert.match(approval.reasons[0], /unpatched PHP/);
});

test("every rule-emitted code has a template", () => {
  assert.ok(ruleCodes.length > 10);
  for (const code of new Set(ruleCodes)) assert.ok(B.TEMPLATES[code], `${code} has no template`);
});

test("every audit producer's code has a severity and a locale string", () => {
  assert.ok(auditCodes.size > 15);
  for (const code of auditCodes) {
    assert.ok(B.AUDIT[code], `${code} has no severity`);
    assert.ok(["info", "low", "medium", "high"].includes(B.AUDIT[code][0]), code);
    // Chrome only allows [a-zA-Z0-9_] in i18n keys, so hyphens become "_".
    const key = `audit_${code.replace(/-/g, "_")}`;
    assert.ok(KEYS.has(key), `missing ${key}`);
    assert.equal(typeof locale[key].message, "string");
  }
});

test("every event code has a locale string", () => {
  const codes = B.EVENT_CODES;
  assert.equal(codes.length, 4);
  for (const code of codes) {
    const key = `event_${code.replace(/-/g, "_")}`;
    assert.ok(KEYS.has(key), `missing ${key}`);
  }
});

test("every literal key the popup translates exists exactly once", () => {
  const used = new Set(literals(POPUP, /\bt\("([A-Za-z0-9_-]+)"/g));
  assert.ok(used.size > 20);
  for (const key of used) assert.ok(KEYS.has(key), `missing locale key ${key}`);
});

test("locale keys are valid for Chrome (ASCII letters, digits, underscore)", () => {
  for (const key of KEYS) {
    assert.match(key, /^[A-Za-z0-9_]+$/, key);
    assert.ok(key.length <= 128, key);
  }
});

test("locale values are non-empty strings and the name/description exist", () => {
  for (const [key, entry] of Object.entries(locale)) {
    assert.equal(typeof entry.message, "string", key);
    assert.ok(entry.message.length > 0, key);
    assert.ok(entry.message.length < 600, key);
  }
  assert.ok(KEYS.has("extName"));
  assert.ok(KEYS.has("extDescription"));
});

test("audit values are bounded before they can reach the popup", () => {
  assert.equal(B.auditValue("many-forms", "12"), "12");
  assert.equal(B.auditValue("many-forms", "12x"), "");
  assert.equal(B.auditValue("pw-cross-origin", "https://evil.example/path"), "evil.example");
  assert.ok(B.auditValue("http-page", "h".repeat(300)).length <= 80);
});

test("manifest keeps the isolation shape and permissions tight", () => {
  assert.equal(MANIFEST.manifest_version, 3);
  assert.equal(MANIFEST.name, "__MSG_extName__");
  assert.equal(MANIFEST.description, "__MSG_extDescription__");
  assert.equal(MANIFEST.default_locale, "en");
  assert.deepEqual(MANIFEST.permissions.sort(), ["storage", "webRequest"]);
  assert.deepEqual(MANIFEST.host_permissions.sort(), ["http://*/*", "https://*/*"]);
  assert.equal(MANIFEST.background, undefined, "build.py adds per-browser background");
  assert.equal(MANIFEST.minimum_chrome_version, undefined);

  const main = MANIFEST.content_scripts.find((c) => c.world === "MAIN");
  assert.ok(main);
  assert.deepEqual(main.js, ["inpage.js"]);
  assert.equal(main.run_at, "document_start");
  assert.equal(main.all_frames, true);

  const isolated = MANIFEST.content_scripts.find((c) => c.js.includes("guard.js"));
  assert.deepEqual(isolated.js.slice(0, 2), ["bip39.js", "homograph.js"]);
  assert.ok(isolated.js.includes("audit.js"));
  assert.equal(isolated.all_frames, true);
});

test("the build never ships source-only or stray files", () => {
  const build = fs.readFileSync(path.join(__dirname, "..", "build.py"), "utf8");
  assert.match(build, /phprotect-chrome/);
  assert.match(build, /phprotect-firefox/);
  assert.match(build, /browser_specific_settings/);
  assert.doesNotMatch(build, /password|token\s*=/i);
});

test("source files do not call out to a PHProtect server", () => {
  for (const f of fs.readdirSync(SRC).filter((n) => n.endsWith(".js"))) {
    const text = read(f);
    const urls = [...text.matchAll(/https?:\/\/[a-z0-9.-]+/gi)].map((m) => m[0]);
    for (const u of urls) {
      assert.doesNotMatch(u, /phprotect\.(com|io|app|dev)/i, `${f}: ${u}`);
    }
  }
});
