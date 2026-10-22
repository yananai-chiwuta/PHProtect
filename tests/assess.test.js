"use strict";
// Assessment tests. The cutoff table is data from OpenAI's php2shell-checker;
// these tests pin it so a careless edit cannot quietly change the verdicts.
const test = require("node:test");
const assert = require("node:assert/strict");
const A = require("../src/assess.js");

const EXPECTED_CUTOFFS = {
  5.4: 45,
  5.5: 38,
  5.6: 40,
  "7.0": 33,
  7.1: 33,
  7.2: 34,
  7.3: 33,
  7.4: 33,
  "8.0": 30,
  8.1: 34,
  8.2: 34,
  8.3: 35,
  8.4: 26,
  8.5: 11,
};

test("vulnerable-through table matches php2shell-checker", () => {
  assert.deepEqual({ ...A.VULNERABLE_THROUGH }, EXPECTED_CUTOFFS);
  assert.ok(Object.isFrozen(A.VULNERABLE_THROUGH));
});

test("every table branch has a first patched release one patch above the cutoff", () => {
  for (const [branch, cutoff] of Object.entries(EXPECTED_CUTOFFS)) {
    const at = A.assessVersion(`${branch}.${cutoff}`);
    const next = A.assessVersion(`${branch}.${cutoff + 1}`);
    if (A.EOL.has(branch)) {
      // EOL branches are "out of support" regardless of their patch level,
      // but the checker's cutoffs are still the right references.
      assert.equal(at.status, "eol", `${branch}.${cutoff}`);
      assert.equal(next.status, "eol", `${branch}.${cutoff + 1}`);
    } else {
      assert.equal(at.status, "vulnerable", `${branch}.${cutoff}`);
      assert.equal(at.needed, `${branch}.${cutoff + 1}`);
      assert.equal(next.status, "patched", `${branch}.${cutoff + 1}`);
    }
  }
});

test("EOL branches stay out of support even above the cutoff", () => {
  for (const branch of ["5.4", "7.4", "8.1"]) {
    assert.equal(A.assessVersion(`${branch}.99`).status, "eol");
  }
  for (const branch of ["8.2", "8.3", "8.4", "8.5"]) {
    assert.equal(A.assessVersion(`${branch}.99`).status, "patched");
  }
});

test("a bare branch without a patch level is unknown", () => {
  const r = A.assessVersion("8.4");
  assert.equal(r.status, "unknown");
  assert.equal(r.reason, "no-patch-level");
});

test("prereleases of a patched version are not proof", () => {
  assert.equal(A.assessVersion("8.4.28-dev").status, "unknown");
  assert.equal(A.assessVersion("8.5.12-rc1").reason, "prerelease");
  assert.equal(A.assessVersion("8.4.27").status, "patched");
});

test("unverified branches stay unknown rather than gaining a safe badge", () => {
  assert.equal(A.assessVersion("8.6.0").status, "unknown");
  assert.equal(A.assessVersion("9.0.1").status, "unknown");
  assert.equal(A.assessVersion("8.6.0-beta2").status, "unknown");
  assert.equal(A.assessVersion("6.0.1").status, "unknown");
});

test("unrecognised input never throws", () => {
  for (const v of ["", "PHP", "eight", null, "8", "8.x.1"]) {
    const r = A.assessVersion(v);
    assert.equal(r.status, "unknown");
  }
});

test("parseVersions only accepts PHP-prefixed versions", () => {
  assert.deepEqual(A.parseVersions("X-Powered-By: PHP/8.2.10"), ["8.2.10"]);
  assert.deepEqual(A.parseVersions("Server: PHP 8.4.27 (Debian)"), ["8.4.27"]);
  assert.deepEqual(A.parseVersions("php/7.4.33-1+deb11u1"), ["7.4.33-1+deb11u1"]);
  assert.deepEqual(A.parseVersions("Apache/2.4.41 (Ubuntu)"), []);
});

test("several advertised versions: the worst one wins", () => {
  const r = A.assessPhp(["8.4.27", "8.2.30"]);
  assert.equal(r.status, "vulnerable");
  assert.equal(r.version, "8.2.30");
  assert.equal(A.assessPhp(["8.4.27", "8.4.20"]).status, "vulnerable");
  assert.equal(A.assessPhp(["8.4.27", "8.6.1"]).status, "unknown");
  assert.equal(A.assessPhp(["8.5.12", "7.4.33"]).status, "eol");
  assert.equal(A.assessPhp(["8.5.12", "6.0.1"]).status, "unknown");
});

test("assessPhp with no advertising is unknown but not alarming", () => {
  const r = A.assessPhp([]);
  assert.equal(r.status, "unknown");
  assert.equal(r.reason, "no-version");
  assert.equal(r.needed, null);
  assert.equal(A.isRisky({ assessment: r }), false);
  assert.equal(A.isRisky(null), false);
});

test("header analysis finds versions, PHP and CMS without touching cookies' values", () => {
  const r = A.analyseHeaders([
    { name: "X-Powered-By", value: "PHP/7.4.33" },
    { name: "Server", value: "nginx" },
    { name: "Set-Cookie", value: "PHPSESSID=abc123; path=/" },
    { name: "Link", value: '<https://api.w.org/>; rel="https://api.w.org/"' },
    { name: "X-Magento-Cache-Debug", value: "MISS" },
  ]);
  assert.deepEqual(r.phpVersions, ["7.4.33"]);
  assert.equal(r.usesPhp, true);
  assert.equal(r.signals.includes("php-cookie"), true);
  assert.deepEqual(r.cms.sort(), ["Magento", "WordPress"]);
  assert.equal(r.cookieNames.includes("phpsessid"), true);
});

test("header analysis is defensive about junk", () => {
  const r = A.analyseHeaders([null, { name: 3 }, { name: "Server", value: 42 }]);
  assert.deepEqual(r.phpVersions, []);
  assert.equal(r.usesPhp, false);
  assert.deepEqual(A.analyseHeaders("nope").phpVersions, []);
});

test("badges show PHP evidence without claiming safety", () => {
  assert.equal(A.badgeFor({ assessment: { status: "vulnerable" } }).text, "!");
  assert.equal(A.badgeFor({ assessment: { status: "patched" }, usesPhp: true }).text, "PHP");
  assert.equal(A.badgeFor({ assessment: { status: "unknown" }, usesPhp: true }).text, "?");
  assert.equal(A.badgeFor({ assessment: { status: "unknown" }, audit: { high: 2 } }).text, "!");
  assert.equal(A.badgeFor({ assessment: { status: "unknown" } }).text, "");
  assert.equal(A.badgeFor(null).text, "");
});

test("status labels stay honest about uncertainty", () => {
  assert.equal(A.statusLabel("vulnerable"), "likely exposed");
  assert.equal(A.statusLabel("eol"), "out of support");
  assert.equal(A.statusLabel("unknown"), "cannot tell");
  assert.equal(A.statusLabel("wat"), "cannot tell");
});

test("clean strips control characters and bounds length", () => {
  assert.equal(A.clean("a\u0000b\u007f"), "a b");
  assert.equal(A.clean("x".repeat(500)).length, 160);
  assert.equal(A.clean(null), "");
});
