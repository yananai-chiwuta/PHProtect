// PHProtect: PHP2Shell exposure assessment.
//
// Data source for the cutoffs below: OpenAI's php2shell-checker (Apache-2.0),
// https://github.com/openai/php2shell-checker: `VULNERABLE_THROUGH`.
// We add the branch-EOL distinction, multiple-version handling, header
// provenance and prerelease handling that a browser extension needs.
//
// Pure functions. No DOM, no network, no globals beyond the export.
(() => {
  "use strict";

  // First *patched* release is cutoff + 1. Anything <= cutoff is vulnerable.
  const VULNERABLE_THROUGH = Object.freeze({
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
  });

  // Outside normal upstream support. Vendor/source backports may exist.
  const EOL = new Set(["5.4", "5.5", "5.6", "7.0", "7.1", "7.2", "7.3", "7.4", "8.0", "8.1"]);

  // Higher rank = safer. Used to pick the worst finding when several versions
  // are advertised (a proxy and an origin, for example).
  const RANK = { vulnerable: 0, eol: 1, unknown: 2, patched: 3 };

  const clean = (s, max = 160) =>
    typeof s === "string"
      ? s
          .replace(/[\u0000-\u001f\u007f]/g, " ")
          .trim()
          .slice(0, max)
      : "";

  // "PHP/8.2.10", "PHP 8.4.27 (Debian)", "php/8.3.36-1+deb12u1" -> ["8.2.10", ...]
  const VERSION_RE = /\bphp[ \t]*[/ ]?[ \t]*v?(\d{1,3}\.\d{1,3}(?:\.\d{1,4})?)([-+~][^\s,;)]*)?/gi;

  function parseVersions(text) {
    const out = [];
    if (typeof text !== "string" || !text) return out;
    const seen = new Set();
    let m;
    VERSION_RE.lastIndex = 0;
    while ((m = VERSION_RE.exec(text))) {
      const version = m[1] + (m[2] || "");
      // A bare "PHP/" with no usable branch is not a version.
      if (seen.has(version)) continue;
      seen.add(version);
      out.push(version);
      if (out.length >= 8) break;
    }
    return out;
  }

  // One advertised version -> status. Never throws, never guesses.
  function assessVersion(version) {
    const v = clean(version, 40);
    const m = /^(\d{1,3})\.(\d{1,3})(?:\.(\d{1,4}))?([-+~].*)?$/.exec(v);
    if (!m) return { status: "unknown", version: v, reason: "unrecognised-version" };

    const major = Number(m[1]);
    const minor = Number(m[2]);
    const branch = `${major}.${minor}`;
    const patch = m[3] === undefined ? null : Number(m[3]);
    const suffix = m[4] || "";

    if (EOL.has(branch)) {
      return {
        status: "eol",
        version: v,
        branch,
        patch,
        reason: "branch-out-of-support",
      };
    }

    const cutoff = VULNERABLE_THROUGH[branch];
    if (cutoff === undefined) {
      // Newer than every branch we know. A development build of a new branch
      // is not evidence of a shipped fix, so keep it unknown.
      const newer = major > 8 || (major === 8 && minor > 5);
      if (newer) {
        if (/(?:^|[-+~.])(?:dev|alpha|beta|rc)/i.test(suffix)) {
          return {
            status: "unknown",
            version: v,
            branch,
            patch,
            reason: "unreleased-branch",
          };
        }
        return {
          status: "unknown",
          version: v,
          branch,
          patch,
          reason: "unverified-branch",
        };
      }
      return {
        status: "unknown",
        version: v,
        branch,
        patch,
        reason: "unknown-branch",
      };
    }

    const needed = `${branch}.${cutoff + 1}`;
    if (patch === null)
      return {
        status: "unknown",
        version: v,
        branch,
        needed,
        reason: "no-patch-level",
      };
    if (patch <= cutoff)
      return {
        status: "vulnerable",
        version: v,
        branch,
        needed,
        patch,
        reason: "at-or-below-cutoff",
      };
    // "8.4.28-dev" is not proof that a stable fix shipped.
    if (/(?:^|[-+~.])(?:dev|alpha|beta|rc)/i.test(suffix)) {
      return {
        status: "unknown",
        version: v,
        branch,
        needed,
        patch,
        reason: "prerelease",
      };
    }
    return {
      status: "patched",
      version: v,
      branch,
      needed,
      patch,
      reason: "newer-than-cutoff",
    };
  }

  // Several advertised versions -> the worst one wins.
  function assessPhp(input) {
    const list = Array.isArray(input) ? input : parseVersions(input);
    const versions = [...new Set(list.map((v) => clean(v, 40)).filter(Boolean))].slice(0, 8);
    if (!versions.length) {
      return {
        status: "unknown",
        versions: [],
        reason: "no-version",
        needed: null,
        version: null,
        branch: null,
      };
    }
    const results = versions.map(assessVersion);
    results.sort((a, b) => RANK[a.status] - RANK[b.status]);
    const worst = results[0];
    return {
      status: worst.status,
      reason: worst.reason,
      versions: results.map((r) => r.version),
      version: worst.version,
      branch: worst.branch || null,
      patch: worst.patch ?? null,
      needed: worst.needed || null,
    };
  }

  // Header names whose *values* can carry a PHP version.
  const VERSION_HEADERS = new Set([
    "x-powered-by",
    "server",
    "x-php",
    "x-backend-server",
    "x-powered-by-plesk",
  ]);
  // Hints, never proof: generic proxy/runtime headers do not imply PHP.
  const PHP_HEADERS = /^x-php(?:$|-)/i;
  const PHP_COOKIE =
    /(?:^|[;\n]\s*)(PHPSESSID|laravel_session|wordpress_[a-z0-9_]+|wp-settings-\d+|woocommerce_[a-z0-9_]+|magento[a-z0-9_]*|drupal\.[a-z0-9_]+|joomla_[a-z0-9_]+)\s*=/i;

  const CMS_PATTERNS = [
    ["WordPress", /\bwordpress\b|api\.w\.org|wp-(?:content|includes|json)\//i],
    [
      "Magento",
      /\bmagento\b|x-magento-|marker\/magento|\/static\/version\d+\/|\/skin\/frontend\//i,
    ],
    ["Drupal", /\bdrupal\b|x-drupal-|sites\/default\/files|drupalSettings/i],
    ["Joomla", /\bjoomla\b|joomla!|com_content|\/media\/system\/js\//i],
    ["Laravel", /\blaravel\b|laravel_session/i],
    ["Symfony", /\bsymfony\b|x-symfony-/i],
  ];

  function analyseHeaders(headers) {
    const list = Array.isArray(headers) ? headers : [];
    const values = new Map();
    const names = [];
    for (const h of list) {
      if (!h || typeof h.name !== "string") continue;
      const name = h.name.toLowerCase();
      names.push(name);
      const value = typeof h.value === "string" ? h.value : "";
      if (!values.has(name)) values.set(name, []);
      values.get(name).push(value);
    }

    const joined = (name) => (values.get(name) || []).join("\n");
    const versionText = [...VERSION_HEADERS].map(joined).join("\n");
    const poweredBy = clean(joined("x-powered-by"), 160);
    const server = clean(joined("server"), 160);
    const cookies = list
      .filter((h) => h && String(h.name || "").toLowerCase() === "set-cookie")
      .map((h) => h.value || "")
      .join("\n");
    const cookieNames = [...cookies.matchAll(/(?:^|;\s*)([A-Za-z0-9_.-]{1,40})\s*=/g)].map((m) =>
      m[1].toLowerCase()
    );
    const link = joined("link");

    const phpVersions = parseVersions(versionText);
    const phpHeader = names.some((n) => PHP_HEADERS.test(n));
    const phpCookie = PHP_COOKIE.test(cookies);
    const usesPhp = phpVersions.length > 0 || phpHeader || phpCookie || /\bphp\b/i.test(poweredBy);

    const haystack = list
      .filter((h) => h && typeof h.name === "string")
      .map((h) => `${h.name}: ${h.value || ""}`)
      .join("\n");
    const cms = [];
    for (const [name, re] of CMS_PATTERNS)
      if (re.test(haystack) || (name === "WordPress" && /api\.w\.org/i.test(link))) cms.push(name);

    const signals = [];
    if (phpVersions.length) signals.push("php-version");
    if (phpHeader) signals.push("php-header");
    if (phpCookie) signals.push("php-cookie");
    for (const c of cms) signals.push(`cms:${c.toLowerCase()}`);

    return {
      phpVersions,
      usesPhp,
      cms: [...new Set(cms)],
      server,
      poweredBy,
      cookieNames: [...new Set(cookieNames)].slice(0, 12),
      signals,
    };
  }

  const isRisky = (state) =>
    !!state &&
    state.assessment &&
    (state.assessment.status === "vulnerable" || state.assessment.status === "eol");

  // Badge: PHP verdict first, then a blue dot for a page-level warning.
  function badgeFor(state) {
    if (!state) return { text: "", color: "#5f6368" };
    const s = state.assessment && state.assessment.status;
    if (s === "vulnerable" || s === "eol") return { text: "!", color: "#d93025" };
    // Page warnings must remain visible even when the PHP version meets a cutoff.
    if (state.audit && state.audit.high > 0) return { text: "!", color: "#b45309" };
    if (s === "patched") return { text: "PHP", color: "#28756b" };
    if (state.usesPhp || (state.cms && state.cms.length)) return { text: "?", color: "#e37400" };
    if (state.audit && state.audit.high > 0) return { text: "\u2022", color: "#1a73e8" };
    return { text: "", color: "#5f6368" };
  }

  // The people who maintain php2shell-checker call their result a *hint*.
  // Keep the same honesty: a backported distro package can look old.
  const statusLabel = (status) =>
    ({
      vulnerable: "likely exposed",
      eol: "out of support",
      patched: "meets PHP2Shell cutoff",
      unknown: "cannot tell",
    })[status] || "cannot tell";

  const api = {
    VULNERABLE_THROUGH,
    EOL,
    parseVersions,
    assessVersion,
    assessPhp,
    analyseHeaders,
    badgeFor,
    isRisky,
    statusLabel,
    clean,
  };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  else globalThis.PHProtectAssess = api;
})();
