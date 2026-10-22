// PHProtect: homograph / lookalike domain checks. Pure functions, no network.
// Punycode decoder follows RFC 3492. The brand list is deliberately small:
// false alarms cost trust, so we only speak up on a positive match.
(() => {
  "use strict";

  // ---- punycode (RFC 3492 decoder) -------------------------------------------------
  const BASE = 36,
    TMIN = 1,
    TMAX = 26,
    SKEW = 38,
    DAMP = 700,
    INITIAL_BIAS = 72,
    INITIAL_N = 128;

  function adapt(delta, numPoints, firstTime) {
    delta = firstTime ? Math.floor(delta / DAMP) : delta >> 1;
    delta += Math.floor(delta / numPoints);
    let k = 0;
    while (delta > ((BASE - TMIN) * TMAX) >> 1) {
      delta = Math.floor(delta / (BASE - TMIN));
      k += BASE;
    }
    return k + Math.floor(((BASE - TMIN + 1) * delta) / (delta + SKEW));
  }

  const digitOf = (c) =>
    c >= 48 && c <= 57 ? c - 22 : c >= 65 && c <= 90 ? c - 65 : c >= 97 && c <= 122 ? c - 97 : BASE;

  function decodePunycode(input) {
    const out = [];
    const basic = input.lastIndexOf("-");
    if (basic > 0) for (let j = 0; j < basic; j++) out.push(input.charCodeAt(j));
    let n = INITIAL_N,
      i = 0,
      bias = INITIAL_BIAS,
      idx = basic > 0 ? basic + 1 : 0;
    while (idx < input.length) {
      const oldi = i;
      let w = 1;
      for (let k = BASE; ; k += BASE) {
        if (idx >= input.length) throw new Error("truncated");
        const digit = digitOf(input.charCodeAt(idx++));
        if (digit >= BASE) throw new Error("bad digit");
        i += digit * w;
        const t = k <= bias ? TMIN : k >= bias + TMAX ? TMAX : k - bias;
        if (digit < t) break;
        w *= BASE - t;
      }
      const len = out.length + 1;
      bias = adapt(i - oldi, len, oldi === 0);
      n += Math.floor(i / len);
      i %= len;
      out.splice(i++, 0, n);
    }
    return String.fromCodePoint(...out);
  }

  // ---- script / confusable helpers -------------------------------------------------
  const scriptOf = (cp) => {
    if (
      (cp >= 0x41 && cp <= 0x5a) ||
      (cp >= 0x61 && cp <= 0x7a) ||
      (cp >= 0xc0 && cp <= 0x24f) ||
      (cp >= 0x1e00 && cp <= 0x1eff)
    )
      return "latin";
    if (cp >= 0x370 && cp <= 0x3ff) return "greek";
    if (cp >= 0x400 && cp <= 0x52f) return "cyrillic";
    if (cp >= 0x590 && cp <= 0x5ff) return "hebrew";
    if (cp >= 0x600 && cp <= 0x6ff) return "arabic";
    if (cp >= 0x900 && cp <= 0x97f) return "devanagari";
    if (cp >= 0x4e00 && cp <= 0x9fff) return "han";
    if (cp >= 0x3040 && cp <= 0x30ff) return "kana";
    return "other";
  };

  const CONFUSABLE = {
    0: "o",
    1: "l",
    3: "e",
    4: "a",
    5: "s",
    6: "g",
    7: "t",
    8: "b",
    9: "g",
    "\u0430": "a",
    "\u0435": "e",
    "\u043e": "o",
    "\u0440": "p",
    "\u0441": "c",
    "\u0443": "y",
    "\u0445": "x",
    "\u0455": "s",
    "\u0456": "i",
    "\u0458": "j",
    "\u04bb": "h",
    "\u0501": "d",
    "\u03b1": "a",
    "\u03bf": "o",
    "\u03c1": "p",
    "\u03bd": "v",
    "\u03b9": "i",
    "\u03ba": "k",
  };

  function skeleton(s) {
    const lower = String(s)
      .toLowerCase()
      .normalize("NFKD")
      .replace(/[\u0300-\u036f]/g, "");
    let out = "";
    for (const ch of lower) out += CONFUSABLE[ch] || ch;
    return out
      .replace(/rn/g, "m")
      .replace(/vv/g, "w")
      .replace(/cl/g, "d")
      .replace(/(.)\1+/g, "$1");
  }

  const isIp = (host) =>
    /^\d{1,3}(?:\.\d{1,3}){3}$/.test(host) || (host.startsWith("[") && host.endsWith("]"));

  // Popular targets of phishing kits and wallet drainers.
  const BRANDS = {
    paypal: ["paypal.com", "paypal.me", "paypal.co.uk", "paypal.de", "paypal.fr"],
    metamask: ["metamask.io", "metamask.com"],
    coinbase: ["coinbase.com", "coinbase.co.uk", "coinbase.de"],
    binance: ["binance.com", "binance.us"],
    uniswap: ["uniswap.org", "uniswap.com"],
    opensea: ["opensea.io"],
    phantom: ["phantom.app", "phantom.com", "phantom.wallet"],
    ledger: ["ledger.com", "ledger.fr"],
    trezor: ["trezor.io", "trezor.com"],
    trustwallet: ["trustwallet.com"],
    walletconnect: ["walletconnect.com"],
    rabby: ["rabby.io"],
    krak: ["kraken.com"],
    apple: ["apple.com", "icloud.com"],
    microsoft: ["microsoft.com", "live.com", "office.com", "outlook.com"],
    google: ["google.com", "gmail.com"],
    amazon: ["amazon.com", "amazon.co.uk", "amazon.de"],
    netflix: ["netflix.com"],
    github: ["github.com"],
    docusign: ["docusign.com", "docusign.net"],
    dropbox: ["dropbox.com"],
    steam: ["steampowered.com", "steamcommunity.com"],
    stripe: ["stripe.com"],
    revolut: ["revolut.com"],
    wise: ["wise.com", "transferwise.com"],
  };

  const LEGIT = new Set(Object.values(BRANDS).flat());

  function checkHost(rawHost) {
    const findings = [];
    const host = String(rawHost || "")
      .toLowerCase()
      .replace(/\.$/, "")
      .slice(0, 253);
    if (!host) return findings;
    if (isIp(host)) return findings;

    const labels = host.split(".");
    const unicodeLabels = [];

    for (const label of labels) {
      if (!label.startsWith("xn--")) {
        unicodeLabels.push(label);
        continue;
      }
      try {
        const decoded = decodePunycode(label.slice(4));
        unicodeLabels.push(decoded);
        const scripts = new Set(
          [...decoded].filter((c) => /[\p{L}]/u.test(c)).map((c) => scriptOf(c.codePointAt(0)))
        );
        if (scripts.size >= 2) {
          findings.push({
            code: "mixed-script",
            severity: "high",
            value: decoded.slice(0, 40),
          });
        }
        if (/\s/.test(decoded))
          findings.push({
            code: "odd-hostname",
            severity: "medium",
            value: host.slice(0, 60),
          });
      } catch {
        findings.push({
          code: "broken-punycode",
          severity: "medium",
          value: label.slice(0, 40),
        });
      }
    }

    const unicodeHost = unicodeLabels.join(".");
    const registrable = labels.slice(-2).join(".");
    if (LEGIT.has(registrable)) return findings;

    // Compare the confusable skeleton of each label against the brand itself.
    const first = host.startsWith("xn--") ? "" : host;
    const candidates = [
      ...new Set([unicodeHost.split(".")[0], labels[0], first.split(".")[0]]),
    ].filter(Boolean);
    for (const [brand, legit] of Object.entries(BRANDS)) {
      const target = skeleton(brand);
      for (const label of candidates) {
        const sk = skeleton(label)
          .replace(/-/g, "")
          .replace(/[^a-z]/g, "");
        if (!sk) continue;
        if (sk === target) {
          findings.push({
            code: "brand-lookalike",
            severity: "high",
            value: `${host} (${brand})`.slice(0, 80),
          });
          return findings;
        }
        // "paypal-secure", "secure-paypal", "paypalverify"
        if (sk.includes(target) && sk.length <= target.length + 10) {
          findings.push({
            code: "brand-in-name",
            severity: "medium",
            value: `${host} (${brand})`.slice(0, 80),
          });
          return findings;
        }
      }
    }
    return findings;
  }

  const api = {
    decodePunycode,
    skeleton,
    scriptOf,
    checkHost,
    isIp,
    BRANDS,
    LEGIT,
  };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  else globalThis.PHProtectHosts = api;
})();
