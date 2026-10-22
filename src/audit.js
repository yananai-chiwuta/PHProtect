// PHProtect page audit: passive DOM signals that a page may not be what it says.
// Runs in the isolated world. No network. Reads limited page/hidden-field text locally; never persists it.
//
// Pure `auditModel` (tested) + a thin DOM snapshotter. Values that came from the
// page are short and get validated again in background.js before display.
(() => {
  "use strict";

  const SHORT = 80;
  const short = (s, n = SHORT) =>
    String(s || "")
      .replace(/[\u0000-\u001f\u007f]/g, " ")
      .slice(0, n);

  const originOf = (u) => {
    try {
      return new URL(u).origin;
    } catch {
      return "";
    }
  };

  // model: {url, host, baseHref, scripts: [], iframes: [{src,hidden}], forms: [{action,passwords,autocomplete}], links: [{href}], inline: "", text: ""}
  function auditModel(model, hostCheck) {
    const m = model || {};
    const findings = [];
    const add = (code, severity, value) => {
      if (findings.length >= 30) return;
      findings.push({ code, severity, value: short(value) });
    };
    const url = (() => {
      try {
        return new URL(m.url || "https://example.invalid/");
      } catch {
        return null;
      }
    })();
    if (!url) return findings;
    // about:blank / srcdoc frames inherit a document but no URL of their own.
    if (!/^https?:$/.test(url.protocol)) return findings;

    const host = short(m.host || url.hostname);
    for (const f of hostCheck ? hostCheck(host) : []) add(f.code, f.severity, f.value);

    const https = url.protocol === "https:";
    if (!https) add("http-page", "medium", host);

    for (const form of m.forms || []) {
      if (!form || !form.passwords) continue;
      if (!https) add("pw-http", "high", host);
      const action = originOf(form.action || "");
      if (action && action !== url.origin) add("pw-cross-origin", "high", action);
      if (!form.autocomplete) add("pw-no-autocomplete", "info", "");
    }
    if ((m.forms || []).length >= 4) add("many-forms", "info", String((m.forms || []).length));

    for (const frame of m.iframes || []) {
      const src = frame && frame.src;
      if (!src) continue;
      const o = originOf(src);
      if (!o || o === url.origin) continue;
      if (frame.hidden) add("hidden-iframe", "high", o);
      else add("cross-origin-iframe", "info", o);
    }

    const base = originOf(m.baseHref || "");
    if (base && base !== url.origin) add("base-hijack", "medium", base);

    const text = String(m.text || "").slice(0, 30000);
    const clickfixText =
      /\b(win\s*\+\s*r|run dialog|paste (?:it |this )?(?:into|in) (?:run|terminal|powershell|cmd)|open (?:run|terminal)|verify (?:that )?you are (?:a )?human)\b/i.test(
        text
      );
    const commandish =
      /\b(powershell|pwsh|mshta|rundll32|curl|wget|iwr|irm|cmd(?:\.exe)?|osascript|bash)\b/i.test(
        text
      );
    if (clickfixText && commandish) add("clickfix-text", "high", "");

    // A command parked in a field the visitor cannot see: classic ClickFix.
    for (const box of m.hiddenBoxes || []) {
      if (/\b(powershell|pwsh|mshta|rundll32|curl|wget|iwr|irm|cmd(?:\.exe)?)\b/i.test(box)) {
        add("hidden-textarea", "medium", "");
        break;
      }
    }

    const inline = String(m.inline || "");
    const escapes =
      (inline.match(/\\x[0-9a-f]{2}/gi) || []).length +
      (inline.match(/\\u[0-9a-f]{4}/gi) || []).length;
    if (escapes > 400 || /eval\s*\(\s*atob\s*\(/.test(inline))
      add("obfuscated-script", "medium", String(escapes));

    const walletHook =
      /\b(setApprovalForAll|eth_requestAccounts|eth_signTypedData|permit2?|seaport|wallet_switchEthereumChain)\b/i.test(
        inline
      );
    if (walletHook) add("wallet-hooks", "info", "");

    const scripts = m.scripts || [];
    const foreign = [...new Set(scripts.map(originOf).filter((o) => o && o !== url.origin))];
    if (foreign.length >= 5) add("foreign-scripts", "low", String(foreign.length));

    if (https) {
      const mixed = [...scripts, ...(m.iframes || []).map((f) => f && f.src)].filter((u) =>
        /^http:\/\//i.test(u || "")
      );
      if (mixed.length) add("mixed-content", "medium", originOf(mixed[0]));
    }

    const refresh = m.metaRefresh;
    if (refresh && originOf(refresh) && originOf(refresh) !== url.origin)
      add("meta-refresh", "medium", originOf(refresh));

    for (const link of m.links || []) {
      const href = link && link.href;
      if (!href || !/\.(exe|msi|dmg|pkg|zip|crx)(?:[?#]|$)/i.test(href)) continue;
      const o = originOf(href);
      if (o && o !== url.origin) add("foreign-download", "info", o);
      break;
    }

    return findings;
  }

  if (typeof module !== "undefined" && module.exports) {
    module.exports = { auditModel, originOf, short };
    return;
  }
  if (typeof chrome === "undefined" || !chrome.runtime || typeof document === "undefined") return;

  const HOSTS = globalThis.PHProtectHosts;
  const seen = new Set();
  let runs = 0;
  let timer = 0;
  let observer = null;
  let enabled = true;
  chrome.runtime.sendMessage({ type: "status?" }, (st) => {
    if (!chrome.runtime.lastError && st?.settings) enabled = st.settings.audit !== false;
    if (!enabled && observer) observer.disconnect();
  });
  chrome.runtime.onMessage.addListener((msg) => {
    if (msg?.type !== "settings") return;
    enabled = msg.settings?.audit !== false;
    if (!enabled) {
      clearTimeout(timer);
      observer?.disconnect();
      observer = null;
    } else {
      runs = 0;
      start();
    }
  });

  function isHidden(el) {
    try {
      const r = el.getBoundingClientRect();
      const cs = getComputedStyle(el);
      return (
        r.width < 5 ||
        r.height < 5 ||
        r.right < 0 ||
        r.bottom < 0 ||
        cs.display === "none" ||
        cs.visibility === "hidden" ||
        Number(cs.opacity) < 0.05
      );
    } catch {
      return false;
    }
  }

  function snapshot() {
    const url = location.href;
    const scripts = [...document.querySelectorAll("script[src]")].map((s) => s.src).slice(0, 80);
    const iframes = [...document.querySelectorAll("iframe[src], frame[src]")]
      .map((f) => ({ src: f.src, hidden: isHidden(f) }))
      .slice(0, 40);
    const hiddenBoxes = [];
    for (const el of document.querySelectorAll("textarea, input")) {
      const v = el.tagName === "TEXTAREA" ? el.value || el.textContent : el.value;
      if (!v || v.length < 9 || v.length > 20000) continue;
      if (!/\b(powershell|pwsh|mshta|rundll32|curl|wget|iwr|irm|cmd(?:\.exe)?)\b/i.test(v))
        continue;
      if (!isHidden(el)) continue;
      hiddenBoxes.push(v.slice(0, 300));
      if (hiddenBoxes.length >= 3) break;
    }
    const forms = [...document.querySelectorAll("form")].slice(0, 40).map((f) => ({
      action: f.getAttribute("action") ? f.action : location.href,
      passwords: f.querySelectorAll('input[type="password"]').length,
      autocomplete:
        /(^|\s)(username|current-password|new-password|on|email)(\s|$)/i.test(
          f.getAttribute("autocomplete") || ""
        ) ||
        !!f.querySelector(
          'input[autocomplete="username"],input[autocomplete="current-password"],input[autocomplete="new-password"],input[name*="user" i],input[type="password"][name*="pass" i]'
        ),
    }));
    const links = [...document.querySelectorAll("a[href]")]
      .slice(0, 120)
      .map((a) => ({ href: a.href }));
    const inline = [...document.querySelectorAll("script:not([src])")]
      .map((s) => s.textContent || "")
      .join("\n")
      .slice(0, 300000);
    const metaRefresh = document.querySelector('meta[http-equiv="refresh" i]');
    const refreshMatch = metaRefresh && /url\s*=\s*([^;]+)/i.exec(metaRefresh.content || "");
    const base = document.querySelector("base[href]");
    return {
      url,
      host: location.hostname,
      baseHref: base ? base.href : "",
      scripts,
      iframes,
      hiddenBoxes,
      forms,
      links,
      inline,
      text: document.body ? document.body.innerText : "",
      metaRefresh: refreshMatch ? refreshMatch[1].trim() : "",
    };
  }

  function report() {
    if (!enabled || runs >= 8) return;
    runs++;
    if (runs >= 8) observer?.disconnect();
    let findings;
    try {
      findings = auditModel(snapshot(), HOSTS && HOSTS.checkHost);
    } catch {
      return;
    }
    const fresh = [];
    for (const f of findings) {
      const key = `${f.code}|${f.value}`;
      if (seen.has(key)) continue;
      seen.add(key);
      fresh.push(f);
    }
    if (!fresh.length) return;
    try {
      chrome.runtime.sendMessage(
        {
          type: "audit",
          findings: fresh.slice(0, 20),
          high: findings.filter((f) => f.severity === "high").length,
          medium: findings.filter((f) => f.severity === "medium").length,
        },
        () => {}
      );
    } catch {
      /* extension reloaded */
    }
  }

  const debounced = () => {
    clearTimeout(timer);
    timer = setTimeout(report, 900);
  };

  function start() {
    if (!enabled) return;
    report();
    if (observer || runs >= 2) return;
    try {
      observer = new MutationObserver(debounced);
      observer.observe(document.documentElement, {
        childList: true,
        subtree: true,
        attributes: true,
        attributeFilter: ["src", "href", "action", "style", "class", "hidden"],
      });
    } catch {
      /* ignore */
    }
  }

  if (document.readyState === "loading")
    document.addEventListener("DOMContentLoaded", start, { once: true });
  else start();
  setTimeout(start, 1500);
  window.addEventListener("pageshow", () => setTimeout(report, 400), {
    once: true,
  });
})();
