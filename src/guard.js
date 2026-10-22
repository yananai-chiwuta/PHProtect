// PHProtect guard (isolated world, document_start, every frame).
//
// 1) Owns the isolated end of the DOM relay to inpage.js and relays decisions to the
//    background, which asks the user in a window the page cannot touch.
// 2) Seed Shield: catches BIP39 recovery phrases being typed or pasted.
// 3) Clipboard Guard: replaces ClickFix commands.
//
// Seed words and clipboard text never leave this context except as short
// verdict codes. Nothing is persisted.
(() => {
  "use strict";
  const BIP39 = globalThis.PHProtectBIP39;

  // ---- seed phrase detection (pure, unit-tested) -------------------------------------

  function tokens(text) {
    return String(text || "")
      .toLowerCase()
      .replace(/\b\d{1,2}[.):]\s?/g, " ")
      .split(/[^a-z]+/)
      .filter(Boolean);
  }

  function looksLikePastedSeed(text) {
    const t = tokens(text);
    if (t.length < 12 || t.length > 30) return false;
    const hits = t.filter((w) => BIP39.has(w)).length;
    return hits >= 12 && hits / t.length >= 0.9;
  }

  function trailingRun(t) {
    let n = 0;
    for (let i = t.length - 1; i >= 0 && BIP39.has(t[i]); i--) n++;
    return n;
  }

  // Trip when the field is all BIP39 words, or when the text ends in a long run
  // of them (what is being typed right now, even after "here is my seed:").
  function looksLikeTypedSeed(text, min = 6) {
    const raw = String(text || "").trim();
    if (!raw || raw.length > 2000) return false;
    const t = tokens(raw);
    const clean = !/[^a-zA-Z0-9\s.,:;()]/.test(raw);
    if (clean && t.length >= min && t.every((w) => BIP39.has(w))) return true;
    // 8 in a row at the end is very rare outside a seed; seed-labelled fields
    // get the lower threshold.
    return trailingRun(t) >= Math.max(min, min <= 3 ? 3 : 8);
  }

  // "seed": the field asks for a recovery phrase -> trip at 3 words.
  // "password": passphrases are legitimate -> require a whole seed.
  // "search": product searches -> skip.
  function fieldHint(el) {
    const attr = (n) => (el.getAttribute && el.getAttribute(n)) || "";
    const bits = [
      el.name,
      el.id,
      el.placeholder,
      attr("aria-label"),
      attr("autocomplete"),
      el.labels && [...el.labels].map((l) => l.textContent).join(" "),
    ]
      .filter(Boolean)
      .join(" ")
      .toLowerCase();
    if (
      /seed|mnemonic|recovery|secret ?phrase|private ?key|backup phrase|12 ?words|24 ?words|word ?#?\d{1,2}/.test(
        bits
      )
    )
      return "seed";
    if (el.type === "password") return "password";
    if (
      el.type === "search" ||
      /search|query|keyword|\bq\b/.test(bits) ||
      (el.closest && el.closest("[role=search],form[action*=search]"))
    )
      return "search";
    return "normal";
  }

  if (typeof module !== "undefined" && module.exports) {
    module.exports = {
      tokens,
      looksLikePastedSeed,
      looksLikeTypedSeed,
      fieldHint,
    };
    return;
  }
  if (!BIP39 || !globalThis.PHProtectRules) return;

  const RULES = globalThis.PHProtectRules;

  // A pending response normally resolves long before the warning window's own
  // timeout. This is a belt-and-braces net so a dead worker can never leave a
  // wallet promise hanging forever.
  const send = (msg, ms = 190000) =>
    new Promise((resolve) => {
      let done = false;
      const finish = (v) => {
        if (!done) {
          done = true;
          resolve(v);
        }
      };
      try {
        chrome.runtime.sendMessage(msg, (res) => finish(chrome.runtime.lastError ? null : res));
      } catch {
        finish(null);
      }
      setTimeout(() => finish(null), ms);
    });

  // ---- DOM relay (page-world endpoint is untrusted) ---------------------------------------------------------------
  const chan = document.createElement("phprotect-channel");
  const toPage = (obj) =>
    chan.dispatchEvent(new CustomEvent("phprotect:to-page", { detail: JSON.stringify(obj) }));
  chan.addEventListener("phprotect:hello", () => chan.remove(), { once: true });

  let risky = false;
  let trusted = false;
  let paused = false;
  let settings = { seed: true, wallet: true, clipboard: true, audit: true };
  const reply = (obj) => toPage({ type: "sync", ...obj });

  const str = (x) => (typeof x === "string" ? x.slice(0, 200) : "");
  const toBackground = (kind, v, extra) =>
    send({
      type: "risk",
      kind,
      extra: { method: str(extra && extra.method) },
      verdict: {
        code: str(v.code),
        risky: !!v.risky,
        level: str(v.level),
        f: {
          who: str(v.f && v.f.who),
          token: str(v.f && v.f.token),
          domain: str(v.f && v.f.domain),
          amount: str(v.f && v.f.amount),
          unlimited: !!(v.f && v.f.unlimited),
          chain: str(v.f && v.f.chain),
          deadline: str(v.f && v.f.deadline),
          name: str(v.f && v.f.name),
          origin: str(v.f && v.f.origin),
          from: str(v.f && v.f.from),
          to: str(v.f && v.f.to),
          selector: str(v.f && v.f.selector),
          count: Number(v.f && v.f.count) || 0,
        },
      },
      frame: location.hostname,
    });

  function shownInCode(text) {
    const snippet = String(text).trim().slice(0, 60);
    if (!snippet || !document.body) return false;
    for (const el of document.querySelectorAll("pre, code, kbd, samp")) {
      if (!el.textContent.includes(snippet)) continue;
      const r = el.getBoundingClientRect();
      const cs = getComputedStyle(el);
      if (
        r.width > 4 &&
        r.height > 4 &&
        r.right > 0 &&
        r.bottom > 0 &&
        cs.visibility !== "hidden" &&
        Number(cs.opacity) > 0.1
      )
        return true;
    }
    return false;
  }

  function selectedText() {
    const a = document.activeElement;
    if (
      a &&
      (a.tagName === "TEXTAREA" || a.tagName === "INPUT") &&
      typeof a.selectionStart === "number"
    ) {
      return a.value.slice(a.selectionStart, a.selectionEnd);
    }
    const sel = window.getSelection && window.getSelection();
    return sel ? sel.toString() : "";
  }

  function clipDecision(d) {
    if (!settings.clipboard) return false;
    let text = typeof d.text === "string" ? d.text : "";
    if (d.via === "execCommand") {
      const cmd = String(d.cmd).toLowerCase();
      if (cmd !== "copy" && cmd !== "cut") return false;
      text = selectedText();
    }
    if (d.via === "setData") {
      const ev = window.event;
      if (!/^text(\/plain)?$/i.test(String(d.format))) return false;
      if (ev && ev.type !== "copy" && ev.type !== "cut") return false;
    }
    const tier = RULES.clipboardTier(text);
    if (!tier) return false;
    if (tier === "install" && !risky && shownInCode(text)) return false;
    toBackground("clipboard", RULES.classifyClipboard(text));
    return true;
  }

  chan.addEventListener("phprotect:to-ext", (e) => {
    let d;
    try {
      d = JSON.parse(e.detail);
    } catch {
      return;
    }
    if (!d || typeof d.type !== "string") return;

    if (d.type === "clip") return reply({ block: clipDecision(d) });

    if (d.type === "clipread") {
      if (settings.clipboard) send({ type: "event", code: "clip-read", frame: location.hostname });
      return;
    }

    if (d.type === "sig" && typeof d.id === "string") {
      if (paused || !settings.wallet) return reply({ id: d.id, verdict: "allow" });
      let v = null;
      try {
        v = RULES.classify(String(d.method), d.params, { risky });
      } catch {
        v = null;
      }
      if (!v) return reply({ id: d.id, verdict: "allow" });
      // A trusted site skips the medium nag, but never the high-risk ones.
      if (trusted && v.level !== "high") return reply({ id: d.id, verdict: "allow" });
      reply({ id: d.id, verdict: "ask" });
      toBackground("signature", v, { method: d.method }).then((res) => {
        // Fail safe: no answer means cancel.
        toPage({ type: "res", id: d.id, allow: !!(res && res.allow) });
      });
    }
  });

  (document.documentElement || document).appendChild(chan);
  chan.dispatchEvent(new CustomEvent("phprotect:channel", { bubbles: true }));
  setTimeout(() => chan.remove(), 0);

  const applyStatus = (st) => {
    if (!st) return;
    if (typeof st.risky === "boolean") risky = st.risky;
    if (typeof st.trusted === "boolean") trusted = st.trusted;
    if (typeof st.paused === "boolean") paused = st.paused;
    if (st.settings && typeof st.settings === "object") {
      settings = {
        seed: st.settings.seed !== false,
        wallet: st.settings.wallet !== false,
        clipboard: st.settings.clipboard !== false,
        audit: st.settings.audit !== false,
      };
    }
  };
  send({ type: "status?" }).then(applyStatus);
  try {
    chrome.runtime.onMessage.addListener((msg, sender, respond) => {
      if (msg && msg.type === "settings") applyStatus(msg);
      if (msg && msg.type === "risk-status") applyStatus(msg);
      if (msg && msg.type === "health?") respond({ ok: true });
    });
  } catch {
    /* ignore */
  }

  // ---- Seed Shield --------------------------------------------------------------------
  const SEED_VERDICT = { code: "seed", f: {} };
  const reportSeed = () => toBackground("seed", SEED_VERDICT);

  let busy = false;
  let bypassUntil = 0;
  let tripped = [];
  let seedTripAt = 0;

  const isEditable = (el) =>
    el &&
    !el.disabled &&
    !el.readOnly &&
    (el.isContentEditable ||
      el.tagName === "TEXTAREA" ||
      (el.tagName === "INPUT" &&
        /^(text|password|search|email|tel|url|number|)$/i.test(el.type || "")));

  const getVal = (el) => (el.isContentEditable ? el.innerText : el.value);
  const setVal = (el, v) => {
    if (el.isContentEditable) el.innerText = v;
    else {
      const proto =
        el.tagName === "TEXTAREA" ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
      const desc = Object.getOwnPropertyDescriptor(proto, "value");
      if (desc && desc.set) desc.set.call(el, v);
      else el.value = v;
    }
    el.dispatchEvent(new Event("input", { bubbles: true }));
  };

  function allFields(root = document, out = []) {
    for (const el of root.querySelectorAll("*")) {
      if (
        (el.tagName === "INPUT" ||
          el.tagName === "TEXTAREA" ||
          (el.isContentEditable && el.childElementCount === 0)) &&
        isEditable(el)
      )
        out.push(el);
      if (el.shadowRoot) allFields(el.shadowRoot, out);
    }
    return out;
  }

  async function trip(fields, replacement) {
    if (busy) return;
    fields = [...new Set(fields)].slice(0, 40);
    if (!fields.length) return;
    busy = true;
    seedTripAt = Date.now();
    const saved = fields.map((el) => [el, replacement === undefined ? getVal(el) : replacement]);
    saved.forEach(([el]) => setVal(el, ""));
    tripped = fields;
    const res = await reportSeed();
    tripped = [];
    if (res && res.allow) {
      bypassUntil = Date.now() + 5000;
      saved.forEach(([el, v]) => setVal(el, v));
    }
    saved.length = 0;
    busy = false;
  }

  const isSingleSeedWord = (v) => {
    v = String(v || "")
      .trim()
      .toLowerCase();
    return /^[a-z]{3,8}$/.test(v) && BIP39.has(v);
  };

  function scan(target) {
    if (busy) {
      if (tripped.indexOf(target) !== -1 && getVal(target)) setVal(target, "");
      return;
    }
    if (!settings.seed || Date.now() < bypassUntil || !isEditable(target)) return;
    const value = getVal(target);
    const hint = target.isContentEditable ? "normal" : fieldHint(target);
    // A just-pasted seed fires both paste and input; don't double trip.
    if (Date.now() - seedTripAt < 900 && !value) return;
    const min = hint === "seed" ? 3 : hint === "password" ? 12 : 6;
    if (hint !== "search" && looksLikeTypedSeed(value, min)) return trip([target]);

    // Seed split over single-word boxes. Stay within one form first; only fall
    // back to the whole document when the boxes are obviously part of a set.
    if (isSingleSeedWord(value)) {
      const form = target.closest && target.closest("form");
      if (form) {
        const group = allFields(form).filter((el) => isSingleSeedWord(getVal(el)));
        if (group.length >= 4) return trip(group);
      }
      const all = allFields();
      const group = all.filter((el) => isSingleSeedWord(getVal(el)));
      if (group.length >= 6) return trip(group);
    }
  }

  const realTarget = (e) => (e.composedPath && e.composedPath()[0]) || e.target;

  // Stop ordinary typed text before the input mutation where the browser permits it.
  // A hostile page can still observe earlier keystrokes or use unsupported editors.
  window.addEventListener(
    "beforeinput",
    (e) => {
      const target = realTarget(e);
      if (
        !settings.seed ||
        busy ||
        Date.now() < bypassUntil ||
        !isEditable(target) ||
        target.isContentEditable ||
        !e.cancelable ||
        typeof e.data !== "string" ||
        typeof target.selectionStart !== "number"
      )
        return;
      const hint = fieldHint(target);
      if (hint === "search") return;
      const prospective =
        target.value.slice(0, target.selectionStart) +
        e.data +
        target.value.slice(target.selectionEnd);
      if (!looksLikeTypedSeed(prospective, hint === "seed" ? 3 : hint === "password" ? 12 : 6))
        return;
      e.preventDefault();
      e.stopImmediatePropagation();
      trip([target], prospective);
    },
    true
  );

  window.addEventListener("input", (e) => scan(realTarget(e)), true);

  window.addEventListener(
    "paste",
    (e) => {
      const target = realTarget(e);
      if (!settings.seed || Date.now() < bypassUntil || !isEditable(target)) return;
      const text = e.clipboardData && e.clipboardData.getData("text");
      if (!looksLikePastedSeed(text)) return;
      e.preventDefault();
      e.stopImmediatePropagation();
      if (busy) return;
      busy = true;
      seedTripAt = Date.now();
      reportSeed().then((res) => {
        busy = false;
        if (res && res.allow) {
          bypassUntil = Date.now() + 5000;
          target.focus();
          try {
            if (!document.execCommand("insertText", false, text)) setVal(target, text);
          } catch {
            setVal(target, text);
          }
        }
      });
    },
    true
  );
})();
