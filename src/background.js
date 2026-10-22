// PHProtect background (service worker / background page).
//
// * Passive PHP2Shell verdict from headers the browser already received.
// * Page-audit findings from the isolated content script.
// * One decision window per tab, with a queue; every word comes from here.
// * Optional one-request re-check when the user asks for it.
//
// No PHProtect server, no analytics, no remote code.
"use strict";

if (
  typeof self !== "undefined" &&
  typeof self.PHProtectAssess === "undefined" &&
  typeof importScripts === "function"
) {
  importScripts("assess.js");
}
const A = (typeof self !== "undefined" ? self : globalThis).PHProtectAssess;

// Firefox exposes promises on `browser.*`; Chrome returns promises from
// `chrome.*` in MV3 and also defines a callback-only `browser` shim in some
// builds, so prefer a namespace that promises are known to work on.
const B =
  typeof browser !== "undefined" && browser && browser.runtime
    ? browser
    : typeof chrome !== "undefined"
      ? chrome
      : undefined;

const STORE_KEY = "tab_";
const WARN_TTL = 180000;
const RATE_WINDOW = 60000;
const RATE_MAX = 12;
const QUEUE_MAX = 25;
const QUEUE_MAX_NOTIFY = 6;
const RECHECK_TIMEOUT = 8000;

const DEFAULTS = {
  seed: true,
  wallet: true,
  clipboard: true,
  audit: true,
  notify: true,
};
const EVENT_CODES = Object.freeze(["clip-read", "clip-write", "seed-ask", "wallet-ask"]);
let settings = { ...DEFAULTS };
let trusted = {};
let paused = {};

// ---- state --------------------------------------------------------------------------
const keyOf = (tabId) => `${STORE_KEY}${tabId}`;
const hostOf = (url) => {
  try {
    return new URL(url).hostname.slice(0, 253);
  } catch {
    return "";
  }
};

const blankAudit = () => ({ findings: [], high: 0, medium: 0 });

const blankState = (host) => ({
  host: hostOf(host) || String(host || "").slice(0, 253),
  usesPhp: false,
  cms: [],
  phpVersions: [],
  signals: [],
  server: "",
  poweredBy: "",
  assessment: { status: "unknown", versions: [], reason: "no-version" },
  generator: "",
  audit: blankAudit(),
  events: [],
  checkedAt: 0,
  activeCheck: null,
});

async function getState(tabId) {
  if (tabId == null || tabId < 0) return null;
  const got = await B.storage.session.get(keyOf(tabId));
  return got[keyOf(tabId)] || null;
}

async function putState(tabId, state) {
  if (tabId == null || tabId < 0) return;
  await B.storage.session.set({ [keyOf(tabId)]: state });
  await paintBadge(tabId, state);
  B.tabs.sendMessage(tabId, { type: "risk-status", risky: A.isRisky(state) }).catch(() => {});
}

// Serialize read/modify/write operations so concurrent headers, audits and
// guard events cannot silently overwrite one another.
const stateWrites = new Map();
function updateState(tabId, update, initialHost = "") {
  const previous = stateWrites.get(tabId) || Promise.resolve();
  const task = previous
    .catch(() => {})
    .then(async () => {
      const state = await getState(tabId);
      const next = update(state || blankState(initialHost));
      if (next) await putState(tabId, next);
      return next;
    });
  stateWrites.set(tabId, task);
  task
    .finally(() => {
      if (stateWrites.get(tabId) === task) stateWrites.delete(tabId);
    })
    .catch(() => {});
  return task;
}

async function paintBadge(tabId, state) {
  const { text, color } = A.badgeFor(state);
  try {
    await B.action.setBadgeText({ tabId, text });
    await B.action.setBadgeBackgroundColor({ tabId, color });
    await B.action.setTitle({
      tabId,
      title: text ? `PHProtect: ${A.statusLabel(state.assessment.status)}` : "PHProtect",
    });
  } catch {
    /* tab gone */
  }
}

function mergeHeaders(state, headers, url) {
  const info = A.analyseHeaders(headers);
  state.host = hostOf(url) || state.host;
  state.usesPhp = info.usesPhp;
  state.phpVersions = info.phpVersions;
  state.cms = [...new Set([...(state.cms || []), ...info.cms])];
  state.signals = info.signals;
  state.server = info.server;
  state.poweredBy = info.poweredBy;
  state.assessment = A.assessPhp(state.phpVersions);
  state.checkedAt = Date.now();
  if (state.cms.length) state.usesPhp = true;
  return state;
}

// ---- warning text -------------------------------------------------------------------
const reAddr = /^0x[0-9a-fA-F]{40}$/;
const reName = /^[\w .\-+:]{1,40}$/;
const reSelector = /^0x[0-9a-f]{8}$/;

const fAddr = (a) =>
  reAddr.test(String(a || "")) ? `${a.slice(0, 6)}\u2026${a.slice(-4)}` : "an unknown address";
const fName = (s) => (reName.test(String(s || "")) ? String(s) : "an unknown contract");
const fOrigin = (s) => {
  let v = String(s || "");
  if (!v || v.length > 300) return "";
  if (!/^[a-z]+:\/\//i.test(v)) v = `https://${v}`;
  try {
    const u = new URL(v);
    if (!/^https?:$/.test(u.protocol)) return "";
    return `${u.hostname}`.slice(0, 80);
  } catch {
    return "";
  }
};
const fChain = (s) => {
  const n = /^\d{1,10}$/.test(String(s || "")) ? String(s) : "";
  if (!n) return "";
  return RULES_CHAINS[n] ? `${RULES_CHAINS[n]} (${n})` : `chain ${n}`;
};
const fDeadline = (s) => {
  const n = Number(s);
  if (!Number.isFinite(n) || n < 1e9 || n > 4e9) return "";
  try {
    return new Date(n * 1000).toLocaleString();
  } catch {
    return "";
  }
};
const fAmount = (s) => {
  const v = String(s || "");
  if (v === "UNLIMITED") return "UNLIMITED";
  if (!/^\d{1,78}$/.test(v)) return "";
  try {
    const b = BigInt(v);
    return b < 10000n ? v : `${b.toString().slice(0, 5)}\u2026`;
  } catch {
    return "";
  }
};
const fCount = (n) => (Number.isInteger(n) && n > 0 && n < 1000 ? String(n) : "");

const RULES_CHAINS = {
  1: "Ethereum",
  10: "Optimism",
  56: "BNB Chain",
  100: "Gnosis",
  137: "Polygon",
  250: "Fantom",
  324: "zkSync",
  8453: "Base",
  42161: "Arbitrum One",
  43114: "Avalanche",
  59144: "Linea",
  534352: "Scroll",
  7777777: "Zora",
  81457: "Blast",
  11155111: "Sepolia",
};

const EXPOSED_NOTE =
  "This site advertises an unpatched PHP version or an unsupported branch. Backported fixes may exist; compromise is not confirmed.";

const row = (label, value) => (value ? [label, value] : null);
const rows = (...list) => list.filter(Boolean);

const TEMPLATES = {
  "approve-unlimited": (f) => ({
    level: "high",
    title: "Unlimited token approval",
    reasons: [
      `Lets ${fAddr(f.who)} spend UNLIMITED amounts of token ${fAddr(f.token)} from your wallet, at any time.`,
      "Drainers use unlimited approvals to empty wallets later without asking again.",
    ],
    rows: rows(
      row("Spender", fAddr(f.who)),
      row("Token", fAddr(f.token)),
      row("Amount", "UNLIMITED")
    ),
  }),
  approve: (f) => ({
    level: "medium",
    title: "Token approval",
    reasons: [
      `Lets ${fAddr(f.who)} spend ${fAmount(f.amount) || "a set amount"} of token ${fAddr(f.token)} from your wallet.`,
      "Only approve contracts you trust.",
    ],
    rows: rows(
      row("Spender", fAddr(f.who)),
      row("Token", fAddr(f.token)),
      row("Amount", fAmount(f.amount))
    ),
  }),
  allowance: (f) => ({
    level: f.unlimited ? "high" : "medium",
    title: "Token allowance increase",
    reasons: [
      `Lets ${fAddr(f.who)} spend ${f.unlimited ? "UNLIMITED amounts more" : "more"} of token ${fAddr(f.token)}.`,
    ],
    rows: rows(
      row("Spender", fAddr(f.who)),
      row("Token", fAddr(f.token)),
      row("Amount", fAmount(f.amount))
    ),
  }),
  "approval-for-all": (f) => ({
    level: "high",
    title: "Approval for ALL your NFTs",
    reasons: [
      `Gives ${fAddr(f.who)} control of every NFT you hold in collection ${fAddr(f.token)}.`,
      "This is the number one trick NFT drainers use.",
    ],
    rows: rows(row("Operator", fAddr(f.who)), row("Collection", fAddr(f.token))),
  }),
  "permit2-approve": (f) => ({
    level: "high",
    title: "Permit2 approval",
    reasons: [
      `Lets ${fAddr(f.who)} move ${f.unlimited ? "UNLIMITED amounts" : "a set amount"} of token ${fAddr(f.token)} through Permit2.`,
    ],
    rows: rows(
      row("Spender", fAddr(f.who)),
      row("Token", fAddr(f.token)),
      row("Amount", "UNLIMITED")
    ),
  }),
  "permit-onchain": (f) => ({
    level: "high",
    title: "On-chain token permit",
    reasons: [
      `Approves ${fAddr(f.who)} for ${f.unlimited ? "UNLIMITED amounts" : "a set amount"} of token ${fAddr(f.token)} in this transaction.`,
    ],
    rows: rows(
      row("Spender", fAddr(f.who)),
      row("Token", fAddr(f.token)),
      row("Amount", fAmount(f.amount))
    ),
  }),
  permit: (f) => ({
    level: "high",
    title: "Permit signature (gasless approval)",
    reasons: [
      `Signing lets ${fAddr(f.who)} move your tokens (${fName(f.domain)}) without another transaction.`,
      "It costs no gas and looks harmless, which is exactly why drainers use it.",
    ],
    rows: rows(
      row("Spender", fAddr(f.who)),
      row("Token", fAddr(f.token)),
      row("App", fName(f.domain)),
      row("Chain", fChain(f.chain)),
      row("Expires", fDeadline(f.deadline))
    ),
  }),
  "permit2-signature": (f) => ({
    level: "high",
    title: "Permit2 gasless approval",
    reasons: [
      `Signing lets ${fAddr(f.who)} move ${fAmount(f.amount) || "tokens"} of ${fAddr(f.token)} through Permit2, with no further transaction.`,
    ],
    rows: rows(
      row("Spender", fAddr(f.who)),
      row("Token", fAddr(f.token)),
      row("Amount", fAmount(f.amount)),
      row("App", fName(f.domain)),
      row("Expires", fDeadline(f.deadline))
    ),
  }),
  "market-order": (f) => ({
    level: "high",
    title: "Marketplace order signature",
    reasons: [
      `This signs a ${fName(f.domain)} order${fCount(f.count) ? ` with ${f.count} items` : ""}. A malicious one can sell your assets for almost nothing.`,
      "Only sign if you are deliberately listing something on the real marketplace.",
    ],
    rows: rows(
      row("Marketplace", fName(f.domain)),
      row("Items", fCount(f.count)),
      row("Expires", fDeadline(f.deadline))
    ),
  }),
  delegation: (f) => ({
    level: "high",
    title: "Delegation / authorization signature",
    reasons: [
      `Signing hands control of your account or assets${fAddr(f.who) !== "an unknown address" ? ` to ${fAddr(f.who)}` : ""} until you revoke it.`,
    ],
    rows: rows(
      row("Delegate", fAddr(f.who)),
      row("App", fName(f.domain)),
      row("Expires", fDeadline(f.deadline))
    ),
  }),
  eip7702: (f) => ({
    level: "high",
    title: "Account delegation (EIP-7702)",
    reasons: [
      `This lets ${fAddr(f.who)} act as your account. A malicious delegation can move everything you own without another prompt.`,
      "Only continue if you expected your wallet to be upgraded or delegated.",
    ],
    rows: rows(row("Delegate", fAddr(f.who))),
  }),
  "eth-sign": () => ({
    level: "high",
    title: "Blind signature (eth_sign)",
    reasons: [
      "eth_sign signs a raw hash you cannot read. It can authorize almost anything, including draining the wallet.",
    ],
    rows: [],
  }),
  "blind-hash": () => ({
    level: "high",
    title: "Blind hash signature",
    reasons: [
      "You are asked to sign a 32-byte hash, not readable text. You cannot tell what it authorizes.",
    ],
    rows: [],
  }),
  "signature-text": (f) => ({
    level: "medium",
    title: "Signature with approval wording",
    reasons: [
      "The page's own wording mentions approval or spending rights. The wallet is the only source of truth.",
      "Read the request in your wallet before signing.",
    ],
    rows: [],
  }),
  "transfer-from": (f) => ({
    level: "medium",
    title: "Token transfer pulls from your wallet",
    reasons: [
      `Moves token ${fAddr(f.token)} from ${fAddr(f.from)} to ${fAddr(f.to)}.`,
      "The contract needs an allowance to do this.",
    ],
    rows: rows(
      row("Token", fAddr(f.token)),
      row("From", fAddr(f.from)),
      row("To", fAddr(f.to)),
      row("Amount", fAmount(f.amount))
    ),
  }),
  "nft-transfer": (f) => ({
    level: "medium",
    title: "NFT transfer",
    reasons: [`Moves an NFT from ${fAddr(f.from)} to ${fAddr(f.to)}.`],
    rows: rows(
      row("Collection", fAddr(f.token)),
      row("From", fAddr(f.from)),
      row("To", fAddr(f.to))
    ),
  }),
  "payable-call": (f) => ({
    level: "medium",
    title: "Sends ETH to a contract",
    reasons: [
      "The call sends value but carries no readable instruction. Make sure you know what the contract does with it.",
    ],
    rows: rows(row("Contract", fAddr(f.who)), row("Amount (wei)", fAmount(f.amount))),
  }),
  "create-contract": () => ({
    level: "medium",
    title: "Deploys a new contract",
    reasons: ["This transaction creates a contract instead of calling one."],
    rows: [],
  }),
  multicall: (f) => ({
    level: "medium",
    title: "Batched contract call",
    reasons: [
      "Several contract calls go out at once, so one confirmation can hide another action.",
      "Check every step in your wallet.",
    ],
    rows: rows(
      row("Calls", fCount(f.count)),
      row("Selector", reSelector.test(f.selector || "") ? f.selector : "")
    ),
  }),
  "batched-call": () => ({
    level: "medium",
    title: "Batched contract call",
    reasons: ["A contract call is bundled in this batch."],
    rows: [],
  }),
  "chain-add": (f) => ({
    level: "high",
    title: "Adds a custom network",
    reasons: [
      "A page can add a network with its own RPC server. That server decides which balances and chain state you see, and can quietly redirect transactions.",
      "Only continue if you recognise the network name.",
    ],
    rows: rows(
      row("Network", fName(f.name)),
      row("Chain", fChain(f.chain)),
      row("RPC", fOrigin(f.origin))
    ),
  }),
  "chain-switch": (f) => ({
    level: "medium",
    title: `Switch network to ${fChain(f.chain) ? RULES_CHAINS[String(f.chain)] || "an unknown chain" : "an unknown chain"}`,
    reasons: [
      "The site wants your wallet pointed at a different chain. Tokens and approvals live per chain.",
    ],
    rows: rows(row("Chain", fChain(f.chain))),
  }),
  "watch-asset": (f) => ({
    level: "medium",
    title: "Adds a token to your wallet",
    reasons: ["Anyone can create a token with any name. A fake one can be made to look valuable."],
    rows: rows(row("Symbol", fName(f.name)), row("Contract", fAddr(f.token))),
  }),
  "grant-permissions": () => ({
    level: "high",
    title: "Grants spending permissions (EIP-7715)",
    reasons: [
      "A permission gives another account ongoing rights over your tokens, often without a prompt next time.",
    ],
    rows: [],
  }),
  "exposed-site": () => ({
    level: "medium",
    title: "Wallet request on an exposed site",
    reasons: [EXPOSED_NOTE, "Check every detail in your wallet before approving."],
    rows: [],
  }),
  clickfix: () => ({
    level: "high",
    title: "A website put a command in your clipboard",
    reasons: [
      'This is the ClickFix trick: a fake "verify you are human" or "fix this error" page asks you to paste a command into Run, Terminal or PowerShell.',
      "PHProtect replaced it with a harmless notice. Never paste commands a website hands you.",
    ],
    rows: [],
  }),
  seed: () => ({
    level: "high",
    title: "This looks like a seed phrase",
    reasons: [
      "Do not give a recovery phrase to a website or support agent. It can grant control of your wallet.",
      "PHProtect stopped this input or cleared the detected text. A page may already have observed earlier words.",
      "If you shared a real phrase with an untrusted site, treat the wallet as compromised. Restore text only if you understand the risk.",
    ],
    rows: [],
  }),
};

const KIND_OF = {
  clickfix: "clipboard",
  seed: "seed",
  "clip-read": "clipboard",
};
const KNOWN_CODES = new Set(Object.keys(TEMPLATES));

function render(verdict, siteRisky) {
  if (!verdict || !KNOWN_CODES.has(verdict.code)) return null;
  const f = verdict.f || {};
  const built = TEMPLATES[verdict.code](f);
  const out = {
    level: built.level,
    title: built.title,
    reasons: [...built.reasons],
    rows: [...(built.rows || [])],
  };
  if ((siteRisky || verdict.risky) && !KIND_OF[verdict.code] && verdict.code !== "exposed-site") {
    out.reasons.unshift(EXPOSED_NOTE);
  }
  return out;
}

// ---- audit text ----------------------------------------------------------------------
const AUDIT = {
  "http-page": ["medium", "Page is not HTTPS"],
  "pw-http": ["high", "Password form on a non-HTTPS page"],
  "pw-cross-origin": ["high", "Password form posts to another site"],
  "pw-no-autocomplete": ["info", "Password field has no autocomplete hint"],
  "hidden-iframe": ["high", "Hidden cross-site iframe"],
  "cross-origin-iframe": ["info", "Cross-site iframe"],
  "base-hijack": ["medium", "Base URL points to another site"],
  "clickfix-text": ["high", "Page text asks to paste a command into Run or Terminal"],
  "hidden-textarea": ["medium", "Hidden command box"],
  "obfuscated-script": ["medium", "Heavily obfuscated inline script"],
  "wallet-hooks": ["info", "Page drives a crypto wallet"],
  "foreign-scripts": ["info", "Many third-party script origins"],
  "mixed-content": ["medium", "HTTP resource on an HTTPS page"],
  "meta-refresh": ["medium", "Redirects to another site"],
  "foreign-download": ["info", "Downloads a file from another site"],
  "many-forms": ["info", "Many forms on one page"],
  "mixed-script": ["high", "Hostname mixes alphabets (homograph)"],
  "brand-lookalike": ["high", "Hostname imitates a known brand"],
  "brand-in-name": ["medium", "Brand name inside an unofficial hostname"],
  "broken-punycode": ["medium", "Malformed international hostname"],
  "odd-hostname": ["medium", "Unusual international hostname"],
};

const auditValue = (code, v) => {
  if (!v) return "";
  if (
    /^https?:|^[a-z0-9.-]+\.[a-z]{2,}$/i.test(v) &&
    [
      "pw-cross-origin",
      "hidden-iframe",
      "cross-origin-iframe",
      "base-hijack",
      "mixed-content",
      "meta-refresh",
      "foreign-download",
    ].includes(code)
  )
    return fOrigin(v);
  if (code === "http-page") return String(v).slice(0, 80);
  if (["many-forms", "foreign-scripts", "obfuscated-script"].includes(code))
    return /^\d{1,6}$/.test(v) ? v : "";
  return String(v).slice(0, 80);
};

// ---- settings ------------------------------------------------------------------------
async function loadSettings() {
  try {
    const got = await B.storage.local.get(["settings", "trusted", "paused"]);
    settings = { ...DEFAULTS, ...(got.settings || {}) };
    trusted = got.trusted && typeof got.trusted === "object" ? got.trusted : {};
    paused = got.paused && typeof got.paused === "object" ? got.paused : {};
  } catch {
    /* defaults */
  }
}
const settingsLoaded = B ? loadSettings() : Promise.resolve();

async function broadcast(host) {
  // An empty host means a global toggle: push it to every tab. Only per-site
  // flags need to be narrowed to the matching host.
  const tabs = await B.tabs.query({});
  for (const tab of tabs) {
    if (!tab.id) continue;
    const tabHost = hostOf(tab.url);
    if (host && tabHost !== host) continue;
    B.tabs
      .sendMessage(tab.id, {
        type: "settings",
        settings,
        trusted: !!trusted[tabHost],
        paused: !!paused[tabHost],
      })
      .catch(() => {});
  }
}

async function setSetting(name, value, host) {
  if (["seed", "wallet", "clipboard", "audit", "notify"].includes(name)) {
    settings = { ...settings, [name]: !!value };
    await B.storage.local.set({ settings });
  } else if (name === "trusted" && host) {
    trusted = { ...trusted, [host]: !!value };
    if (!value) delete trusted[host];
    await B.storage.local.set({ trusted });
  } else if (name === "paused" && host) {
    paused = { ...paused, [host]: !!value };
    if (!value) delete paused[host];
    await B.storage.local.set({ paused });
  } else return null;
  await broadcast(["trusted", "paused"].includes(name) ? host : "");
  return { settings, trusted: !!trusted[host], paused: !!paused[host] };
}

// ---- warning windows -----------------------------------------------------------------
const pending = new Map(); // id -> item
const sessions = new Map(); // "tab:frame" -> session
const windowKey = new Map(); // windowId -> key
const recent = new Map(); // "tab:frame" -> [timestamps]
const navigationVersions = new Map();

function event(tabId, code) {
  if (!EVENT_CODES.includes(code)) return;
  updateState(tabId, (state) => {
    state.events.push({ code, at: Date.now() });
    state.events = state.events.slice(-20);
    return state;
  }).catch(() => {});
}

function safeToken() {
  try {
    return crypto.randomUUID();
  } catch {
    return `${Date.now().toString(36)}${Math.random().toString(36).slice(2)}`;
  }
}

function finish(id, allow) {
  const item = pending.get(id);
  if (!item || item.done) return;
  item.done = true;
  if (item.timer) clearTimeout(item.timer);
  try {
    item.respond({ allow: !!allow });
  } catch {
    /* tab gone */
  }
  pending.delete(id);

  const session = sessions.get(item.key);
  if (!session) return;
  if (session.currentId !== id) {
    session.queue = session.queue.filter((queued) => queued !== id);
    return;
  }
  if (session.currentId === id) session.currentId = null;
  if (session.queue.length) {
    if (session.windowId != null) {
      const w = session.windowId;
      session.windowId = null;
      windowKey.delete(w);
      B.windows.remove(w).catch(() => {});
    }
    return pump(session);
  }
  if (session.windowId != null) {
    const w = session.windowId;
    session.windowId = null;
    windowKey.delete(w);
    B.windows.remove(w).catch(() => {});
  }
  sessions.delete(item.key);
}

async function pump(session) {
  if (sessions.get(session.key) !== session) return;
  if (session.windowId != null || session.currentId) return;
  if (!session.queue.length) {
    sessions.delete(session.key);
    return;
  }
  const id = session.queue.shift();
  const item = pending.get(id);
  if (!item) return pump(session);
  session.currentId = id;
  if (Date.now() >= item.info.expiresAt) {
    finish(id, false);
    return;
  }
  try {
    const win = await B.windows.create({
      url: B.runtime.getURL(
        `warning.html?sid=${encodeURIComponent(session.key)}&token=${session.token}&id=${encodeURIComponent(id)}`
      ),
      type: "popup",
      width: 480,
      height: 680,
      focused: true,
    });
    if (sessions.get(session.key) !== session || !pending.has(id)) {
      B.windows.remove(win.id).catch(() => {});
      return;
    }
    session.windowId = win.id;
    windowKey.set(win.id, session.key);
  } catch {
    finish(id, false);
  }
}

async function openWarning(msg, sender, respond) {
  const revision = navigationVersions.get(sender.tab.id) || 0;
  const verdictIn = msg && msg.verdict;
  const host = (sender.tab && sender.tab.url && hostOf(sender.tab.url)) || "";
  const kind =
    (verdictIn && KIND_OF[verdictIn.code]) || (msg.kind === "signature" ? "signature" : "");
  if (
    !verdictIn ||
    !kind ||
    (msg.kind === "signature" && kind !== "signature") ||
    (msg.kind === "seed" && kind !== "seed") ||
    (msg.kind === "clipboard" && kind !== "clipboard")
  ) {
    return respond({ allow: false });
  }
  if (kind === "signature" && (!settings.wallet || paused[host])) return respond({ allow: true });
  if (kind === "seed" && !settings.seed) return respond({ allow: true });
  if (kind === "clipboard" && !settings.clipboard) return respond({ allow: true });

  const state = sender.tab && sender.tab.id != null ? await getState(sender.tab.id) : null;
  if ((navigationVersions.get(sender.tab.id) || 0) !== revision) return respond({ allow: false });
  const verdict = render(verdictIn, A.isRisky(state));
  // Fail closed on an unknown code.
  if (!verdict) return respond({ allow: false });
  if (kind === "signature" && verdict.level !== "high" && trusted[host])
    return respond({ allow: true });

  const notifyOnly = kind === "clipboard";
  if (notifyOnly && settings.notify === false) {
    event(sender.tab.id, "clip-write");
    return respond({ allow: true });
  }
  // One shared queue/window per tab, including subframes, prevents frame spam.
  const key = `${sender.tab.id}:tab`;
  const now = Date.now();
  const times = (recent.get(key) || []).filter((t) => now - t < RATE_WINDOW);
  const session = sessions.get(key) || {
    key,
    id: safeToken(),
    token: safeToken(),
    windowId: null,
    currentId: null,
    queue: [],
    host,
    tabId: sender.tab && sender.tab.id,
  };

  if (times.length >= RATE_MAX) {
    return respond({ allow: notifyOnly ? true : false });
  }
  const max = notifyOnly ? QUEUE_MAX_NOTIFY : QUEUE_MAX;
  if (session.queue.length + (session.currentId ? 1 : 0) >= max) {
    return respond({ allow: notifyOnly ? true : false });
  }
  // A second seed trip in the same frame is almost always the same phrase.
  if (
    kind === "seed" &&
    pending.size &&
    [...pending.values()].some((p) => p.key === key && p.kind === "seed" && !p.done)
  ) {
    return respond({ allow: false });
  }

  times.push(now);
  recent.set(key, times);
  event(
    sender.tab.id,
    kind === "seed" ? "seed-ask" : kind === "clipboard" ? "clip-write" : "wallet-ask"
  );

  const id = safeToken();
  const item = {
    id,
    key,
    kind,
    notifyOnly,
    done: false,
    respond: notifyOnly ? () => {} : respond,
    info: {
      kind,
      verdict,
      method: /^[a-zA-Z0-9_]{1,40}$/.test((msg.extra && msg.extra.method) || "")
        ? msg.extra.method
        : "",
      host,
      frame: hostOf(sender.url),
      siteStatus: state ? state.assessment.status : "unknown",
      notifyOnly,
      createdAt: now,
      expiresAt: now + WARN_TTL,
    },
  };
  pending.set(id, item);
  // Deadlines include queue time; stale requests must never be approved later.
  item.timer = setTimeout(() => finish(id, false), WARN_TTL);
  if (notifyOnly) respond({ allow: true });

  if (!sessions.has(key)) sessions.set(key, session);
  session.queue.push(id);
  pump(session);
}

function cancelSession(key) {
  const session = sessions.get(key);
  if (!session) return;
  sessions.delete(key);
  if (session.currentId) finish(session.currentId, false);
  for (const id of session.queue.splice(0)) finish(id, false);
  if (session.windowId != null) {
    windowKey.delete(session.windowId);
    B.windows.remove(session.windowId).catch(() => {});
    session.windowId = null;
  }
}

// ---- messages ------------------------------------------------------------------------
const extensionRoot = B ? B.runtime.getURL("") : "";
const ownPage = (sender) => {
  const url = String((sender && sender.url) || "");
  return url === extensionRoot.slice(0, -1) || url.startsWith(extensionRoot);
};

if (B && B.runtime)
  B.runtime.onMessage.addListener((msg, sender, respond) => {
    if (!msg || typeof msg.type !== "string") return;
    const fromPage = !!sender.tab && !ownPage(sender);
    const pageHost = fromPage ? hostOf(sender.tab.url) : "";

    if (msg.type === "status?") {
      const tabId = fromPage
        ? sender.tab.id
        : Number.isInteger(msg.tabId)
          ? msg.tabId
          : sender.tab && sender.tab.id;
      const host = pageHost || (typeof msg.host === "string" ? msg.host.slice(0, 253) : "");
      if (tabId == null && !host) return;
      settingsLoaded
        .then(async () => {
          const state = tabId != null ? await getState(tabId) : null;
          respond({
            risky: A.isRisky(state),
            settings,
            trusted: !!trusted[host],
            paused: !!paused[host],
          });
        })
        .catch(() => respond({ settings, trusted: false, paused: false, risky: false }));
      return true;
    }

    if (msg.type === "risk" && fromPage && msg.verdict) {
      settingsLoaded
        .then(() => openWarning(msg, sender, respond))
        .catch(() => respond({ allow: false }));
      return true;
    }

    if (msg.type === "audit" && fromPage) {
      if (!Array.isArray(msg.findings)) {
        respond({ ok: false });
        return;
      }
      const clean = [];
      for (const f of msg.findings.slice(0, 20)) {
        const def = f && Object.hasOwn(AUDIT, f.code) && AUDIT[f.code];
        if (!def) continue;
        clean.push({
          code: f.code,
          severity: def[0],
          value: auditValue(f.code, String(f.value || "")),
        });
      }
      settingsLoaded
        .then(() => {
          if (!settings.audit) {
            respond({ ok: false });
            return;
          }
          return updateState(
            sender.tab.id,
            (state) => {
              const seen = new Set(state.audit.findings.map((f) => `${f.code}|${f.value}`));
              for (const f of clean) {
                const k = `${f.code}|${f.value}`;
                if (seen.has(k)) continue;
                seen.add(k);
                state.audit.findings.push(f);
              }
              state.audit.findings = state.audit.findings.slice(-40);
              state.audit.high = state.audit.findings.filter((f) => f.severity === "high").length;
              state.audit.medium = state.audit.findings.filter(
                (f) => f.severity === "medium"
              ).length;
              return state;
            },
            pageHost
          ).then(() => respond({ ok: true }));
        })
        .catch(() => respond({ ok: false }));
      return true;
    }

    if (msg.type === "event" && fromPage) {
      if (["clip-read", "clip-write", "seed-ask", "wallet-ask"].includes(msg.code))
        event(sender.tab.id, msg.code);
      return;
    }

    if (msg.type === "cms-hints" && fromPage) {
      updateState(
        sender.tab.id,
        (state) => {
          const cms = Array.isArray(msg.cms)
            ? msg.cms.filter((c) => typeof c === "string" && /^[A-Za-z]{2,20}$/.test(c)).slice(0, 5)
            : [];
          state.cms = [...new Set([...state.cms, ...cms])];
          state.generator =
            typeof msg.generator === "string" ? msg.generator.slice(0, 80) : state.generator;
          if (state.cms.length) state.usesPhp = true;
          return state;
        },
        pageHost
      ).catch(() => {});
      return;
    }

    if (msg.type === "pending?" && ownPage(sender)) {
      const session = sessions.get(String(msg.sid || ""));
      const item = pending.get(String(msg.id || ""));
      if (
        !session ||
        !item ||
        session.token !== msg.token ||
        session.currentId !== item.id ||
        Date.now() >= item.info.expiresAt
      )
        return respond(null);
      respond({ ...item.info, queue: session.queue.length });
      return true;
    }

    if (msg.type === "decide" && ownPage(sender)) {
      const session = sessions.get(String(msg.sid || ""));
      const item = pending.get(String(msg.id || ""));
      if (!session || !item || session.token !== msg.token || session.currentId !== item.id)
        return respond({ ok: false });
      if (
        msg.allow === true &&
        (Date.now() >= item.info.expiresAt ||
          (item.info.verdict.level === "high" && msg.acknowledged !== true))
      )
        return respond({ ok: false });
      finish(item.id, msg.allow === true);
      respond({ ok: true });
      return true;
    }

    if (msg.type === "ping") {
      respond({ ok: true });
      return;
    }

    if (msg.type === "reset-preferences" && ownPage(sender)) {
      settingsLoaded
        .then(async () => {
          settings = { ...DEFAULTS };
          trusted = {};
          paused = {};
          await B.storage.local.set({ settings, trusted, paused });
          await broadcast("");
          respond({ ok: true });
        })
        .catch(() => respond({ ok: false }));
      return true;
    }

    if (msg.type === "set" && ownPage(sender)) {
      const host = typeof msg.host === "string" ? msg.host.slice(0, 253) : "";
      settingsLoaded
        .then(() => setSetting(msg.key, msg.value, host))
        .then((res) => respond(res || { ok: false }));
      return true;
    }

    if (msg.type === "recheck" && ownPage(sender)) {
      recheck(Number(msg.tabId))
        .then((r) => respond(r))
        .catch(() => respond({ ok: false, error: "network-error" }));
      return true;
    }
  });

// ---- header plumbing -----------------------------------------------------------------
if (B && B.webRequest) {
  const onHeaders = (details) => {
    if (details.tabId < 0 || !details.url || !/^https?:/i.test(details.url)) return;
    const url = details.url.split("#")[0];
    updateState(
      details.tabId,
      (state) => {
        const host = hostOf(url);
        if (!state || state.host !== host) {
          const fresh = blankState(host);
          fresh.events = state && state.host === host ? state.events : [];
          const merged = mergeHeaders(fresh, details.responseHeaders || [], url);
          return merged;
        }
        return mergeHeaders(state, details.responseHeaders || [], url);
      },
      hostOf(url)
    ).catch(() => {});
  };
  const filter = { urls: ["http://*/*", "https://*/*"], types: ["main_frame"] };
  B.webRequest.onBeforeRequest.addListener((details) => {
    if (details.tabId < 0) return;
    navigationVersions.set(details.tabId, (navigationVersions.get(details.tabId) || 0) + 1);
    updateState(details.tabId, () => blankState(hostOf(details.url))).catch(() => {});
    for (const k of recent.keys()) if (k.startsWith(`${details.tabId}:`)) recent.delete(k);
    for (const [k, session] of sessions) if (session.tabId === details.tabId) cancelSession(k);
  }, filter);
  try {
    B.webRequest.onHeadersReceived.addListener(onHeaders, filter, [
      "responseHeaders",
      "extraHeaders",
    ]);
  } catch {
    B.webRequest.onHeadersReceived.addListener(onHeaders, filter, ["responseHeaders"]);
  }

  B.windows.onRemoved.addListener((windowId) => {
    const key = windowKey.get(windowId);
    windowKey.delete(windowId);
    if (key) cancelSession(key);
  });

  B.tabs.onRemoved.addListener((tabId) => {
    navigationVersions.delete(tabId);
    const lastWrite = stateWrites.get(tabId) || Promise.resolve();
    lastWrite.finally(() => B.storage.session.remove(keyOf(tabId))).catch(() => {});
    for (const k of recent.keys()) if (k.startsWith(`${tabId}:`)) recent.delete(k);
    for (const [k, session] of sessions) if (session.tabId === tabId) cancelSession(k);
  });

  B.tabs.onUpdated.addListener((tabId, change) => {
    if (change.status !== "loading") return;
    // HTTP navigations reset in onBeforeRequest before headers arrive.
    // Loading events can arrive after response headers; never erase them here.
    for (const k of recent.keys()) if (k.startsWith(`${tabId}:`)) recent.delete(k);
    for (const [k, session] of sessions) if (session.tabId === tabId) cancelSession(k);
  });
}

// ---- optional active re-check --------------------------------------------------------
async function fetchHeaders(url) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), RECHECK_TIMEOUT);
  try {
    for (const method of ["HEAD", "GET"]) {
      const res = await fetch(url, {
        method,
        redirect: "manual",
        cache: "no-store",
        credentials: "omit",
        signal: ctrl.signal,
      });
      const headers = [];
      res.headers.forEach((value, name) => headers.push({ name, value }));
      try {
        await res.body?.cancel();
      } catch {
        /* ignore */
      }
      if (![405, 501].includes(res.status)) return { headers, status: res.status };
    }
  } finally {
    clearTimeout(timer);
  }
  return { headers: [], status: 0 };
}

async function recheck(tabId) {
  if (!Number.isInteger(tabId)) return { ok: false, error: "no-tab" };
  const tab = await B.tabs.get(tabId).catch(() => null);
  if (!tab || !/^https?:/i.test(tab.url || "")) return { ok: false, error: "not-http" };
  const revision = navigationVersions.get(tabId) || 0;
  // One request, and only when the user asks.
  const { headers, status } = await fetchHeaders(tab.url);
  const current = await B.tabs.get(tabId).catch(() => null);
  if (!current || current.url !== tab.url || (navigationVersions.get(tabId) || 0) !== revision)
    return { ok: false, error: "page-changed" };
  const merged = await updateState(
    tabId,
    (state) => {
      if ((navigationVersions.get(tabId) || 0) !== revision) return null;
      const result = mergeHeaders(state, headers, tab.url);
      result.activeCheck = { status, at: Date.now(), headers: headers.length };
      return result;
    },
    hostOf(tab.url)
  );
  if (!merged) return { ok: false, error: "page-changed" };
  return {
    ok: true,
    status: merged.assessment.status,
    found: merged.phpVersions.length,
  };
}

// Exported for Node tests.
if (typeof module !== "undefined" && module.exports) {
  module.exports = {
    render,
    TEMPLATES,
    AUDIT,
    auditValue,
    blankState,
    mergeHeaders,
    EVENT_CODES,
  };
}

if (B?.runtime?.onInstalled)
  B.runtime.onInstalled.addListener((details) => {
    if (details.reason === "install") B.runtime.openOptionsPage();
  });
