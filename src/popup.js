(async () => {
  "use strict";
  const B = typeof browser !== "undefined" && browser.runtime ? browser : chrome;
  const $ = (id) => document.getElementById(id);
  // Keep bundled English as a fallback for browser namespace/i18n differences.
  const messages = await fetch(B.runtime.getURL("_locales/en/messages.json"))
    .then((response) => response.json())
    .catch(() => ({}));
  const t = (key, fallback) =>
    chrome.i18n.getMessage(key) || messages[key]?.message || fallback || key;
  $("help").onclick = $("about").onclick = () => B.runtime.openOptionsPage();
  const translated = {
    tagline: "tagline",
    footer: "footer",
    findingsTitle: "findingsTitle",
    eventsTitle: "eventsTitle",
    guardTitle: "guardTitle",
    gSeed: "guardSeed",
    gWallet: "guardWallet",
    gClip: "guardClip",
    gAudit: "guardAudit",
    gNotify: "guardNotify",
    gTrusted: "guardTrusted",
    gPaused: "guardPaused",
    recheck: "recheck",
    copy: "copyReport",
    tell: "tellOwner",
  };
  for (const [id, key] of Object.entries(translated)) $(id).textContent = t(key, $(id).textContent);
  const send = (msg, ms = 3000) =>
    new Promise((resolve) => {
      let timer;
      const finish = (v) => {
        clearTimeout(timer);
        resolve(v);
      };
      timer = setTimeout(() => finish(null), ms);
      try {
        chrome.runtime.sendMessage(msg, (res) => finish(chrome.runtime.lastError ? null : res));
      } catch {
        finish(null);
      }
    });
  const flash = (text) => {
    $("msg").textContent = text;
  };
  const [tab] = await B.tabs.query({ active: true, currentWindow: true });
  const supported = !!tab && /^https?:\/\//i.test(tab.url || "");
  const host = supported ? new URL(tab.url).hostname : "";
  $("host").textContent = host || "Browser or restricted page";
  let s = null,
    live = null;
  const read = async () => {
    if (!supported) return;
    const got = await B.storage.session.get(`tab_${tab.id}`).catch(() => ({}));
    s = got[`tab_${tab.id}`] || null;
  };
  const pairs = [
    ["tSeed", "seed"],
    ["tWallet", "wallet"],
    ["tClip", "clipboard"],
    ["tAudit", "audit"],
    ["tNotify", "notify"],
    ["tTrusted", "trusted"],
    ["tPaused", "paused"],
  ];
  const labelFor = (code) => t(`audit_${code.replace(/-/g, "_")}`, code);
  function render() {
    const a = s?.assessment || { status: "unknown", versions: [] };
    let cls = "none",
      title = t("noData"),
      note = "Refresh headers for PHP evidence. Reload the page to start newly installed guards.";
    if (!supported) {
      title = "Checks unavailable here";
      note =
        "PHProtect works on ordinary HTTP and HTTPS pages. Browser pages, stores, PDFs and other protected documents may restrict extensions.";
    } else if (a.status === "vulnerable") {
      cls = "vulnerable";
      title = t("vulnTitle");
      note = t("vulnNote");
    } else if (a.status === "eol") {
      cls = "eol";
      title = t("eolTitle");
      note = t("eolNote");
    } else if (a.status === "patched") {
      cls = "patched";
      title = t("patchedTitle");
      note =
        "The advertised version meets the published PHP2Shell cutoff. This does not verify the server or the safety of this page.";
    } else if (s) {
      cls = "unknown";
      title = s.usesPhp || s.cms?.length ? t("hiddenTitle") : t("notPhp");
      note =
        a.reason === "unverified-branch"
          ? "This PHP branch is outside the bundled advisory data. Its patch status has not been verified."
          : t("hiddenNote");
    }
    $("assessment").className = `assessment ${cls}`;
    $("status").textContent = title;
    $("note").textContent = note;
    const details = $("details");
    details.textContent = "";
    const add = (k, v) => {
      if (!v) return;
      const dt = document.createElement("dt"),
        dd = document.createElement("dd");
      dt.textContent = k;
      dd.textContent = v;
      details.append(dt, dd);
    };
    if (s) {
      add(t("rowPhp"), a.versions?.slice(0, 2).join(", ") || t("rowNone"));
      add(t("rowNeeded"), a.needed);
      add(t("rowCms"), s.cms?.join(", "));
      add(t("rowServer"), s.server || s.poweredBy);
      add(
        t("rowRecheck"),
        s.activeCheck?.at
          ? `${new Date(s.activeCheck.at).toLocaleTimeString()}  -  HTTP ${s.activeCheck.status}`
          : ""
      );
    }
    $("recheck").disabled = !supported;
    $("copy").disabled = !s;
    $("tell").hidden = !["vulnerable", "eol"].includes(a.status);
    const findings = $("findings");
    findings.textContent = "";
    const rank = { high: 0, medium: 1, info: 2 };
    const items = [...(s?.audit?.findings || [])].sort(
      (a, b) => (rank[a.severity] ?? 2) - (rank[b.severity] ?? 2)
    );
    for (const f of items) {
      const li = document.createElement("li");
      li.className = f.severity;
      li.textContent = labelFor(f.code) + (f.value ? `  -  ${f.value}` : "");
      findings.append(li);
    }
    $("findingCount").textContent = String(items.length);
    $("findingsEmpty").hidden = !!items.length;
    $("findingsEmpty").textContent =
      live?.settings?.audit === false
        ? "Page checks are turned off. Previous signals remain until navigation."
        : "No signals reported. This does not verify the page is safe.";
    const events = $("events");
    events.textContent = "";
    for (const e of (s?.events || []).slice(-8).reverse()) {
      const li = document.createElement("li");
      li.textContent = `${t(`event_${e.code.replace(/-/g, "_")}`, e.code)}  -  ${new Date(e.at).toLocaleTimeString()}`;
      events.append(li);
    }
    $("eventsSection").hidden = !events.children.length;
    $("eventCount").textContent = String(s?.events?.length || 0);
    for (const [id, key] of pairs) {
      $(id).disabled = !live || (!host && ["trusted", "paused"].includes(key));
      $(id).checked = ["trusted", "paused"].includes(key)
        ? !!live?.[key]
        : live?.settings?.[key] !== false;
    }
    const exceptions = [];
    if (live?.paused) exceptions.push("Wallet guard is paused on this host.");
    if (live?.trusted) exceptions.push("Medium wallet warnings are skipped on this host.");
    const off = Object.entries(live?.settings || {}).filter(
      ([k, v]) => v === false && k !== "notify"
    ).length;
    if (off)
      exceptions.push(`${off} protection switch${off === 1 ? " is" : "es are"} off globally.`);
    $("exceptions").hidden = !exceptions.length;
    $("exceptions").textContent = exceptions.join(" ");
  }
  await read();
  live = await send({ type: "status?", tabId: tab?.id, host });
  render();
  try {
    const health =
      supported && (await B.tabs.sendMessage(tab.id, { type: "health?" }, { frameId: 0 }));
    $("coverage").textContent = health?.ok
      ? "Guards loaded. Website hooks are best effort."
      : "Reload this page to start guards. Some pages restrict extensions.";
  } catch {
    $("coverage").textContent = "Reload this page to start guards. Some pages restrict extensions.";
  }
  B.storage.onChanged.addListener(async (changes, area) => {
    if (area === "session" && changes[`tab_${tab?.id}`]) {
      await read();
      render();
    }
  });
  for (const [id, key] of pairs)
    $(id).onchange = async () => {
      $(id).disabled = true;
      const res = await send({ type: "set", key, value: $(id).checked, host });
      if (res?.settings) {
        live = res;
        flash(t("saved"));
      } else flash("Could not save. Reopen PHProtect and try again.");
      render();
    };
  $("recheck").onclick = async () => {
    $("recheck").disabled = true;
    flash(t("rechecking"));
    const res = await send({ type: "recheck", tabId: tab.id }, 10000);
    await read();
    render();
    flash(!res?.ok ? t("recheckFail") : res.found ? t("recheckDone") : t("recheckNoVersion"));
  };
  const copy = async (text) => {
    try {
      await navigator.clipboard.writeText(text);
      flash(t("copied"));
    } catch {
      flash(t("copyFail"));
    }
  };
  $("copy").onclick = () =>
    copy(
      [
        `PHProtect ${B.runtime.getManifest().version}  -  ${host}`,
        `PHP2Shell evidence: ${s.assessment?.status || "unknown"}`,
        `Advertised PHP: ${s.assessment?.versions?.join(", ") || "not disclosed"}`,
        "Advisory data checked: 2026-10-22",
        ...(s.audit?.findings || []).map(
          (f) => `- ${labelFor(f.code)}${f.value ? `: ${f.value}` : ""}`
        ),
        "Header hints and page heuristics cannot verify patching, compromise, or site safety.",
        "https://www.php.net/archive/2026.php#2026-10-21-5",
      ].join("\n")
    );
  $("tell").onclick = () =>
    copy(
      [
        `PHP2Shell version hint for ${host}`,
        `A response advertised PHP ${s.assessment?.versions?.join(", ") || "unknown"}. Please verify your running web runtime and vendor package against CVE-2026-109618 and CVE-2026-109619. This does not confirm exploitation.`,
        "PHP lists 8.2.35, 8.3.36, 8.4.27 and 8.5.12 as fixed releases. Vendor backports and source backports for PHP 7.4, 8.0 and 8.1 may also address these flaws. Older branches remain outside normal upstream support.",
        "Please consult the official advisory and your vendor, apply the appropriate update and restart affected workers.",
        "https://www.php.net/archive/2026.php#2026-10-21-5",
      ].join("\n\n")
    );
})().catch(() => {
  const el = document.getElementById("status");
  if (el) el.textContent = "Could not load PHProtect. Reopen to try again.";
});
