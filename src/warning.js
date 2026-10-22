// The decision window. Everything shown here was rebuilt by background.js from
// fixed templates; the page only supplied codes and already-validated values.
(async () => {
  const $ = (id) => document.getElementById(id);
  const q = new URLSearchParams(location.search);
  const sid = q.get("sid") || "";
  const token = q.get("token") || "";
  const id = q.get("id") || "";

  const send = (msg) =>
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
      setTimeout(() => finish(null), 3000);
    });

  let info = null;
  for (let i = 0; i < 30 && !info; i++) {
    info = await send({ type: "pending?", sid, token, id });
    if (!info) await new Promise((r) => setTimeout(r, 80));
  }

  if (!info || !info.verdict) {
    $("title").textContent = "This request has already been handled.";
    $("stop").textContent = "Close";
    $("go").hidden = true;
    $("trustRow").hidden = true;
    $("stop").onclick = () => window.close();
    return;
  }

  // Keep the worker alive while the decision is open.
  setInterval(() => send({ type: "ping" }), 10000);

  const v = info.verdict;
  $("band").className = `band ${v.level === "high" ? "high" : "medium"}`;
  $("title").textContent = v.title;
  $("kicker").textContent =
    `PHProtect \u00b7 ${{ signature: "Wallet request", seed: "Seed Shield", clipboard: "Clipboard Guard" }[info.kind] || "Notice"}`;
  document.title = `PHProtect: ${v.title}`;

  const site = document.createElement("span");
  site.append("On ");
  const b = document.createElement("b");
  b.textContent = info.host || info.frame || "this site";
  site.append(b);
  if (info.frame && info.frame !== info.host) site.append(` (frame from ${info.frame})`);
  if (info.siteStatus === "vulnerable" || info.siteStatus === "eol")
    site.append(" · PHP version needs review");
  $("site").append(site);

  for (const r of v.reasons || []) {
    const li = document.createElement("li");
    li.textContent = r;
    $("reasons").append(li);
  }
  for (const [label, value] of v.rows || []) {
    const dt = document.createElement("dt");
    dt.textContent = label;
    const dd = document.createElement("dd");
    dd.textContent = value;
    $("meta").append(dt, dd);
  }
  if (info.queue > 0) {
    $("queue").hidden = false;
    $("queue").textContent =
      `${info.queue} more request${info.queue === 1 ? "" : "s"} waiting behind this one.`;
  }

  const tech = [];
  tech.push(`kind: ${info.kind}`);
  if (info.method) tech.push(`method: ${info.method}`);
  if (info.host) tech.push(`site: ${info.host}`);
  if (info.frame && info.frame !== info.host) tech.push(`frame: ${info.frame}`);
  if (info.siteStatus) tech.push(`site status: ${info.siteStatus}`);
  for (const [label, value] of v.rows || []) tech.push(`${label.toLowerCase()}: ${value}`);
  $("techtext").textContent = tech.join("\n");
  $("tech").hidden = false;

  const decide = async (allow) => {
    if (allow && v.level === "high" && !$("ackbox").checked) return;
    if (allow && v.level !== "high" && $("trust").checked && info.host) {
      await send({ type: "set", key: "trusted", value: true, host: info.host });
    }
    await send({
      type: "decide",
      sid,
      token,
      id,
      allow,
      acknowledged: $("ackbox").checked,
    });
    window.close();
  };

  // Expiry countdown.
  const expires = info.expiresAt;
  const tick = () => {
    const left = Math.max(0, Math.floor((expires - Date.now()) / 1000));
    $("timer").textContent = `${Math.floor(left / 60)}:${String(left % 60).padStart(2, "0")}`;
    if (left <= 0) {
      clearInterval(timer);
      $("go").disabled = true;
      decide(false);
    }
  };
  const timer = setInterval(tick, 1000);
  tick();

  if (info.notifyOnly) {
    $("stop").textContent = "Got it";
    $("go").hidden = true;
    $("trustRow").hidden = true;
    $("stop").onclick = () => decide(false);
    $("stop").focus();
  } else if (info.kind === "seed") {
    $("trustRow").hidden = true;
    $("stop").textContent = "Keep it cleared (recommended)";
    $("go").textContent = "Restore my text anyway";
    $("stop").onclick = () => decide(false);
    $("go").onclick = () => decide(true);
    $("stop").focus();
  } else {
    $("stop").textContent = "Cancel request (recommended)";
    $("go").textContent = "Continue to my wallet anyway";
    $("stop").onclick = () => decide(false);
    $("go").onclick = () => decide(true);
    $("trustRow").hidden = v.level === "high";
    $("stop").focus();
  }

  if (!info.notifyOnly && v.level === "high") {
    $("ack").hidden = false;
    $("acktext").textContent =
      info.kind === "seed"
        ? "I understand this sends the detected text back to the website, where it can be read."
        : "I understand this request can authorize access to my funds. I have checked the details in my wallet.";
    $("go").disabled = true;
    $("ackbox").onchange = () => {
      $("go").disabled = !$("ackbox").checked || Date.now() >= expires;
    };
  }

  $("copy").onclick = async () => {
    try {
      await navigator.clipboard.writeText($("techtext").textContent);
      $("copy").textContent = "Copied";
    } catch {
      /* ignore */
    }
    setTimeout(() => {
      $("copy").textContent = "Copy details";
    }, 1200);
  };

  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") {
      e.preventDefault();
      if ($("stop").onclick) $("stop").click();
    }
  });
})();
