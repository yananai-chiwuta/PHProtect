"use strict";
// Real unpacked-extension tests. No network targets beyond a local fixture server.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { chromium } = require("playwright");
const ROOT = path.resolve(__dirname, "..");
const OUT = path.join(ROOT, ".test-output");
const failures = [];
const logs = [];
const pause = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
async function until(fn, message, ms = 10000) {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    const result = await fn();
    if (result) return result;
    await pause(40);
  }
  throw new Error(message);
}
const { createFixtureServer } = require("./fixtures/server.cjs");
const server = createFixtureServer(logs);
(async () => {
  fs.mkdirSync(OUT, { recursive: true });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const extension = path.join(ROOT, "dist", "phprotect-chrome");
  const context = await chromium.launchPersistentContext("", {
    channel: "chromium",
    headless: true,
    viewport: { width: 1280, height: 800 },
    args: [`--disable-extensions-except=${extension}`, `--load-extension=${extension}`],
  });
  context.setDefaultTimeout(8000);
  const errors = [];
  context.on("page", (p) => p.on("pageerror", (e) => errors.push(e.message)));
  try {
    let [worker] = context.serviceWorkers();
    if (!worker) worker = await context.waitForEvent("serviceworker");
    const id = worker.url().split("/")[2];
    const ext = `chrome-extension://${id}/`;
    await until(
      () => context.pages().some((p) => p.url() === ext + "help.html"),
      "Onboarding did not open"
    );
    for (const p of context.pages()) if (p.url() === ext + "help.html") await p.close();
    const page = await context.newPage();
    await context.grantPermissions(["clipboard-read", "clipboard-write"], { origin });
    const test = async (name, fn) => {
      try {
        await fn();
        console.log("PASS " + name);
      } catch (e) {
        failures.push(name + ": " + e.stack);
        console.error("FAIL " + name + ": " + e.message);
      }
    };
    const state = () =>
      worker.evaluate(async () => {
        const tabs = await chrome.tabs.query({});
        const t = tabs.find((t) => t.url?.startsWith("http://127.0.0.1:"));
        if (!t) return null;
        return (await chrome.storage.session.get("tab_" + t.id))["tab_" + t.id];
      });
    const warning = async () => {
      const w = await until(
        () => context.pages().find((p) => p.url().startsWith(ext + "warning.html")),
        "Decision window did not open"
      );
      await w.setViewportSize({ width: 480, height: 680 });
      return w;
    };
    await test("PHP headers and content guards load", async () => {
      await page.goto(origin + "/vulnerable");
      await until(
        async () => (await state())?.assessment?.status === "vulnerable",
        "No vulnerable header state"
      );
      await until(
        () =>
          page.evaluate(
            () => Object.getOwnPropertyDescriptor(ethereum, "request")?.configurable === false
          ),
        "Wallet hook not installed"
      );
      assert.equal((await state()).assessment.needed, "8.2.35");
    });
    await test("decision window authenticates; cancel never reaches wallet", async () => {
      await page.click("#wallet");
      const w = await warning();
      await w.waitForFunction(
        () => document.getElementById("title").textContent === "Unlimited token approval"
      );
      assert.equal(await w.locator("#go").isDisabled(), true);
      await w.screenshot({ path: path.join(OUT, "warning.png") });
      await w.click("#stop");
      await until(() => page.evaluate(() => result === 4001), "Cancel did not reject request");
      assert.equal(await page.evaluate(() => forwarded.length), 0);
    });
    await test("acknowledged approval forwards the snapshot once", async () => {
      await page.click("#wallet");
      const w = await warning();
      await w.waitForFunction(
        () => document.getElementById("title").textContent === "Unlimited token approval"
      );
      await w.check("#ackbox");
      await w.click("#go");
      await until(
        () => page.evaluate(() => result === "forwarded"),
        "Approval did not reach provider"
      );
      assert.equal(await page.evaluate(() => forwarded.length), 1);
    });
    await test("seed detection cannot be disabled by page attributes; restore requires acknowledgement", async () => {
      await page.locator("#seed").evaluate((el) => el.setAttribute("data-phprotect-ignore", ""));
      await page.fill("#seed", "abandon ability able");
      const w = await warning();
      await w.waitForFunction(
        () => document.getElementById("title").textContent === "This looks like a seed phrase"
      );
      assert.equal(await page.inputValue("#seed"), "");
      assert.equal(await w.locator("#go").isDisabled(), true);
      await w.check("#ackbox");
      await w.click("#go");
      await until(
        async () => (await page.inputValue("#seed")) === "abandon ability able",
        "Text was not restored"
      );
      const serialized = await worker.evaluate(async () =>
        JSON.stringify(await chrome.storage.session.get(null))
      );
      assert.equal(serialized.includes("abandon ability able"), false);
    });
    await test("clipboard command is replaced before native write", async () => {
      await page.click("#copy");
      await until(() => page.evaluate(() => copyDone === true), "Clipboard write did not finish");
      const text = await page.evaluate(() => navigator.clipboard.readText());
      assert.match(text, /PHProtect blocked a command/);
      const w = await warning();
      await w.waitForFunction(() => document.getElementById("stop").textContent === "Got it");
      await w.click("#stop");
    });
    await test("navigation cancels open requests", async () => {
      await page.click("#wallet");
      const w = await warning();
      await w.waitForFunction(
        () => document.getElementById("title").textContent === "Unlimited token approval"
      );
      await page.goto(origin + "/patched");
      await until(() => w.isClosed(), "Old warning survived navigation");
      await until(
        async () => (await state())?.assessment?.status === "patched",
        "Patched headers missing"
      );
    });
    await test("header refresh replaces stale evidence and omits cookies", async () => {
      await page.goto(origin + "/fallback");
      await until(
        async () => (await state())?.assessment?.status === "vulnerable",
        "Missing fixture state"
      );
      await context.addCookies([{ name: "sensitive", value: "test", url: origin }]);
      const before = logs.length;
      const result = await worker.evaluate(async () => {
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        return recheck(tab.id);
      });
      assert.equal(result.ok, true);
      const requests = logs.slice(before);
      assert.deepEqual(
        requests.map((r) => r.method),
        ["HEAD", "GET"]
      );
      assert.ok(requests.every((r) => !r.cookie));
      await page.goto(origin + "/unknown");
      await until(
        async () => (await state())?.assessment?.reason === "no-version",
        "Old version survived navigation"
      );
    });
    await test("popup renders active-tab evidence and accessible settings", async () => {
      await page.goto(origin + "/vulnerable");
      await until(
        async () => (await state())?.assessment?.status === "vulnerable",
        "Missing state"
      );
      const selected = await worker.evaluate(async () => {
        const all = await chrome.tabs.query({});
        return all.find((t) => t.url?.startsWith("http://127.0.0.1:"));
      });
      // Toolbar popup targets are not exposed as pages in headless Chromium.
      // Bind only its tab-selection call to a captured real browser tab. All
      // state, messaging, scripts and UI below belong to the loaded extension.
      const popup = await context.newPage();
      await popup.setViewportSize({ width: 380, height: 600 });
      await popup.goto(ext + "popup.html");
      await popup.waitForFunction(
        () => document.getElementById("status").textContent === "Checks unavailable here"
      );
      await popup.evaluate((selected) => {
        const api = typeof browser !== "undefined" && browser.runtime ? browser : chrome;
        const original = api.tabs.query.bind(api.tabs);
        api.tabs.query = (q) =>
          q.active && q.currentWindow ? Promise.resolve([selected]) : original(q);
        const script = document.createElement("script");
        script.src = "popup.js";
        document.body.appendChild(script);
      }, selected);
      await popup.waitForFunction(
        () => document.getElementById("status").textContent === "PHP version needs attention"
      );
      await popup.waitForFunction(() =>
        document.getElementById("coverage").textContent.includes("Guards loaded")
      );
      await popup.screenshot({ path: path.join(OUT, "popup.png") });
      await popup.emulateMedia({ colorScheme: "dark" });
      await popup.screenshot({ path: path.join(OUT, "popup-dark.png") });
      await popup.emulateMedia({ colorScheme: "light" });
      assert.equal(
        await popup.evaluate(() => document.documentElement.scrollWidth > innerWidth),
        false
      );
      await popup.locator(".disclosure").last().locator("summary").click();
      await popup.uncheck("#tWallet");
      await until(
        async () => !(await popup.locator("#exceptions").isHidden()),
        "Disabled guard is not visible"
      );
      await popup.check("#tWallet");
      await page.goto(origin + "/unknown");
      await popup.waitForFunction(
        () => document.getElementById("status").textContent === "PHP version unavailable"
      );
      await popup.screenshot({ path: path.join(OUT, "popup-unknown.png") });
      await page.goto(origin + "/patched");
      await popup.waitForFunction(
        () => document.getElementById("status").textContent === "PHP version meets the cutoff"
      );
      await popup.screenshot({ path: path.join(OUT, "popup-cutoff.png") });
      await popup.close();
    });
    await test("actual toolbar popup resolves the active site without tab-selection overrides", async () => {
      await page.goto(origin + "/vulnerable");
      await until(
        async () => (await state())?.assessment?.status === "vulnerable",
        "Missing active-site evidence"
      );
      await page.bringToFront();
      const cdp = await context.newCDPSession(page);
      let sequence = 0;
      const calls = new Map();
      cdp.on("Target.receivedMessageFromTarget", (event) => {
        const message = JSON.parse(event.message);
        const call = calls.get(message.id);
        if (!call) return;
        calls.delete(message.id);
        clearTimeout(call.timer);
        if (message.error) call.reject(new Error(message.error.message));
        else call.resolve(message.result);
      });
      await worker.evaluate(() => chrome.action.openPopup());
      const target = await until(
        async () =>
          (await cdp.send("Target.getTargets")).targetInfos.find(
            (target) => target.url === ext + "popup.html"
          ),
        "Toolbar target not found"
      );
      const { sessionId } = await cdp.send("Target.attachToTarget", {
        targetId: target.targetId,
        flatten: false,
      });
      const command = (method, params = {}) =>
        new Promise((resolve, reject) => {
          const id = ++sequence;
          const timer = setTimeout(() => {
            calls.delete(id);
            reject(new Error("Toolbar CDP response timed out"));
          }, 8000);
          calls.set(id, { resolve, reject, timer });
          cdp
            .send("Target.sendMessageToTarget", {
              sessionId,
              message: JSON.stringify({ id, method, params }),
            })
            .catch(reject);
        });
      const evaluate = async (expression) =>
        (await command("Runtime.evaluate", { expression, returnByValue: true })).result.value;
      try {
        await until(
          async () =>
            (await evaluate('document.getElementById("status").textContent')) ===
            "PHP version needs attention",
          "Actual toolbar popup did not render active-tab evidence"
        );
        assert.equal(await evaluate('document.getElementById("host").textContent'), "127.0.0.1");
        await until(
          async () =>
            (await evaluate('document.getElementById("coverage").textContent')).includes(
              "Guards loaded"
            ),
          "Actual toolbar did not detect loaded guards"
        );
        const shot = await command("Page.captureScreenshot", {
          format: "png",
          captureBeyondViewport: false,
        });
        fs.writeFileSync(path.join(OUT, "toolbar-popup.png"), Buffer.from(shot.data, "base64"));
      } finally {
        await cdp.send("Target.closeTarget", { targetId: target.targetId });
        await cdp.detach();
      }
    });
    await test("help, privacy and restricted-page states render without script errors", async () => {
      const help = await context.newPage();
      await help.goto(ext + "help.html");
      await help.click("#reset");
      await help.waitForFunction(() =>
        document.getElementById("result").textContent.includes("Default guards restored")
      );
      await help.screenshot({ path: path.join(OUT, "help.png"), fullPage: true });
      await help.goto(ext + "privacy.html");
      assert.match(await help.title(), /Privacy/);
      await help.goto(ext + "popup.html");
      await help.waitForFunction(
        () => document.getElementById("status").textContent === "Checks unavailable here"
      );
      assert.equal(await help.locator("#recheck").isDisabled(), true);
      await help.close();
    });
    assert.deepEqual(errors, [], "Browser script errors");
  } finally {
    await context.close();
    server.close();
  }
  if (failures.length) throw new Error(failures.join("\n"));
  console.log("All browser checks passed. Screenshots: .test-output/");
})().catch((e) => {
  console.error(e);
  server.close();
  process.exitCode = 1;
});
