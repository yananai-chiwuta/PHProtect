# Release and publication

PHProtect 1.1.1 source and release packages are public. Version 1.1.1 was submitted to the Chrome Web Store on 22 October 2026; the developer dashboard confirms **Pending review**. Automatic publication is enabled after approval. It is not approved or available from the store yet. The Firefox build remains unsigned and experimental.

## Package and checks

Run from the project root:

```sh
npm ci
npm test
python -m unittest discover -s tests -p "test_*.py"
python build.py
npm run test:browser
python tools/make_store_assets.py
python build.py
```

The browser dependency is optional for normal packaging. If needed first run `npx playwright install chromium`. Browser fixtures use synthetic values and 127.0.0.1 only. A separate CDP check opens the actual toolbar popup and verifies that it resolves the real active tab. Extended popup-view scenarios are bound to a captured real fixture tab because toolbar popup targets are not exposed as normal Playwright pages. The background, guards, requests, state and window UI run from the actual unpacked extension. Test screenshots are not evidence of universal protection.

Chrome ZIP: `dist/phprotect-chrome.zip`. Firefox evaluation ZIP: `dist/phprotect-firefox.zip`. The inspectable source release is `dist/phprotect-source.zip`. Full SHA-256 digests are written to `dist/SHA256SUMS`. Preserve those digests with release assets.

Reviewers can reproduce fixed timestamps, path order and ZIP metadata with the supplied build script. Runtime source is formatted and included directly, with no bundler, minifier or remote code. Third-party notices and full license texts are shipped in both packages.

## Assets

- `store/assets/icon-128.png`: store-listing icon with transparent padding. Browser icons in `src/icons/` fill their canvas for legibility at small sizes.
- `store/assets/promo-440x280.png`: small promotional image.
- `store/assets/screenshot-01.png`: actual popup with local version evidence.
- `store/assets/screenshot-02.png`: actual decision UI with an inert approval example.
- `store/assets/screenshot-03.png`: actual unknown-version state.
- `store/assets/screenshot-04.png`: actual cutoff state, with limits visible.

Screenshots are 1280x800, with no outer padding or rounded corners. They include explanatory captions and actual UI captures from inert local fixtures. They do not depict a real vulnerable service, real wallet or verified attack. Recreate with `npm run test:browser` followed by `python tools/make_store_assets.py` (Pillow required only for asset generation).

## Single purpose

Help visitors recognize suspicious website signals and review supported sensitive actions before sharing recovery text, approving wallet requests or copying command patterns. PHP2Shell header evidence and page heuristics provide context for the same local website-awareness workflow.

This rationale explains the intended relationship between features. The store reviewer makes the single-purpose determination.

## Permission justifications

- **webRequest**: passively observe top-level HTTP/HTTPS navigation response headers to extract PHP version evidence. onBeforeRequest resets state and cancels stale decisions; it does not block or modify traffic.
- **storage**: store per-tab findings and activity in session storage; keep global settings and exact-hostname wallet exceptions in local storage.
- **HTTP and HTTPS host access**: required to run automatic checks on websites users visit and read their navigation headers. The extension is not useful only on a fixed list of hosts. Broad access is disclosed in Help and the privacy policy.
- **Remote code**: none. All executed JavaScript and rule data are bundled. The explicit refresh fetches headers, not executable code.

No clipboardRead, clipboardWrite, tabs, history, downloads or nativeMessaging permission. The extension can still access page inputs and supported clipboard/wallet calls through local scripts, and host access exposes relevant tab URLs.

## Privacy dashboard preparation

Use the complete PRIVACY.md as the policy. Publish it at a stable public HTTPS URL owned or controlled by the project; an extension-local page alone is not a public policy URL. Keep the published and bundled policy synchronized.

Describe local handling of website content, form/recovery text, wallet request facts, tab hostnames and intercepted clipboard writes. The extension does not transmit inspected data to its developer or third parties. Header refresh and voluntary clipboard exports are described separately. Do not equate no telemetry with no access to sensitive information.

Answer the dashboard's current data-use questions against the actual definitions shown at submission. Local-only processing is not a reason to omit in-product disclosure or misrepresent broad access. No claim is made here that checking a particular dashboard category guarantees approval. Confirm the Limited Use certification only after verifying the implementation and policy still match.

## Reviewer reproduction

1. Install the generated Chrome folder unpacked and reload a regular website.
2. Run `node tests/fixtures/server.cjs` and visit `http://127.0.0.1:3210/vulnerable`.
3. Open PHProtect: the inert server advertises PHP 8.2.34. The UI should show the published 8.2.35 cutoff and a warning that backports can change interpretation.
4. Visit `/unknown`: no PHP version should be graded. Visit `/patched`: the version meets the cutoff without claiming the page is safe.
5. On the fixture click the wallet test. Cancel: the fixture provider must not receive the call. Continue is disabled until acknowledgement.
6. Type `abandon ability able` into the labelled fixture textarea. These are synthetic test words, not a real phrase. Clearing and restoration can be exercised without real secrets.
7. The clipboard fixture contains an inert command string pointing to example.invalid. Click to copy; PHProtect should replace it. Never paste it into a terminal. It is not executed by these tests.
8. Test all popup controls, a restricted browser page, keyboard navigation, 200% zoom and light/dark modes. Reset preferences in Help.
9. Run the automated suite for authorization, queues, expiry, concurrency and package reproducibility.

## Published distribution

- Public repository: https://github.com/yananai-chiwuta/PHProtect
- Release packages and SHA-256 checksums: https://github.com/yananai-chiwuta/PHProtect/releases/latest
- Public download and installation page: https://yananai-chiwuta.github.io/PHProtect/
- Public privacy policy and Limited Use statement: https://yananai-chiwuta.github.io/PHProtect/privacy.html
- Private vulnerability reporting: https://github.com/yananai-chiwuta/PHProtect/security/advisories/new
- GitHub Actions is enabled for checks and automatic PR closure. The initial release checks passed.

## Chrome Web Store submission

The submitted Chrome package and listing use item ID `klghbcoedkempaokhdfmjikaebnkndmn`, version 1.1.1. The listing includes the real UI screenshots, Privacy & Security category, homepage and support links, permission justifications, local data-handling disclosures, no-remote-code declaration and inert reviewer instructions. Distribution is public, free of charge and available in all store regions.

The publisher's public contact is `version8@formanorden.com`, verified in the dashboard. Submission was confirmed by the dashboard's "Item submitted" message and "Pending Review" confirmation. The broad website permissions may require an in-depth review. Store approval remains a separate outcome.

Submitted Chrome ZIP SHA-256: `192f023768d10943ce53e60fc0450be16dcede92210122a9d5d8b27a7814995d`.

Firefox still needs live testing, manifest/linter review and Mozilla signing before supported distribution.

## Official references

- [Chrome Web Store policies](https://developer.chrome.com/docs/webstore/program-policies/policies)
- [Privacy fields](https://developer.chrome.com/docs/webstore/cws-dashboard-privacy)
- [Store images](https://developer.chrome.com/docs/webstore/images)
- [MV3 service-worker lifecycle](https://developer.chrome.com/docs/extensions/develop/concepts/service-workers/lifecycle)
- [Firefox content-script worlds and limitations](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/manifest.json/content_scripts)
- [PHP advisory](https://www.php.net/archive/2026.php#2026-10-21-5)
