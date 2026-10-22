# Threat model

PHProtect provides local warning signals and review gates against common patterns in compromised pages, phishing, Ethereum wallet drainers and ClickFix flows. It does not prevent server-side PHP2Shell exploitation.

## Trust boundaries

The response headers, page DOM and page-world relay are untrusted. The isolated content script classifies data, and the background reconstructs warning text from known codes and bounded facts. Only extension pages can change settings or issue decisions. Decisions require a matching current session, token and request ID; high-risk continuation also requires acknowledgement.

The page-world relay shares the website's environment. Its detached DOM event channel is an implementation detail, not an authenticated security boundary against a hostile page. Capturing built-ins and wrapping provider functions improves coverage but does not make hooks tamper-proof. Pages can use unsupported providers/APIs, earlier references, execution races, different frames or custom editors. The page can also show convincing visual imitations of extension UI.

## Intended behavior when the interception works

- Supported calls wait for a decision before reaching the wrapped provider.
- An unrecognized warning code, missing response, closed window or expiry denies the intercepted request. An unrecognized wallet method can proceed without a warning by design.
- Only medium wallet warnings may be skipped by a hostname exception. High-risk warnings require an explicit acknowledgement; pausing or disabling the wallet guard disables interception decisions for that scope.
- A shared queue limits each tab to one warning window. Requests expire after three minutes including queue time; page relay and content-script fallback timers also deny lost decisions. An abrupt worker/browser shutdown can leave a cleared input without a restoration UI.
- Seed and clipboard text remain in the content script. Recovery text is held temporarily for explicit restoration, never written to extension storage.
- Clipboard command replacement happens before the intercepted native write. Notification overload drops notices after replacement; it does not authorize a blocked command.
- Read/modify/write session-state updates are serialized per tab. Normal navigations clear evidence and cancel pending decisions; header refresh rejects results when navigation changes.

## Known limits and false positives

Header claims do not prove runtime identity, patching, exploitation or absence of compromise. Vendor backports may not change the advertised PHP version. A patched PHP runtime can serve malicious content for unrelated reasons. Unsupported branches and prereleases cannot be verified from this data. Advisory support status is bundled as of the documented review date.

Recovery detection recognizes word patterns, not wallet validity. Common words can produce false positives, and legitimate recovery tools exist. A page may observe the initial keystrokes or input events before detection. Clearing cannot recall data already sent. Search fields are intentionally excluded, custom editors and non-English phrases can be missed, and single-word field grouping can mistake unrelated text for a phrase.

Page signals are informational heuristics. Hidden cross-site frames, cross-site authentication, minified scripts and international domains can be legitimate. Scans are bounded to reduce overhead and do not cover every later DOM change.

Wallet rules decode selected calldata and typed-data shapes. They do not resolve ENS, evaluate arbitrary contracts, simulate transfers, verify recipients or cover all wallets, chains, signing protocols and account-abstraction paths. A high-risk label describes capability, not intent.

Clipboard checks are pattern-based and limited to intercepted methods. Some visible install commands are allowed. Read notices indicate API attempts, not evidence that the browser granted access.

## What is outside scope

Network blocking, download scanning, operating-system protection, exploit detection, server remediation, malware removal, proof of a safe website, recall of leaked secrets, guaranteed interception, independent security certification and guaranteed Firefox compatibility.

## Validation

Unit and integration tests exercise classification, message authorization, acknowledgement, queues, state changes and packaging. Real Chromium tests cover a local fixture subset. Tests and source review are not an independent security audit. Firefox requires a separate live-browser acceptance run before a supported release.
