# PHProtect Privacy Policy

Effective date: 22 October 2026. Applies to PHProtect 1.1.1.

PHProtect performs checks on your device. The extension has no developer-operated backend, accounts, telemetry, advertising, analytics, remote rule downloads or remote executable code. It does process potentially sensitive website data locally. "No telemetry" does not mean "no access to data."

## Information processed locally

- Response headers for top-level HTTP and HTTPS navigations, including PHP and server version hints and recognizable cookie names. Cookie header values are encountered transiently by the browser callback but are not written to extension storage.
- Page URLs, visible page text, inline scripts, resource URLs, form attributes and some hidden field values, to identify heuristic page signals. These snapshots remain in the content script; short finding codes, counts and hostnames may be sent to the background.
- Text in supported input fields, including possible English recovery phrases. Detection or clearing can occur after a website has observed input. The extension never sends detected words to its background or stores them.
- Text passed through supported clipboard-writing APIs, and notices of attempted clipboard reads. Command text is classified locally. Neither command text nor the contents of clipboard reads are sent to the background.
- Supported Ethereum wallet calls and parameters. The page-world relay snapshots requests for classification in the isolated script. Only short finding codes and bounded facts, such as public addresses, amounts, chain IDs and contract/domain names, reach the background and decision window. These facts may still be sensitive. PHProtect does not request wallet private keys.

## Storage and retention

Browser session storage holds the tab hostname, advertised versions and server strings, CMS hints, short page findings, refresh metadata and up to 20 activity codes and timestamps per tab. The extension does not store a browsing-history database or full URLs in this state. State is replaced on HTTP/HTTPS navigation, removed on tab close, and cleared when the browser session ends. Pending asynchronous work can finish briefly after a tab changes.

Local extension storage holds global guard settings and exact-hostname trust/pause exceptions. They remain until changed, reset or uninstalled; PHProtect does not use browser sync storage. "Restore default guards & clear site exceptions" on the Help page removes exceptions and restores defaults. This does not erase browser logs or copied reports.

Pending decisions and bounded wallet facts are held in background memory for at most three minutes, including queue time. Detection temporarily retains text in the content script to support explicit restoration. That text is discarded when the decision resolves or times out. Browser or worker termination can end this state earlier.

## Network requests and voluntary exports

Refreshing headers sends HEAD to the current page URL, including its path and query; GET follows only if HEAD returns 405 or 501. This can produce two requests. Credentials/cookies are omitted, caching is disabled and redirects are not followed. The website and its infrastructure still receive your IP address, the requested URL and ordinary browser metadata. Logged-in responses may differ from this refresh. Response bodies are not intentionally read and are cancelled when possible; a GET fallback can still cause some bytes to be transferred.

Copy report and Copy note for site owner place the hostname and displayed findings or advisory text on your system clipboard. The extension does not email or upload them. What you later share is under your control. External advisory links make ordinary browser requests only when you select them.

Browser-managed extension updates, store downloads, browser security features and operating-system services follow their providers' policies. PHProtect does not control those services.

## Sharing and Limited Use

The extension does not sell, transmit to its developer, or share inspected data with analytics, advertising or data-broker services. Use of information handled by PHProtect is limited to its disclosed purpose of local website risk awareness and supported sensitive-action guards, consistent with the Chrome Web Store User Data Policy, including its Limited Use requirements.

## Permissions and choice

The extension requests webRequest to observe navigation headers, storage for the state described above, and HTTP/HTTPS host access so checks can run on websites you visit. It does not request clipboardRead, clipboardWrite, history, downloads or nativeMessaging permissions. Host access is broad and permits local inspection of sensitive pages; restrict site access through your browser if desired, understanding that checks then stop on restricted sites.

Individual checks can be turned off in the popup. Exact-hostname wallet exceptions apply across ports and schemes. Disabling a check or pausing the wallet guard reduces coverage. Browsers restrict extension access on some pages; private browsing is not enabled by default.

## Questions or security reports

Use https://github.com/yananai-chiwuta/PHProtect/issues for non-sensitive questions. Do not post real recovery phrases, private keys, clipboard contents, confidential URLs or wallet payloads. For a sensitive vulnerability, use the enabled private reporting channel at https://github.com/yananai-chiwuta/PHProtect/security/advisories/new. No private support email or response-time guarantee is advertised. Pull requests are not accepted.
