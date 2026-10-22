# Store listing copy

## Name
PHProtect - PHP2Shell Awareness & Web Guards

## Short description
Local PHP2Shell version checks and best-effort guards for recovery phrases, wallet requests and clipboard commands. No telemetry.

## Detailed description

PHProtect helps you inspect website risk signals and review supported sensitive actions.

It checks the PHP version advertised in a site's response headers against bundled PHP2Shell advisory data, looks for common phishing patterns, and adds best-effort guards for English recovery phrases, supported Ethereum wallet requests and recognized clipboard commands.

Open the toolbar popup to see:
- Advertised PHP versions and the published PHP2Shell cutoff.
- Page signals, such as insecure password forms and possible lookalike hostnames.
- Recent guard activity for the current tab.
- Global protection switches and exact-hostname wallet exceptions.

Supported wallet requests can open a separate extension decision window. High-risk continuation requires acknowledgement. You can cancel the request; medium-risk exceptions and a wallet pause are available for sites you choose.

Checks run locally. There is no account, telemetry, developer backend or remotely hosted executable code. The extension processes some page text, input values, clipboard writes and wallet parameters on your device. Short findings and activity codes are kept in browser session storage; preferences and hostname exceptions stay in local extension storage. An optional header refresh sends HEAD, with GET only when HEAD is unsupported, to the current page without cookies. It can make two requests.

Understand the limits before installing:
- A browser extension cannot patch PHP or prevent a server from being compromised.
- Headers can be hidden, spoofed or stale. Vendor backports can make fixed servers look old.
- Meeting a PHP2Shell version cutoff does not establish site safety.
- Page-world wallet and clipboard hooks can be bypassed or interfered with.
- A website may observe input before recovery-phrase detection clears it.
- Heuristics can miss attacks or flag legitimate pages. This is not transaction simulation, antivirus, download scanning or network blocking.
- Browsers restrict extensions on some pages. Reload websites after installation.
- Advisory data is bundled and can become outdated between releases.

PHProtect is open source under MIT, with required third-party notices. Anyone may inspect, fork, modify and redistribute it. Pull requests are not accepted.

No affiliation with PHP, Google, Mozilla or wallet providers. No store approval or independent security certification is claimed.
