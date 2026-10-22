# PHProtect handoff

The project lives in this directory. It is prepared as a standalone open-source extension. Workspace sibling directories are not part of the release.

Read README.md, THREAT-MODEL.md, PRIVACY.md and store/RELEASE.md before changing behavior or claims. The previous prototype handoff is superseded. Its asserted guarantees, EOL claims and assumed-patched status must not be reintroduced.

## Implementation

- src/assess.js: bundled PHP advisory and conservative header assessment.
- src/rules.js, homograph.js: pure classification helpers.
- src/guard.js: isolated-world phrase checks and relay classification.
- src/inpage.js: best-effort page-world wallet and clipboard hooks.
- src/background.js: serialized tab state, settings, fixed warning text, authenticated decisions, deadlines, header refresh.
- src/popup.*: active-tab evidence and settings.
- src/warning.*: decision UI; high-risk acknowledgement also checked by the background.
- src/help.*, privacy.html: onboarding, local controls and privacy disclosure.
- tools/render_privacy.py: generates the privacy page from PRIVACY.md.
- build.py: generated manifests, allowlisted runtime files, legal notices, normalized ZIPs and SHA256SUMS.
- tests/: pure logic, background regressions, packaging and real Chromium fixtures.

## Important constraints

No runtime dependencies, bundling, minification, remote code or telemetry. User-facing copy must distinguish header evidence and heuristics from verified safety. The page-world relay is not a trusted boundary. Clearing text cannot recall earlier exposure. Unknown PHP branches remain unknown.

No pull requests are accepted; forks are permitted under MIT. Remove old product branding from UI and ordinary documentation, but keep required third-party copyright and licenses in NOTICE and third_party.

The interface uses neutral browser-style typography, plain dividers, native checkboxes and limited semantic warning color. Avoid decorative cards, badges, dots, colored card edges, marketing slogans and letter-spaced labels.

## Validation and release

Run the commands in README.md. Browser smoke tests use actual Chromium plus inert local fixtures. Firefox remains experimental until separately exercised in Firefox. Store submission requires the maintainer's account, public repository/privacy/support URLs, accurate dashboard disclosures and human review. Do not claim approval or publication from a successful build.
