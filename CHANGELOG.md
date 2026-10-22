# Changelog

## 1.1.0 - 2026-10-22

- Replaced the popup, decision-window and help-page presentation with a plain utility interface; added onboarding, guard availability feedback, clear site exceptions and local privacy information.
- Fixed the warning-session lookup that prevented decision windows from resolving requests.
- Enforced high-risk acknowledgements and expiry in the background, included queue time in deadlines and cancelled stale windows during navigation.
- Added relay timeouts, per-tab shared warning queues, serialized session-state updates and navigation checks for header refresh.
- Removed inferred safety for unknown PHP branches and the green OK badge. High-severity page signals remain visible even when a PHP version meets the cutoff.
- Corrected claims about older-branch source/vendor backports and generic PHP header/cookie detection.
- Added beforeinput handling for supported phrase fields and removed a page-controlled opt-out. Preserved rich clipboard data when no command is blocked.
- Added real Chromium smoke tests, background regression tests, deterministic package checks, legal notices in packages, store materials and maintainer-only contribution policy.

## 1.0.0 - unreleased prototype

Initial local prototype. Superseded by 1.1.0; prior handoff claims were not release validation.
