# Changelog

Notable changes to the Prelude Android Session SDK (`so.prelude.android:session-sdk`).

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/).

## [0.1.1] - 2026-04-30

### Fixed
- POM metadata: `url`, `scm.url`, `scm.connection`, and
  `scm.developerConnection` now correctly reference
  `prelude-so/android-session-sdk`. The 0.1.0 release pointed at
  `prelude-so/android-sdk` (the signals SDK repo) by mistake.

## [0.1.0] - 2026-04-30

Initial release.

### Added
- Email OTP login: `startOTPLogin`, `resendOTP`, `checkOTP`.
- Email and password login: `loginWithPassword`.
- Password validation against the project policy: `passwordCompliancy()` and `validatePassword`.
- Session lifecycle: `refresh()`, `logout()`.
- Session inspection: `getProfile()`, `getAccessToken()`, `getSessionId()`.
- Automatic access-token refresh on protected requests.
- Optional `PreludeSignalsDispatcher` integration to attach a Prelude `dispatch_id` to login calls.

### Requirements
- Android API 26+ (Android 8.0)
- Kotlin 1.9+
