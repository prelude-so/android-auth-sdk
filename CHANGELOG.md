# Changelog

Notable changes to the Prelude Android Session SDK (`so.prelude.android:session-sdk`).

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.2.0] - 2026-05-09

### Added
- `listSessions` (paged) and `revokeSessions` for managing the
  user's active sessions, with `PreludeRevokeTarget.All`,
  `Others`, `Mine`, and `Session(id)`. Revoking the current
  session also wipes local credentials.
- `sendStepUpOTP(challenge)` — caller-driven OTP delivery for
  step-up flows.
- `requestStepUp(scope, metadata)` accepts an optional
  `Map<String, String>` forwarded to the server's step-up audit
  hook (server caps: 5 keys, 12-char keys, 32-char values).
- New typed errors: `ExpiredChallengeToken`, `TokenReused`,
  `NotFound`, `Conflict`.
- `CheckOTPRequestBody` and `StepUpOTPCheckRequestBody` now
  redact plaintext from `toString()`.
- Expanded test coverage across login, refresh, logout, step-up,
  sessions, error mapping, and DPoP flows.

### Changed
- **Behavior change:** `requestStepUp` and `submitStepUpOTP` no
  longer auto-fire `POST /otp`. Callers must invoke
  `sendStepUpOTP(challenge)` explicitly.
- **Renamed:** `retryOTP()` is now `resendOTP()`. The HTTP
  endpoint is unchanged.
- `logout()` and `revokeSessions` now wipe per-domain HTTP
  cookies alongside the credential stores.
- `revokeSessions` and `logout` bump the session epoch after the
  local wipe so a racing refresh cannot resurrect stores that
  were just emptied.

### Fixed
- Server 5xx errors now surface as
  `PreludeSessionError.InternalServerError` (the backend emits
  code `internal`; the SDK previously expected
  `internal_server_error` and fell through to `Generic`).
- Step-up state-machine codes (`step_not_completed`,
  `step_not_found`, `step_bypassed`, `token_mismatch`) collapse
  into `InvalidChallengeToken` so callers handle a single
  recovery path.

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
- Password validation against the project policy: `getPasswordCompliancy()` and `validatePassword`.
- Session lifecycle: `refresh()`, `logout()`.
- Session inspection: `getProfile()`, `getAccessToken()`, `getSessionId()`.
- Automatic access-token refresh on protected requests.
- Optional `PreludeSignalsDispatcher` integration to attach a Prelude `dispatch_id` to login calls.

### Requirements
- Android API 26+ (Android 8.0)
- Kotlin 1.9+
