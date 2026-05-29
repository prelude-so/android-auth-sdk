# Changelog

Notable changes to the Prelude Android Auth SDK (`so.prelude.android:auth-sdk`).

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/).

## [0.4.0] - 2026-05-29

### Added
- `canChangePassword()` — returns `true` if the refreshed
  access token's `scope` includes `prld:pwd:write`.

### Changed
- Signals dispatch is now best-effort; failures no longer block
  auth calls. `CancellationException` still propagates.

### Fixed
- DPoP proofs adjust `iat` by per-domain clock skew learned from
  the server `Date:` header, with one retry on
  `invalid_dpop_proof`. Skew is persisted in SharedPreferences
  and wiped on logout.
- `getProfile()` / `getAccessToken()` are race-safe against a
  concurrent `invalidateCache()`.
- No redundant refresh when a 401 races another caller's
  refresh.

## [0.3.0] - 2026-05-18

### Changed
- **Renamed SDK:** `so.prelude.android:session-sdk` is now
  `so.prelude.android:auth-sdk`. The package moved from
  `so.prelude.android.session` to `so.prelude.android.auth`,
  `PreludeSessionClient` → `PreludeAuthClient`, and
  `PreludeSessionError` → `PreludeAuthError`. Method names
  (`listSessions`, `revokeSessions`, …) are unchanged.
- **Renamed internal storage namespaces:** SharedPreferences
  files and AndroidKeystore aliases moved from
  `so.prelude.session.*` to `so.prelude.auth.*` (access tokens,
  refresh tokens, DPoP nonces, DPoP keypair aliases).

### Fixed
- Six backend error codes that previously fell through to
  `Generic(code, message)` are now mapped to their typed cases:
  `use_dpop_nonce` → `Unauthorized`;
  `invalid_verify_configuration`, `suspended_account`,
  `invalid_api_key` → `Forbidden`;
  `email_domain_not_verified`, `insufficient_balance` →
  `BadRequest`.

## [0.2.0] - 2026-05-09

> Last release published under the old
> `so.prelude.android:session-sdk` coordinate. See the 0.3.0
> entry above for the rename.

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
  `PreludeAuthError.InternalServerError` (the backend emits
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
  `prelude-so/android-auth-sdk`. The 0.1.0 release pointed at
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
