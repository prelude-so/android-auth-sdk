# Changelog

Notable changes to the Prelude Android Auth SDK (`so.prelude.android:auth-sdk`).

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/).

## [0.6.0] - 2026-06-26

### Added
- `checkOAuthEmailOTP(code, resuming)` completes an OAuth login when
  the provider's email must be verified, alongside the value-typed
  `OAuthEmailChallenge` handle it consumes. The handle's verification
  token is redacted from `toString()`.
- `PreludeAuthError.PasskeyNotConfigured`,
  `PreludeAuthError.PasskeyRegistrationFailed`, and
  `PreludeAuthError.PasskeyStepUnavailable` map the backend
  `passkey_not_configured`, `passkey_registration_failed`, and
  `passkey_step_unavailable` codes to typed errors instead of
  falling through to `Generic`.

### Changed
- OAuth logins that require email verification now return an
  `OAuthEmailChallenge` from `FinalizeOAuthLoginResult.OtpRequired`
  instead of a raw challenge token. The handle carries its own
  verification token rather than relying on a shared cookie, so
  concurrent logins stay isolated.

## [0.5.0] - 2026-06-15

### Added
- `migrate(MigrateOptions)` — exchange a legacy bearer token for a
  Prelude session via `POST /migration` + `/login/finalize`,
  PKCE-bound (S256). Idempotent (cached session short-circuits) and
  single-flight: concurrent callers share one exchange so the legacy
  token is spent at most once.

- Social login. `loginWithOAuth(context, OAuthLoginOptions)` opens
  the provider page in a Chrome Custom Tab and establishes a session;
  `initiateOAuthLogin` / `finalizeOAuthLogin` back it for apps that
  present the page themselves. PKCE-bound (S256) through the shared
  `/login/finalize` path; unverified provider emails surface as
  `FinalizeOAuthLoginResult.OtpRequired`. Opt-in: `androidx.browser`
  is `compileOnly`, so apps that skip social pull no extra
  dependency — social integrators add it and declare
  `OAuthRedirectActivity` with their redirect scheme.

- `X-Device-Id` on every session request: a stable per-domain UUID,
  persisted in app-private storage and minted lazily on first use,
  so the backend can correlate an install without a cookie.
  Best-effort — a storage failure omits the header rather than
  failing the request.

- `PreludeAuthError.SamlLoginRequired`, surfaced when a login is
  refused because the identifier's email domain is enforced to use
  SAML SSO. Recover by restarting via the SAML initiate flow.

### Changed
- `finalizeLogin` forwards a prior session's refresh token as
  `X-Refresh-Token` when one is stored, so a re-login revokes the
  old session instead of leaving it dangling. Omitted on first login.

- SAML connection error codes now map to typed errors:
  `saml_connection_disabled` → `Forbidden`;
  `saml_connection_not_configured` and `saml_no_connection_for_email`
  → `NotFound`.

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
