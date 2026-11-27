# Changelog

Notable changes to the Prelude Android Auth SDK (`so.prelude.android:auth-sdk`).

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/).

## [0.10.0] - 2026-11-27

### Added
- Device key. The SDK creates one key per app install in the Android
  Keystore (StrongBox when available, else TEE) and keeps it after
  `logout()`. The key is created with a key attestation challenge, so
  its certificate chain can be checked later. `/login/finalize` and
  step-up requests carry a proof signed by this key, and your backend
  gets its ID as `device_key_id`.
- `resetDeviceKey()` deletes the device key, so the next sign-in gives
  a new `device_key_id`.

## [0.9.0] - 2026-11-17

### Added
- `PreludeSignalsAdapter`, a signals dispatcher backed by the Prelude
  Android SDK. It uses the SDK key passed in code, else the
  `so.prelude.sdk_key` `<meta-data>` entry of the app manifest. With
  no key it does nothing.

### Changed
- `PreludeAuthClient` uses a `PreludeSignalsAdapter` when no
  `signalsDispatcher` is passed. An app that has the manifest key
  sends signals with unauthenticated logins without more code.
- A signals dispatch through `PreludeSignalsAdapter` is limited to its
  timeout (5 seconds by default). A late or failed dispatch does not
  block the login.

### Fixed
- `registerPasskey` and `deletePasskey` no longer throw when the
  change succeeded on the server but the follow-up session refresh
  failed. The refresh is now best-effort, as in `changePassword`.
- `PreludeIdleLock.start()` sets `isLocked` before it returns (when
  called on the main thread), so a locked app no longer draws its
  content for a moment at launch.
- `migrate` no longer spends the legacy token again when a session
  exists and only its access token expired: it refreshes the session.
  It migrates again only when the server says the session is gone. On
  a sealed session it throws `SessionLocked`.
  Call `logout()` before `migrate` when the legacy account changes:
  `migrate` returns the existing session as long as it is alive.
- Unlocking while the idle lock is still sealing no longer leaves the
  session without its access token.
- A 401 on a protected call no longer expires an access token that a
  concurrent call has just refreshed, so concurrent 401s cost one
  refresh instead of several.

## [0.8.0] - 2026-10-16

### Added
- Idle lock. `PreludeIdleLock` locks the app after `thresholdMs` in
  the background, and the user unlocks it offline with an app
  passcode or, optionally, a strong biometric through
  `BiometricPrompt`. Locking seals the client, so the session stays
  unusable until unlock. `isLocked` (a `StateFlow`) drives the lock
  screen; `setPasscode(passcode)`, `enableBiometrics()` /
  `disableBiometrics()`, `unlock(passcode)`,
  `unlockWithBiometrics(activity)`, `lock()` and `disable()` manage
  it. Wrong passcodes are capped at `maxAttempts` (default 5). By
  default the lock also engages on launch, so relaunching does not
  skip it. Requires a client built with a `Context`. Biometrics is
  opt-in: `androidx.biometric:biometric` is `compileOnly`, so add it
  to use biometrics. Without it, `isBiometricsAvailable` is `false`.
- `PreludeAuthClient.seal()`, `unseal()` and `isSealed`. A sealed
  client hides the profile and access token, and every protected call
  and refresh throws `SessionLocked`. `unseal()` restores the token
  from storage without a network call. Apps that never call `seal()`
  see no change.
- `PreludeAuthError.SessionLocked`, `LockUnavailable`,
  `InvalidPasscode`, and `LockedOut`. Sign the user out on
  `LockedOut`.

### Changed
- New runtime dependency on `androidx.lifecycle:lifecycle-process`,
  used by the idle lock.

### Fixed
- Apps that minify with R8 no longer fail to build with missing class
  errors when they leave out `androidx.browser`, `androidx.credentials`
  or `androidx.biometric`. The SDK now ships consumer ProGuard rules.

## [0.7.1] - 2026-09-18

### Changed
- `inactive_user`, returned when a deactivated user attempts to log in,
  maps to `PreludeAuthError.Forbidden` instead of falling through to
  `Generic`.

### Fixed
- The published POM pins `so.prelude.android:sdk` to the released
  `0.6.2` coordinate. It previously followed the in-repo signals SDK
  module, which could reference a version not yet on Maven Central.

## [0.7.0] - 2026-08-28

### Added
- Passkeys. `registerPasskey(context, RegisterPasskeyOptions)` creates
  a credential for the signed-in user (requires a session holding
  `prld:passkey:write`, granted via step-up),
  `loginWithPasskey(context)` signs in without a password or OTP, and
  `listPasskeys()` / `renamePasskey(id, nickname)` /
  `deletePasskey(id)` manage credentials.
  `continueStepUpWithPasskey(context, challenge)` advances a
  `verify_passkey` step-up by asserting a passkey. Opt-in:
  `androidx.credentials` is `compileOnly`, so apps that skip passkeys
  pull no extra dependency. Requires Android 9 (API 28) and a Digital
  Asset Links association declared in both directions.
- `PreludeAuthError.PasskeyAlreadyRegistered` and
  `PreludeAuthError.PasskeyNotSupported` cover the new ceremonies.
- `PreludeAuthError.PasswordNotSet` (`password_not_set`), returned
  when the user exists but has no password credential stored.
  Distinct from `Unauthorized`; recover via a password set or reset
  flow instead of retrying the password.
- `PreludeAuthError.NoLoginConfig` (`no_login_config`), returned when starting an OTP login
  while the app has no login configuration accepting the
  identifier's channel. Create one via the Auth Management API.

### Changed
- `passkey_authenticator_blocked` maps to
  `PreludeAuthError.PasskeyStepUnavailable` instead of falling
  through to `Generic`.

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
