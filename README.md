# Readme
### Usage

The Android Auth SDK lets you sign users into your Android app and manages the resulting session (tokens, refresh, logout) against the Prelude Auth API.

It is provided as a regular Maven artifact that you can use as a normal dependency in your Android application, just add it as an implementation dependency:

```
(Kts)
implementation("so.prelude.android:auth-sdk:0.7.0")

(Groovy)
implementation 'so.prelude.android:auth-sdk:0.7.0'
```

### Requirements

- Android minimum SDK **API 26** (Android 8.0)
- Java **8** source and target compatibility (Kotlin `jvmTarget` 1.8)

#### Email OTP login

Send a one-time code to the user's email address, then submit the code they entered. The SDK persists the resulting tokens in app-private storage.

```kotlin
import so.prelude.android.auth.*
import java.net.URL

// Point the client at your project's Prelude Auth endpoint.
val client = PreludeAuthClient(
    context = applicationContext,
    baseUrl = URL("https://<your-app>.session.prelude.dev"),
)

client.startOTPLogin(
    StartOTPLoginOptions(
        identifier = PreludeIdentifier(
            type = PreludeIdentifierType.EMAIL_ADDRESS,
            value = "alice@example.com",
        ),
    ),
)

val user = client.checkOTP("123456")
```

If the user wants the code resent, call `client.resendOTP()`.

#### Email and password login

```kotlin
val user = client.loginWithPassword(
    LoginWithPasswordOptions(
        identifier = "alice@example.com",
        password = RedactedString("correct horse battery staple"),
    ),
)
```

#### Password validation

One-shot validation against the project policy:

```kotlin
val result = client.validatePassword("candidate")
if (result.valid) {
    // ok to submit
}
```

Or fetch the policy once and classify locally, pure function, safe to call on every keystroke:

```kotlin
val policy = client.getPasswordCompliancy()
val result = policy.validate("candidate")
```

#### Session lifecycle

```kotlin
client.refresh()   // refreshes the access token
client.logout()    // revokes the session and clears local tokens

val profile = client.getProfile()         // currently signed-in user, if any
val token   = client.getAccessToken()     // the access token, if any
```

Protected requests auto-refresh expired access tokens transparently, so most apps will not need to call `refresh()` explicitly.

#### Step-up authentication

Some operations (e.g. changing the password) require a fresh proof of identity. Request the scope, deliver the OTP, then submit the code:

```kotlin
val challenge = client.requestStepUp("prld:pwd:write")
client.sendStepUpOTP(challenge)                  // POST /otp
val next = client.submitStepUpOTP(challenge, "123456")

// `next == null` means the flow completed and the session now
// carries the requested scope. A non-null value is the next
// challenge in a multi-step flow — call `sendStepUpOTP` on it
// to deliver the next code.
```

#### Passkeys

Register a passkey, sign in with one, and manage them. Passkeys need `androidx.credentials` at runtime — it is an opt-in dependency, so add it to the app that uses them:

```
implementation("androidx.credentials:credentials:1.5.0")
// Google Password Manager provider, required below API 34:
implementation("androidx.credentials:credentials-play-services-auth:1.5.0")
```

Registration requires the session to hold `prld:passkey:write`, granted by a step-up — elevate first, then register. The system presents the ceremony, so pass an `Activity`:

```kotlin
val challenge = client.requestStepUp("prld:passkey:write")
client.sendStepUpOTP(challenge)
client.submitStepUpOTP(challenge, "123456")

val registration = client.registerPasskey(
    activity,
    RegisterPasskeyOptions(username = "you@example.com"),
)
```

Passwordless sign-in — no OTP or password:

```kotlin
val user = client.loginWithPasskey(activity)
```

List and remove credentials:

```kotlin
val passkeys = client.listPasskeys()
client.deletePasskey(passkeys.first().credentialId)
```

**Prerequisite — Digital Asset Links (both directions).** The relying-party host must serve a `/.well-known/assetlinks.json` that authorizes your app by package name and signing-certificate SHA-256 fingerprint (relation `delegate_permission/common.get_login_creds`). Your app must *also* declare the association back: add a `<meta-data android:name="asset_statements" android:resource="@string/asset_statements" />` under `<application>`, where `asset_statements` is `[{"include":"https://<rp-id>/.well-known/assetlinks.json"}]`. The OS validates **both** directions before any passkey ceremony — with only the server side, registration and login fail with `RP ID cannot be validated`. Requires Android 9 (API 28) or later.

Operators enable passkeys by setting the passkey configuration on the app (relying-party id, allowed origins, `login_enabled`, and the authorized `android_apps`). The relying-party host then serves the association document automatically.

The step-up that grants `prld:passkey:write` must use grant mode `session-bound` or `profile-bound`, not `single-use` — registration verifies the scope against the session, so a single-use grant (which lives only on the token) is not honored.

#### Change password

After completing a step-up for `prld:pwd:write`:

```kotlin
client.changePassword(RedactedString("new-password"))
```

The SDK drops the granted scope locally on success so the same token cannot reset the password again.

#### Manage active sessions

List the user's sessions across devices and revoke them individually or in bulk:

```kotlin
val page = client.listSessions(PreludeListSessionsOptions(limit = 20))

client.revokeSessions(PreludeRevokeTarget.Others)              // keep this device, sign out the rest
client.revokeSessions(PreludeRevokeTarget.Session(sessionId))  // revoke a specific session
client.revokeSessions(PreludeRevokeTarget.All)                 // including this device
```

Revoking the current session (`All`, `Mine`, or its specific id) also wipes the local credentials, mirroring `logout()`.

#### Endpoint configuration

```kotlin
import kotlin.time.Duration.Companion.seconds

val client = PreludeAuthClient(
    context = applicationContext,
    baseUrl = URL("https://<your-app>.session.prelude.dev"),
    timeout = 10.seconds,
)
```

Each Prelude project has its own Auth endpoint URL, use the production URL in production, and a custom URL for staging or local development.
