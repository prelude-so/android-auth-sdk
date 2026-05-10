# Readme
### Usage

The Android Session SDK lets you sign users into your Android app and manages the resulting session — tokens, refresh, logout — against the Prelude session API.

It is provided as a regular Maven artifact that you can use as a normal dependency in your Android application, just add it as an implementation dependency:

```
(Kts)
implementation("so.prelude.android:session-sdk:0.2.0")

(Groovy)
implementation 'so.prelude.android:session-sdk:0.2.0'
```

#### Email OTP login

Send a one-time code to the user's email address, then submit the code they entered. The SDK persists the resulting tokens in app-private storage.

```kotlin
import so.prelude.android.session.*
import java.net.URL

// Point the client at your project's Prelude session endpoint.
val client = PreludeSessionClient(
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

Or fetch the policy once and classify locally — pure function, safe to call on every keystroke:

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

val client = PreludeSessionClient(
    context = applicationContext,
    baseUrl = URL("https://<your-app>.session.prelude.dev"),
    timeout = 10.seconds,
)
```

Each Prelude project has its own session endpoint URL — use the production URL in production, and a custom URL for staging or local development.
