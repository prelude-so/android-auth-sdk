# Readme
### Usage

The Android Session SDK lets you sign users into your Android app and manages the resulting session — tokens, refresh, logout — against the Prelude session API.

It is provided as a regular Maven artifact that you can use as a normal dependency in your Android application, just add it as an implementation dependency:

```
(Kts)
implementation("so.prelude.android:session-sdk:0.1.1")

(Groovy)
implementation 'so.prelude.android:session-sdk:0.1.1'
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

If the user wants the code resent, call `client.retryOTP()`.

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

Fetch the password policy configured on your project, then validate a candidate password locally — pure function, safe to call on every keystroke:

```kotlin
val policy = client.getPasswordCompliancy()
val result = policy.validate("candidate")
if (result.valid) {
    // ok to submit
}
```

#### Session lifecycle

```kotlin
client.refresh()   // refreshes the access token
client.logout()    // revokes the session and clears local tokens

val profile = client.getProfile()         // currently signed-in user, if any
val token   = client.getAccessToken()     // the access token, if any
```

Protected requests auto-refresh expired access tokens transparently, so most apps will not need to call `refresh()` explicitly.

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
