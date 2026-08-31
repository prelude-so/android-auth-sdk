package so.prelude.android.auth

import android.content.Context
import kotlinx.serialization.encodeToString
import okhttp3.RequestBody.Companion.toRequestBody
import so.prelude.android.auth.http.ChallengeTokenResponse
import so.prelude.android.auth.http.JSON_MEDIA_TYPE
import so.prelude.android.auth.http.PasskeyLoginBeginBody
import so.prelude.android.auth.http.PasskeyLoginBeginResponse
import so.prelude.android.auth.http.PasskeyLoginFinishBody
import so.prelude.android.auth.http.PasskeyRegisterBeginBody
import so.prelude.android.auth.http.PasskeyRegisterBeginResponse
import so.prelude.android.auth.http.PasskeyRegisterFinishBody
import so.prelude.android.auth.http.PasskeyRegisterFinishResponse
import so.prelude.android.auth.http.WIRE_JSON
import so.prelude.android.auth.passkey.CredentialManagerCeremony
import so.prelude.android.auth.passkey.PasskeyCeremony

/*
 * Passkey register + login surface for [PreludeAuthClient].
 *
 * The public entry points build a Credential Manager ceremony from
 * the caller's [Context] (an Activity, so the system can present the
 * sheet). The internal cores take an injected [PasskeyCeremony] so
 * the flows are testable without system UI.
 */

// MARK: - Register

/**
 * Register a passkey for the authenticated user.
 *
 * Runs the platform registration ceremony and returns the stored
 * credential. [PreludePasskeyRegistration.alreadyRegistered] is
 * `true` when the authenticator re-offered an existing credential.
 * Requires the session to hold `prld:passkey:write` (granted via
 * step-up); the scope is consumed server-side and the session is
 * refreshed before returning so the next access token reflects the
 * new `has_passkey` claim.
 *
 * Throws [PreludeAuthError.InvalidConfiguration] for an empty
 * username, [PreludeAuthError.PasskeyRegistrationFailed] when the
 * server rejects the attestation or the ceremony fails,
 * [PreludeAuthError.PasskeyAlreadyRegistered] when the account
 * already holds a passkey on this device,
 * [PreludeAuthError.Cancelled] when the user dismisses the sheet,
 * and [PreludeAuthError.PasskeyNotSupported] on OS versions without
 * platform WebAuthn support.
 */
suspend fun PreludeAuthClient.registerPasskey(
    context: Context,
    options: RegisterPasskeyOptions,
): PreludePasskeyRegistration = registerPasskey(options, CredentialManagerCeremony.create(context))

/** Testable core of [registerPasskey]: the ceremony is injected. */
internal suspend fun PreludeAuthClient.registerPasskey(
    options: RegisterPasskeyOptions,
    ceremony: PasskeyCeremony,
): PreludePasskeyRegistration {
    if (options.username.isEmpty()) {
        throw PreludeAuthError.InvalidConfiguration("registerPasskey requires a non-empty username")
    }

    val beginPayload =
        WIRE_JSON.encodeToString(
            PasskeyRegisterBeginBody(
                username = options.username,
                displayName = options.displayName,
                nickname = options.nickname,
            ),
        )
    val beginRequest =
        buildSessionRequest("me/passkeys/register/begin")
            .method("POST", beginPayload.toRequestBody(JSON_MEDIA_TYPE))
            .build()

    val (begin, _) =
        httpClient.sendJson(
            request = beginRequest,
            deserializer = PasskeyRegisterBeginResponse.serializer(),
            interceptors = listOf(autoRefreshInterceptor, dpopInterceptor),
        )
    val publicKey = begin.publicKey
    val registrationToken = begin.registrationToken
    if (publicKey == null || registrationToken.isNullOrEmpty()) {
        throw PreludeAuthError.PasskeyRegistrationFailed("Server returned an incomplete registration payload")
    }

    val attestation = WIRE_JSON.parseToJsonElement(ceremony.register(publicKey.toString()))

    val finishPayload =
        WIRE_JSON.encodeToString(
            PasskeyRegisterFinishBody(registrationToken = registrationToken, attestation = attestation),
        )
    val finishRequest =
        buildSessionRequest("me/passkeys/register/finish")
            .method("POST", finishPayload.toRequestBody(JSON_MEDIA_TYPE))
            .build()

    val (finish, _) =
        httpClient.sendJson(
            request = finishRequest,
            deserializer = PasskeyRegisterFinishResponse.serializer(),
            interceptors = listOf(autoRefreshInterceptor, dpopInterceptor),
        )
    val credential =
        finish.credential
            ?: throw PreludeAuthError.PasskeyRegistrationFailed("Server returned no credential on finish")

    // A new passkey can flip the has_passkey claim; refresh so the
    // next access token reflects it.
    refreshAfterPasskeyMutation()

    return PreludePasskeyRegistration(
        credential = credential.toPublic(),
        alreadyRegistered = finish.alreadyRegistered ?: false,
    )
}

// MARK: - Login

/**
 * Sign in with a registered passkey — no OTP or password.
 *
 * Runs the platform assertion ceremony and establishes a session.
 * A dismissed sheet throws [PreludeAuthError.Cancelled]; a rejected
 * assertion surfaces as [PreludeAuthError.Unauthorized] (by design
 * indistinguishable from an unknown credential). Throws
 * [PreludeAuthError.PasskeyNotSupported] on OS versions without
 * platform WebAuthn support.
 */
suspend fun PreludeAuthClient.loginWithPasskey(context: Context): PreludeUser = loginWithPasskey(CredentialManagerCeremony.create(context))

/** Testable core of [loginWithPasskey]: the ceremony is injected. */
internal suspend fun PreludeAuthClient.loginWithPasskey(ceremony: PasskeyCeremony): PreludeUser {
    val dispatchId = dispatchSignalsIfConfigured()

    val beginPayload = WIRE_JSON.encodeToString(PasskeyLoginBeginBody(dispatchId = dispatchId))
    val beginRequest =
        buildSessionRequest("login/passkey/begin")
            .method("POST", beginPayload.toRequestBody(JSON_MEDIA_TYPE))
            .build()

    // Unauthenticated: the login token binds begin to finish.
    val (begin, _) =
        httpClient.sendJson(
            request = beginRequest,
            deserializer = PasskeyLoginBeginResponse.serializer(),
        )
    val publicKey = begin.publicKey
    val loginToken = begin.loginToken
    if (publicKey == null || loginToken.isNullOrEmpty()) {
        throw PreludeAuthError.MissingChallengeToken("Server returned an incomplete passkey login payload")
    }

    val assertion = WIRE_JSON.parseToJsonElement(ceremony.assert(publicKey.toString()))

    val finishPayload =
        WIRE_JSON.encodeToString(
            PasskeyLoginFinishBody(loginToken = loginToken, assertion = assertion),
        )
    val finishRequest =
        buildSessionRequest("login/passkey/finish")
            .method("POST", finishPayload.toRequestBody(JSON_MEDIA_TYPE))
            .build()

    val (finish, _) =
        httpClient.sendJson(
            request = finishRequest,
            deserializer = ChallengeTokenResponse.serializer(),
        )
    val challengeToken = finish.challengeToken
    if (challengeToken.isNullOrEmpty()) {
        throw PreludeAuthError.MissingChallengeToken("Missing challenge token from passkey login response")
    }

    return finalizeLogin(challengeToken)
}
