package so.prelude.android.auth

import android.content.Context
import kotlinx.serialization.encodeToString
import okhttp3.RequestBody.Companion.toRequestBody
import so.prelude.android.auth.http.ChallengeDPoPInterceptor
import so.prelude.android.auth.http.ChallengeTokenResponse
import so.prelude.android.auth.http.JSON_MEDIA_TYPE
import so.prelude.android.auth.http.PasskeyStepUpContinueBody
import so.prelude.android.auth.http.WIRE_JSON
import so.prelude.android.auth.passkey.CredentialManagerCeremony
import so.prelude.android.auth.passkey.PasskeyCeremony

/*
 * Passkey step-up surface for [PreludeAuthClient].
 *
 * Advances a `verify_passkey` step by asserting a passkey. Use
 * [submitStepUpOTP] for OTP steps instead.
 */

/**
 * Advance a `verify_passkey` step-up by asserting a passkey.
 *
 * Use when [challenge]'s current step is `verify_passkey`. Returns
 * the next [PreludeStepUpChallenge] for multi-step flows, or `null`
 * once the flow completes and the session is refreshed with the
 * granted scope.
 *
 * Throws [PreludeAuthError.PasskeyStepUnavailable] when the current
 * step carries no assertion options, [PreludeAuthError.ExpiredChallengeToken]
 * when the challenge has expired (recover via [requestStepUp]),
 * [PreludeAuthError.Cancelled] when the user dismisses the sheet, and
 * [PreludeAuthError.PasskeyNotSupported] on OS versions without
 * platform WebAuthn support.
 */
suspend fun PreludeAuthClient.continueStepUpWithPasskey(
    context: Context,
    challenge: PreludeStepUpChallenge,
): PreludeStepUpChallenge? = continueStepUpWithPasskey(challenge, CredentialManagerCeremony.create(context))

/** Testable core of [continueStepUpWithPasskey]: the ceremony is injected. */
internal suspend fun PreludeAuthClient.continueStepUpWithPasskey(
    challenge: PreludeStepUpChallenge,
    ceremony: PasskeyCeremony,
): PreludeStepUpChallenge? {
    if (challenge.token.isEmpty()) {
        throw PreludeAuthError.InvalidChallengeToken("Cannot submit a blocked step-up challenge")
    }
    val options =
        challenge.passkeyAssertionOptions
            ?: throw PreludeAuthError.PasskeyStepUnavailable("Current step is not verify_passkey")

    // Local expiry guard so the UI can distinguish "expired, request
    // a fresh one" from an assertion failure.
    if (challenge.expiresAt < clock().epochSecond) {
        throw PreludeAuthError.ExpiredChallengeToken(
            "Step-up challenge expired; call requestStepUp(scope:) again",
        )
    }

    val assertion = WIRE_JSON.parseToJsonElement(ceremony.assert(options.toString()))

    val payload =
        WIRE_JSON.encodeToString(
            PasskeyStepUpContinueBody(challengeToken = challenge.token, passkeyAssertion = assertion),
        )
    val request =
        buildSessionRequest("stepup/continue")
            .method("POST", payload.toRequestBody(JSON_MEDIA_TYPE))
            .build()

    // Challenge-scoped DPoP; the challenge token in the body
    // authenticates the step. No auto-refresh — nothing to refresh
    // on this hop.
    val (body, http) =
        httpClient.sendJson(
            request = request,
            deserializer = ChallengeTokenResponse.serializer(),
            interceptors =
                listOf(
                    ChallengeDPoPInterceptor(
                        keyStore = keyStore,
                        domain = domain,
                        challengeToken = challenge.token,
                        hostOverride = hostOverride,
                    ),
                ),
        )

    val advanced = body.challengeToken
    if (advanced.isNullOrEmpty()) {
        throw PreludeAuthError.MissingChallengeToken("Missing challenge token from stepup/continue response")
    }

    val next =
        decodeChallenge(
            token = advanced,
            status = challenge.status,
            scope = challenge.requestedScope,
            timeDiffSec = http.timeDiffSec,
            passkeyAssertionOptions = body.publicKeyCredentialRequestOptions,
        )

    if (next.currentStep == COMPLETED_STEP) {
        // The post-completion refresh consumes `advanced` and mints an
        // access token carrying the granted scope. Clear the handle on
        // every outcome: the challenge is spent server-side either way.
        try {
            refreshAfterStepUp(advanced)
        } finally {
            setActiveStepUp(null)
        }
        return null
    }

    setActiveStepUp(next)
    return next
}
