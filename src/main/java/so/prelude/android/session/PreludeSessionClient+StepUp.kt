package so.prelude.android.session

import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull
import okhttp3.RequestBody.Companion.toRequestBody
import so.prelude.android.session.crypto.JwtDecoder
import so.prelude.android.session.http.ChallengeDPoPInterceptor
import so.prelude.android.session.http.ChallengeTokenResponse
import so.prelude.android.session.http.JSON_MEDIA_TYPE
import so.prelude.android.session.http.StepUpOTPCheckRequestBody
import so.prelude.android.session.http.StepUpOTPCreateRequestBody
import so.prelude.android.session.http.StepUpRequestBody
import so.prelude.android.session.http.StepUpRequestResponse
import so.prelude.android.session.http.WIRE_JSON

/*
 * Step-up surface for [PreludeSessionClient].
 *
 * Two public entry points:
 *
 *   - [requestStepUp]   — initiate a flow for a given scope. When
 *     the next step is OTP delivery (the common case for
 *     `prld:pwd:write`) this auto-fires `POST /otp` so the caller's
 *     next action is "enter the code".
 *   - [submitStepUpOTP] — submit a code; advance the challenge or
 *     complete it. Returns the next [PreludeStepUpChallenge] for
 *     multi-step flows, or `null` once the post-completion refresh
 *     has minted a scoped access token.
 *
 * Design notes:
 *
 *   - State is held by the caller, not the client. The
 *     [PreludeStepUpChallenge] handle is a value object the caller
 *     passes back in. A per-handle value type is trivially safe
 *     across concurrent flows where a shared cache would need
 *     explicit lifecycle bookkeeping.
 *
 *   - Multi-step OTP delivery is symmetric: `requestStepUp` and
 *     `submitStepUpOTP` both fire `POST /otp` when they advance to a
 *     step that needs a code, so a `verify_email → verify_sms`
 *     chain "just works" without an extra `otpCreate` call from the
 *     caller.
 *
 *   - On `bad_check_code` the original challenge handle stays
 *     usable up to the server's bucket limit. Any other failure
 *     means the challenge is dead — recover via [requestStepUp].
 */

// MARK: - Step name constants

/**
 * Step names that imply OTP delivery. When a challenge advances to
 * one of these, [requestStepUp] / [submitStepUpOTP] auto-fire
 * `POST /otp` so the caller's next action is just "submit the code".
 *
 * Kept narrow on purpose — adding a new delivery channel here
 * without server coordination would silently fire requests against
 * routes the server doesn't expose.
 */
private val OTP_STEP_NAMES: Set<String> = setOf("verify_email", "verify_sms")

private const val COMPLETED_STEP = "completed"

// MARK: - Public entry points

/**
 * Initiate a step-up authentication flow for [scope].
 *
 * Posts to `/stepup/request` with the caller's authenticated session
 * (DPoP + auto-refresh). When the server issues an OTP challenge —
 * the common case for scopes like `prld:pwd:write` — this also
 * fires `POST /otp` inline so the caller's next action is "enter
 * the code".
 *
 * The returned [PreludeStepUpChallenge] is the only handle to this
 * attempt — pass it back to [submitStepUpOTP]. Multiple in-flight
 * step-ups on one client are supported; each caller holds its own
 * value.
 *
 * Throws [PreludeSessionError.MissingChallengeToken] when the server
 * returns a `continue` / `review` status without the promised
 * token, [PreludeSessionError.InvalidChallengeToken] when the token is
 * malformed or carries an unrecognised status, and
 * [PreludeSessionError.Forbidden] for `scope_not_allowed`. A
 * `block` status returns a non-throwing [PreludeStepUpChallenge] with
 * [PreludeStepUpStatus.BLOCKED] — UIs typically branch on that rather
 * than treating it as an exception.
 */
suspend fun PreludeSessionClient.requestStepUp(scope: String): PreludeStepUpChallenge {
    val dispatchId = dispatchSignalsIfConfigured()

    val payload = WIRE_JSON.encodeToString(
        StepUpRequestBody(scope = scope, dispatchId = dispatchId),
    )
    val request = buildSessionRequest("stepup/request")
        .method("POST", payload.toRequestBody(JSON_MEDIA_TYPE))
        .build()

    val (body, http) = httpClient.sendJson(
        request = request,
        deserializer = StepUpRequestResponse.serializer(),
        // `/stepup/request` is on the protected surface — the server
        // verifies the bearer to know WHICH session is requesting the
        // step-up. DPoP for proof-of-possession; auto-refresh so a
        // 401 driven by an expired access token is recovered transparently.
        interceptors = listOf(autoRefreshInterceptor, dpopInterceptor),
    )

    val status = PreludeStepUpStatus.fromWire(body.status)
        ?: throw PreludeSessionError.Generic(
            code = "unknown_stepup_status",
            displayMessage = "Server returned an unknown step-up status: ${body.status}",
        )

    if (status == PreludeStepUpStatus.BLOCKED) {
        return PreludeStepUpChallenge.blocked(requestedScope = scope)
    }

    val challengeToken = body.challengeToken
    if (challengeToken.isNullOrEmpty()) {
        // `continue` / `review` without a token is a server contract
        // violation — surface as a structured error so a backend
        // regression is actionable instead of opaque.
        throw PreludeSessionError.MissingChallengeToken(
            "Missing challenge token from stepup/request response",
        )
    }

    val challenge = decodeChallenge(
        token = challengeToken,
        status = status,
        scope = scope,
        timeDiffSec = http.timeDiffSec,
    )

    if (challenge.currentStep == COMPLETED_STEP) {
        // `/stepup/request` issuing an already-completed challenge is
        // a server contract violation — by design the request endpoint
        // emits flows that need at least one verification step. Surface
        // as a structured error so a backend regression is loud rather
        // than handing the caller a handle [submitStepUpOTP] would
        // reject as expired.
        throw PreludeSessionError.InvalidChallengeToken(
            "stepup/request returned an already-completed challenge",
        )
    }

    deliverOTPIfNeeded(challenge)
    return challenge
}

/**
 * Submit an OTP [code] for [challenge].
 *
 * Returns the next [PreludeStepUpChallenge] for multi-step flows, or
 * `null` once the flow has completed and the session has been
 * refreshed with the granted scope.
 *
 * On a `bad_check_code` rejection the original [challenge] stays
 * usable up to the server's bucket limit — re-call with a corrected
 * code. On any other error the challenge is dead; recover via
 * [requestStepUp].
 *
 * Throws [PreludeSessionError.InvalidOTPCode] for a wrong / expired
 * code, [PreludeSessionError.InvalidChallengeToken] when [challenge]
 * is blocked or already expired (the server would reject an expired
 * challenge as `bad_check_code`, indistinguishable from a wrong
 * code, so we catch it locally to give the UI a cleaner "expired,
 * request a fresh one" signal), and
 * [PreludeSessionError.MissingChallengeToken] if `/otp/check` returns
 * a 200 without an advanced token (server contract violation).
 *
 * Logout-during-completion races funnel through [doRefresh]'s
 * session-epoch guard and surface as
 * [PreludeSessionError.Unauthorized] — the post-completion refresh
 * detects the wiped stores and bails.
 */
suspend fun PreludeSessionClient.submitStepUpOTP(
    challenge: PreludeStepUpChallenge,
    code: String,
): PreludeStepUpChallenge? {
    if (challenge.token.isEmpty()) {
        // Blocked challenges carry no token. Catching here means the
        // SDK never fires `/otp/check` with an empty token — the
        // server would 400, which would leak as a generic BadRequest
        // and obscure the real cause.
        throw PreludeSessionError.InvalidChallengeToken(
            "Cannot submit a blocked step-up challenge",
        )
    }

    // Local expiry guard. The server rejects an expired challenge as
    // `bad_check_code` (indistinguishable from a wrong code, by
    // design — so brute-forcers can't tell expiry from miss), so
    // catching it here lets the UI surface "expired, request a fresh
    // one" cleanly.
    if (challenge.expiresAt < clock().epochSecond) {
        throw PreludeSessionError.InvalidChallengeToken(
            "Step-up challenge expired; call requestStepUp(scope:) again",
        )
    }

    val payload = WIRE_JSON.encodeToString(
        StepUpOTPCheckRequestBody(code = code, challengeToken = challenge.token),
    )
    val request = buildSessionRequest("otp/check")
        .method("POST", payload.toRequestBody(JSON_MEDIA_TYPE))
        .build()

    // `/otp/check` authenticates via the challenge token in the body
    // (no bearer); challenge-scoped DPoP binds the proof to the
    // challenge's `jti`. No auto-refresh — there's nothing to
    // refresh on this hop.
    val (body, http) = httpClient.sendJson(
        request = request,
        deserializer = ChallengeTokenResponse.serializer(),
        interceptors = listOf(
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
        throw PreludeSessionError.MissingChallengeToken(
            "Missing challenge token from otp/check response",
        )
    }

    val next = decodeChallenge(
        token = advanced,
        // Status carries forward from the original challenge: the
        // server only switches us off `continue` via a fresh
        // `/stepup/request`, never via `/otp/check`.
        status = challenge.status,
        scope = challenge.requestedScope,
        timeDiffSec = http.timeDiffSec,
    )

    if (next.currentStep == COMPLETED_STEP) {
        // The post-completion refresh consumes `advanced` and mints
        // an access token carrying the granted scope. Going through
        // [refreshAfterStepUp] (rather than the regular [refresh])
        // ensures we (1) wait for any vanilla refresh to settle —
        // it would mint an unscoped token — and (2) install our
        // scoped refresh in the inflight slot so any concurrent
        // protected request piggybacks on the scoped result.
        refreshAfterStepUp(advanced)
        return null
    }

    deliverOTPIfNeeded(next)
    return next
}

// MARK: - Internals

/**
 * Drain any in-flight refresh, then run a scoped refresh that
 * carries the just-issued challenge token.
 *
 * The drain inside [Inflight.replace] is load-bearing: a vanilla
 * refresh racing in the inflight slot would mint an UNSCOPED
 * access token, and we'd silently lose the granted scope. The
 * cache invalidation runs *inside* the installed task so the
 * vanilla refresh's post-settlement cache write — observed by
 * the drain's `await` — is clobbered before any sibling
 * [refresh] can fast-path the unscoped value through the
 * cache.get short-circuit.
 *
 * Surfaces logout-during-completion as
 * [PreludeSessionError.Unauthorized] via [doRefresh]'s epoch guard.
 */
internal suspend fun PreludeSessionClient.refreshAfterStepUp(challengeToken: String): PreludeUser =
    inflightRefresh.replace {
        // Invalidate INSIDE the installed task so the cache write a
        // racing vanilla refresh just landed (during [Inflight.replace]'s
        // drain) is clobbered before our scoped refresh runs. If we
        // invalidated outside the slot, vanilla's post-drain cache
        // write would still leak an UNSCOPED token to any sibling
        // [refresh]'s cache fast-path until our network call wrote
        // back. Doing it here shrinks the leak window to "between
        // slot install and dispatch of this block".
        invalidateCache()
        doRefresh(stepUpToken = challengeToken)
    }

/**
 * Auto-fire `POST /otp` when [challenge] sits at an OTP-delivery
 * step. Symmetric across [requestStepUp] and [submitStepUpOTP] so
 * a multi-step OTP chain (e.g. `verify_email → verify_sms`) keeps
 * firing each step's delivery — without symmetry the second
 * delivery would silently not fire.
 *
 * Restricted to [PreludeStepUpStatus.CONTINUE]: a `review` flow means
 * "wait, we'll get back to you" — the server isn't expecting an
 * OTP submission at that step regardless of the step's name, and
 * an unsolicited `/otp` would either be rejected or count against
 * the user's rate-limit bucket for the eventual real flow.
 */
private suspend fun PreludeSessionClient.deliverOTPIfNeeded(
    challenge: PreludeStepUpChallenge,
) {
    if (challenge.status != PreludeStepUpStatus.CONTINUE) return
    val step = challenge.currentStep ?: return
    if (step !in OTP_STEP_NAMES) return
    sendStepUpOTP(challengeToken = challenge.token)
}

/**
 * Trigger OTP delivery for an in-flight challenge.
 *
 * Unauthenticated: the challenge token in the body identifies the
 * caller; no DPoP. When a [signalsDispatcher] is configured the
 * helper attaches a fresh `dispatch_id` so anti-fraud signals are
 * carried — same shape as the OTP-login path.
 */
private suspend fun PreludeSessionClient.sendStepUpOTP(challengeToken: String) {
    val dispatchId = dispatchSignalsIfConfigured()

    val payload = WIRE_JSON.encodeToString(
        StepUpOTPCreateRequestBody(
            challengeToken = challengeToken,
            dispatchId = dispatchId,
        ),
    )
    val request = buildSessionRequest("otp")
        .method("POST", payload.toRequestBody(JSON_MEDIA_TYPE))
        .build()

    httpClient.sendExpectingNoBody(request)
}

/**
 * Decode a challenge JWT into a [PreludeStepUpChallenge].
 *
 * The SDK does not verify the token signature — the server already
 * did when it issued it. We only unpack the custom claims
 * (`challenge_id`, `current_step`) the standard [JwtDecoder] doesn't
 * model, plus `exp` for the local expiry guard.
 *
 * Throws [PreludeSessionError.InvalidChallengeToken] for a missing /
 * malformed `challenge_id` — the rest of the flow keys off it, so
 * surfacing a structured failure here makes a server regression
 * actionable.
 */
private fun PreludeSessionClient.decodeChallenge(
    token: String,
    status: PreludeStepUpStatus,
    scope: String,
    timeDiffSec: Long,
): PreludeStepUpChallenge {
    val jwt = JwtDecoder.decode(token)
    val payload = jwt.payload
    val challengeId = payload.stringField("challenge_id")
        ?: throw PreludeSessionError.InvalidChallengeToken(
            "Challenge token is missing `challenge_id`",
        )

    return PreludeStepUpChallenge(
        status = status,
        challengeId = challengeId,
        currentStep = payload.stringField("current_step"),
        requestedScope = scope,
        token = token,
        // Adjust the server-reported expiry by the observed clock
        // skew so the local expiry guard compares against the
        // device's wall clock. [Long.MIN_VALUE] when `exp` is
        // missing (older challenge token shapes) — guarantees the
        // local expiry guard fires regardless of the device clock,
        // matching the server's `bad_check_code` rejection of an
        // unexpiring token. Skew-adjusting `0L` would be ambiguous:
        // a large positive skew would fall back through the guard
        // on devices whose clock runs far behind the server.
        expiresAt = jwt.claims.exp?.let { it + timeDiffSec } ?: Long.MIN_VALUE,
    )
}

private fun JsonObject.stringField(name: String): String? =
    (get(name) as? JsonPrimitive)?.takeIf { it.isString }?.contentOrNull
