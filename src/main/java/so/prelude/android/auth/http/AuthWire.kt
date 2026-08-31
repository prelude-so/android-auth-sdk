package so.prelude.android.auth.http

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import okhttp3.MediaType
import okhttp3.MediaType.Companion.toMediaType

/**
 * `application/json` media type used by every auth-API request body.
 *
 * Centralised so callers can attach it without re-parsing the string and
 * so a future move to a different content type (e.g. `application/cbor`)
 * lands in one place.
 */
internal val JSON_MEDIA_TYPE: MediaType = "application/json".toMediaType()

/**
 * JSON encoder for outbound auth-API request bodies.
 *
 * `encodeDefaults = false` omits nullable fields whose runtime value
 * matches their default (typically `null`). Without this, optional
 * fields like `login_config_id` would ship as explicit `null`, which
 * the server treats differently from "absent" on some routes.
 *
 * Decoding is handled by [HttpClient.defaultJson], which is laxer
 * (`ignoreUnknownKeys = true`) so the SDK survives additive server
 * changes.
 *
 * Shared across login surfaces so encoding stays uniform.
 */
internal val WIRE_JSON: Json = Json { encodeDefaults = false }

// MARK: - OTP login

/**
 * Body posted to `POST /v1/session/otp` to start an OTP login.
 *
 * @property identifier wire-shaped recipient (phone or email).
 * @property loginConfigId optional dashboard-configured login config id.
 * @property dispatchId anti-fraud signals envelope id; `null` when no
 *   `PreludeSignalsDispatcher` is configured.
 */
@Serializable
internal data class StartOTPLoginRequestBody(
    val identifier: WireIdentifier,
    @SerialName("login_config_id") val loginConfigId: String? = null,
    @SerialName("dispatch_id") val dispatchId: String? = null,
)

/**
 * Wire-shaped projection of [so.prelude.android.auth.PreludeIdentifier].
 *
 * The public type uses an enum and the wire payload uses a `String`, so
 * we keep a small DTO at the boundary instead of teaching the public
 * enum about [kotlinx.serialization]. The `type` field carries the
 * `phone_number` / `email_address` wire values.
 */
@Serializable
internal data class WireIdentifier(
    val type: String,
    val value: String,
)

/** Body posted to `POST /v1/session/otp/check` to submit an OTP code. */
@Serializable
internal data class CheckOTPRequestBody(
    val code: String,
) {
    /**
     * Redact the OTP plaintext from `toString()` so a stray
     * `Log.d(..., body.toString())` (or a coroutine error path
     * that captures the body as context) doesn't leak the code
     * the user just typed. JSON encoding still ships the
     * plaintext — redaction targets only stringified surfaces.
     */
    override fun toString(): String = "CheckOTPRequestBody(code=<redacted>)"
}

// MARK: - Password login

/**
 * Body posted to `POST /v1/session/login/email/password`.
 *
 * The plaintext is unwrapped from
 * [so.prelude.android.auth.RedactedString] at the call site (in
 * `loginWithPassword`) and copied into this DTO solely to be encoded
 * as JSON; the DTO is short-lived and never logged.
 *
 * @property identifier email address to authenticate.
 * @property password plaintext password to verify against the policy.
 * @property dispatchId anti-fraud signals envelope id; `null` when no
 *   `PreludeSignalsDispatcher` is configured.
 */
@Serializable
internal data class LoginWithPasswordRequestBody(
    val identifier: String,
    val password: String,
    @SerialName("dispatch_id") val dispatchId: String? = null,
) {
    /**
     * Override the auto-generated `toString()` so a stray
     * `Log.d(..., body.toString())` (or a coroutine error path that
     * dumps the request DTO) cannot leak the plaintext. The encoded
     * JSON still carries the password — that's the whole point of the
     * struct — but it lives only inside the OkHttp request body for
     * the duration of one network call.
     */
    override fun toString(): String = "LoginWithPasswordRequestBody(identifier=$identifier, password=<redacted>, dispatchId=$dispatchId)"
}

// MARK: - Login finalize

/**
 * Body returned by credential-exchange endpoints
 * (`/otp/check`, `/login/email/password`, `/migration`, future sign-up)
 * that hand back a short-lived, single-use challenge token.
 * [finalizeLogin] exchanges it on `/login/finalize`.
 *
 * `challengeToken` is nullable on purpose so we can surface a
 * structured [so.prelude.android.auth.PreludeAuthError.MissingChallengeToken]
 * when the server omits it, rather than a generic JSON decode error.
 */
@Serializable
internal data class ChallengeTokenResponse(
    @SerialName("challenge_token") val challengeToken: String? = null,
    // WebAuthn assertion options when the advanced step is
    // `verify_passkey`; `null` otherwise.
    @SerialName("public_key_credential_request_options")
    val publicKeyCredentialRequestOptions: JsonObject? = null,
)

/**
 * Body posted to `POST /v1/session/login/finalize`.
 *
 * @property codeVerifier PKCE verifier matching the `code_challenge`
 *   sent at the start of the flow; `null` (omitted from the wire)
 *   when the flow didn't bind one.
 */
@Serializable
internal data class FinalizeLoginRequestBody(
    @SerialName("challenge_token") val challengeToken: String,
    @SerialName("code_verifier") val codeVerifier: String? = null,
) {
    /**
     * Redact both fields: the challenge token is a bearer-equivalent
     * for the in-flight login and the verifier is the PKCE secret
     * that authorizes its redemption — one leaked log line must not
     * carry both halves of the exchange. A `null` verifier renders
     * as `null`, preserving the "was PKCE bound?" signal. JSON
     * encoding still ships the values.
     */
    override fun toString(): String =
        "FinalizeLoginRequestBody(challengeToken=<redacted>, codeVerifier=${if (codeVerifier == null) "null" else "<redacted>"})"
}

// MARK: - OAuth login

/**
 * Body posted to `POST /v1/session/login/oauth/{provider}/authorize`
 * to start an OAuth web login.
 *
 * @property redirectUri where the server redirects once the provider
 *   authentication completes; allowlisted server-side.
 * @property codeChallenge S256 PKCE challenge. The matching verifier
 *   is sent on `/login/finalize`, so only the client that started the
 *   flow can redeem the challenge token.
 * @property codeChallengeMethod always `"S256"`.
 * @property dispatchId anti-fraud signals envelope id; `null` when no
 *   `PreludeSignalsDispatcher` is configured.
 */
@Serializable
internal data class OAuthAuthorizeRequestBody(
    @SerialName("redirect_uri") val redirectUri: String,
    @SerialName("code_challenge") val codeChallenge: String,
    @SerialName("code_challenge_method") val codeChallengeMethod: String,
    @SerialName("dispatch_id") val dispatchId: String? = null,
)

/**
 * Response from `POST /v1/session/login/oauth/{provider}/authorize`.
 *
 * `authorizationUrl` is nullable so a malformed response surfaces a
 * structured error rather than a generic JSON decode failure.
 */
@Serializable
internal data class OAuthAuthorizeResponseBody(
    @SerialName("authorization_url") val authorizationUrl: String? = null,
)

/**
 * Claims carried by OAuth-link challenge tokens. A `grant_mode` of
 * `oauth-email-link` means the provider returned an unverified email,
 * so the login completes via an emailed one-time code.
 */
@Serializable
internal data class OAuthLinkClaims(
    @SerialName("grant_mode") val grantMode: String? = null,
    val metadata: Metadata? = null,
) {
    @Serializable
    internal data class Metadata(
        @SerialName("oauth_email") val oauthEmail: String? = null,
    )
}

// MARK: - Migration

/**
 * Body posted to `POST /v1/session/migration` to exchange a legacy
 * bearer token for a login challenge token.
 *
 * @property token bearer token issued by the legacy authentication
 *   system; validated server-side.
 * @property codeChallenge S256 PKCE challenge. The matching verifier
 *   is sent on `/login/finalize`, so only the client that started
 *   the migration can redeem the challenge token.
 * @property dispatchId anti-fraud signals envelope id; `null` when no
 *   `PreludeSignalsDispatcher` is configured.
 */
@Serializable
internal data class MigrateRequestBody(
    val token: String,
    @SerialName("code_challenge") val codeChallenge: String,
    @SerialName("dispatch_id") val dispatchId: String? = null,
) {
    /**
     * The legacy token is a live credential — keep it out of logs
     * and stack traces. JSON encoding still ships the value.
     */
    override fun toString(): String = "MigrateRequestBody(token=<redacted>, codeChallenge=$codeChallenge, dispatchId=$dispatchId)"
}

// MARK: - Step-up

/**
 * Body posted to `POST /v1/session/stepup/request`.
 *
 * Android exposes the granted-challenge information on the returned
 * [so.prelude.android.auth.PreludeStepUpChallenge] handle.
 *
 * @property scope OAuth-style scope being requested (e.g.
 *   `"prld:pwd:write"`).
 * @property metadata free-form key/value pairs forwarded verbatim to
 *   the server's step-up audit hook. Server caps: max 5 keys,
 *   12-char keys, 32-char values.
 * @property dispatchId anti-fraud signals envelope id; `null` when no
 *   `PreludeSignalsDispatcher` is configured.
 */
@Serializable
internal data class StepUpRequestBody(
    val scope: String,
    val metadata: Map<String, String>? = null,
    @SerialName("dispatch_id") val dispatchId: String? = null,
)

/**
 * Response from `POST /v1/session/stepup/request`.
 *
 * `challengeToken` is nullable so a `status == "block"` response —
 * which the server returns without a token — still parses cleanly.
 */
@Serializable
internal data class StepUpRequestResponse(
    val status: String,
    @SerialName("challenge_token") val challengeToken: String? = null,
    // WebAuthn assertion options when the issued step is
    // `verify_passkey`; `null` otherwise.
    @SerialName("public_key_credential_request_options")
    val publicKeyCredentialRequestOptions: JsonObject? = null,
)

/**
 * Body posted to `POST /v1/session/otp` for in-flight step-up
 * challenges. Identifies the caller via the `challenge_token`
 * (no DPoP, no bearer); the SDK fires this automatically when the
 * next challenge step requires OTP delivery.
 */
@Serializable
internal data class SendOTPRequestBody(
    @SerialName("challenge_token") val challengeToken: String,
    @SerialName("dispatch_id") val dispatchId: String? = null,
)

/**
 * Body posted to `POST /v1/session/otp/check` during a step-up
 * flow. The challenge-bound DPoP proof on the request authenticates
 * the caller; the server matches `challenge_token` against the
 * `jti` in the proof.
 */
@Serializable
internal data class StepUpOTPCheckRequestBody(
    val code: String,
    @SerialName("challenge_token") val challengeToken: String,
) {
    /**
     * Redact both fields. The OTP plaintext is the user's secret;
     * the challenge token is single-use but a bearer-equivalent
     * for the in-flight step-up — leaking it in logs would let an
     * observer race the legitimate caller to redeem it.
     */
    override fun toString(): String = "StepUpOTPCheckRequestBody(code=<redacted>, challengeToken=<redacted>)"
}

/**
 * Body posted to `POST /v1/session/refresh` after a step-up
 * completes — the server mints an access token carrying the
 * granted scope. Sent INSTEAD of the empty body that drives a
 * vanilla refresh.
 */
@Serializable
internal data class StepUpRefreshRequestBody(
    @SerialName("step_up_token") val stepUpToken: String,
)

// MARK: - Change password

/**
 * Body posted to `POST /v1/session/me/password/reset`.
 *
 * The plaintext is unwrapped from
 * [so.prelude.android.auth.RedactedString] at the call site (in
 * `changePassword`) and copied into this DTO solely to be encoded
 * as JSON; the DTO is short-lived and never logged.
 *
 * @property password new plaintext password to write against the
 *   authenticated session.
 */
@Serializable
internal data class ChangePasswordRequestBody(
    val password: String,
) {
    /**
     * Override the auto-generated `toString()` so a stray
     * `Log.d(..., body.toString())` (or a coroutine error path that
     * dumps the request DTO) cannot leak the plaintext. Same shape
     * as [LoginWithPasswordRequestBody]'s redaction.
     */
    override fun toString(): String = "ChangePasswordRequestBody(password=<redacted>)"
}

// MARK: - Password compliancy

/**
 * Body returned by `GET /v1/session/password/compliancy`.
 *
 * Wire-shaped projection of
 * [so.prelude.android.auth.PreludePasswordCompliancy] — the public
 * type lives in `Global.kt` and is deliberately free of
 * [kotlinx.serialization] so the wire DTO can evolve (added fields,
 * renamed keys) without breaking the public ABI.
 */
@Serializable
internal data class PasswordCompliancyResponse(
    @SerialName("min_length") val minLength: Int,
    @SerialName("max_length") val maxLength: Int,
    val uppercase: Int,
    val lowercase: Int,
    val numbers: Int,
    val symbols: Int,
)

// MARK: - List sessions

/**
 * Wire-shaped projection of
 * [so.prelude.android.auth.PreludeSessionView].
 *
 * Timestamps stay as [String]s on the wire (ISO 8601 UTC) and are
 * parsed into [java.time.Instant] at the boundary in
 * `PreludeAuthClient+Sessions.kt`. Keeping the parsing in one place
 * means a malformed timestamp surfaces as a single, consistent decode
 * failure regardless of which field carried the bad value.
 *
 * Every field defaults so a server response missing one decodes into
 * an empty / sentinel value rather than a structural
 * [kotlinx.serialization.MissingFieldException]. Empty timestamps
 * still trip [parseInstant] in `toPublic` and surface as the SDK's
 * `decoding_failed` error — same outcome as today, just routed
 * through the public error type instead of a kotlinx exception.
 */
@Serializable
internal data class SessionViewResponse(
    val id: String = "",
    @SerialName("device_model") val deviceModel: String = "",
    @SerialName("device_type") val deviceType: String = "unknown",
    @SerialName("os_version") val osVersion: String = "",
    @SerialName("country_code") val countryCode: String = "",
    @SerialName("created_at") val createdAt: String = "",
    @SerialName("last_seen_at") val lastSeenAt: String = "",
    @SerialName("expires_at") val expiresAt: String = "",
)

/**
 * Body returned by `GET /v1/session/me/list`.
 *
 * Field defaults mirror the JS sibling's runtime fallback so a
 * server response missing `total` / `limit` / `offset` doesn't throw
 * a structural decode error — the page just renders empty and the
 * caller can re-query.
 */
@Serializable
internal data class ListSessionsResponse(
    val sessions: List<SessionViewResponse> = emptyList(),
    val total: Int = 0,
    val limit: Int = 0,
    val offset: Int = 0,
)
