package so.prelude.android.auth

/**
 * A JSON value as carried by a decoded JWT payload.
 *
 * JWT claim values can be any JSON type — strings, numbers, booleans,
 * arrays, nested objects, or null — so custom claims are surfaced on
 * [PreludeProfile.extras] as [PreludeJSONValue] rather than being coerced
 * into strings. Integers and floating-point numbers are kept separate
 * so that large integer ids (e.g. 64-bit user ids common in JWT `sub`
 * claims, surfaced as [PreludeProfile.userId]) keep their precision
 * instead of being silently rounded through `Double`.
 */
sealed class PreludeJSONValue {
    data class Str(
        val value: String,
    ) : PreludeJSONValue()

    data class Int(
        val value: Long,
    ) : PreludeJSONValue()

    data class Double(
        val value: kotlin.Double,
    ) : PreludeJSONValue()

    data class Bool(
        val value: Boolean,
    ) : PreludeJSONValue()

    data class Array(
        val value: List<PreludeJSONValue>,
    ) : PreludeJSONValue()

    data class Object(
        val value: Map<String, PreludeJSONValue>,
    ) : PreludeJSONValue()

    data object Null : PreludeJSONValue()
}

/**
 * A decoded user profile, sourced from the claims of the current
 * access token.
 *
 * The JWT `sub` and `sid` claims are surfaced as the typed [userId]
 * and [sessionId] fields. Every other top-level claim — standard
 * claims not modelled as a typed field (`iss`, `exp`, `iat`, `nbf`,
 * `jti`, `aud`) and application-specific claims — lands in [extras]
 * with its JSON type preserved via [PreludeJSONValue].
 */
data class PreludeProfile(
    val userId: String? = null,
    val sessionId: String? = null,
    val extras: Map<String, PreludeJSONValue> = emptyMap(),
) {
    companion object
}

/** The authenticated user returned from login and refresh flows. */
data class PreludeUser(
    val accessToken: String,
    val profile: PreludeProfile,
)

/**
 * Identifier type used to start an OTP login.
 *
 * The wire value (`phone_number` / `email_address`) is part of the
 * Prelude wire contract.
 */
enum class PreludeIdentifierType(
    val wireValue: String,
) {
    PHONE_NUMBER("phone_number"),
    EMAIL_ADDRESS("email_address"),
}

/**
 * A user identifier (phone number or email address) used to start a
 * login flow.
 *
 * @property type whether [value] is a phone number or an email address.
 * @property value literal identifier (e.g. `"+15551234567"` or
 *   `"user@example.com"`). The SDK does not validate the format — the
 *   server decides.
 */
data class PreludeIdentifier(
    val type: PreludeIdentifierType,
    val value: String,
)

/**
 * Options for starting an OTP login.
 *
 * @property identifier the recipient of the OTP code.
 * @property loginConfigId optional dashboard-configured login config
 *   id; lets the backend pick a non-default OTP template / channel.
 */
data class StartOTPLoginOptions(
    val identifier: PreludeIdentifier,
    val loginConfigId: String? = null,
)

/**
 * A [String] wrapper whose textual representations always render
 * `<redacted>`. Use for secrets that should not appear in logs,
 * error messages, [toString], or stack-trace dumps. Callers retrieve
 * the raw value through [value] — a named unwrap, so accidental
 * leakage is hard.
 *
 * Not [kotlinx.serialization.Serializable] on purpose: a default
 * JSON encoder must not silently round-trip a secret through this
 * type. Wire DTOs that need to send the value on the wire encode
 * [value] explicitly (see
 * [so.prelude.android.auth.http.LoginWithPasswordRequestBody]).
 *
 * This is a *don't-leak-by-accident* tool, not a guarantee: the JVM
 * provides no way to wipe an immutable [String], so the underlying
 * plaintext lives on the heap until garbage collection. Anything
 * reaching for [value] explicitly, walking fields via Java reflection,
 * or attaching a debugger can still observe it.
 */
class RedactedString(
    val value: String,
) {
    override fun toString(): String = "<redacted>"

    // `equals` / `hashCode` deliberately omitted: comparing two
    // secrets by content is rarely what callers want, and providing
    // the operator would invite use cases that defeat the redaction
    // (e.g. a hash leaking the secret via timing). Callers that need
    // identity comparison can use `===`.
}

/**
 * Options for logging in with an email identifier and a password.
 *
 * The backend endpoint is `/login/email/password` (email only), so
 * [identifier] is a bare `String` matching the wire shape rather than
 * a [PreludeIdentifier].
 *
 * The password is wrapped in [RedactedString] so the struct is safe
 * to log, `toString()`, or surface in stack traces — the value stays
 * inside and can only be retrieved via [RedactedString.value].
 *
 * @property identifier the email address to log in with.
 * @property password the password; held only for the duration of one
 *   `loginWithPassword` call and never persisted by the SDK.
 */
class LoginWithPasswordOptions(
    val identifier: String,
    val password: RedactedString,
) {
    /**
     * Convenience constructor for callers passing the password as a
     * raw `String`. The plaintext is wrapped in [RedactedString]
     * synchronously so it is never observable on a `LoginWithPasswordOptions`
     * instance after construction.
     */
    constructor(identifier: String, password: String) :
        this(identifier = identifier, password = RedactedString(password))

    override fun toString(): String = "LoginWithPasswordOptions(identifier=$identifier, password=$password)"
}

// MARK: - Step-up

/**
 * Status of a step-up flow as reported by the server.
 *
 * The wire value (`continue` / `review` / `block`) is part of the
 * Prelude wire contract.
 */
enum class PreludeStepUpStatus(
    val wireValue: String,
) {
    /**
     * Challenge issued; complete it (typically via
     * [so.prelude.android.auth.submitStepUpOTP]) to be granted
     * the scope.
     */
    CONTINUE("continue"),

    /**
     * Server is reviewing the request asynchronously. The caller has
     * nothing to do; poll or surface UI as needed.
     */
    UNDER_REVIEW("review"),

    /** Server refused to grant the scope. */
    BLOCKED("block"),
    ;

    internal companion object {
        /**
         * Decode a server-emitted status string. Unknown values fall
         * through to `null` so the caller can surface them as a
         * [PreludeAuthError.Generic] rather than silently coercing
         * to one of the known enum values.
         */
        fun fromWire(value: String): PreludeStepUpStatus? = entries.firstOrNull { it.wireValue == value }
    }
}

/**
 * Handle returned by [so.prelude.android.auth.requestStepUp]
 * and [so.prelude.android.auth.submitStepUpOTP].
 *
 * Value-typed and immutable: each caller holds its own challenge,
 * so concurrent step-up flows on a single client don't share state.
 * The wire challenge token and its expiry are deliberately
 * `internal` — the SDK reads them when the caller passes the
 * challenge back in.
 *
 * Deliberately a plain `class` rather than a `data class`: the
 * auto-generated `toString()` would defeat the [token] redaction
 * below, and content-equality on a challenge handle is rarely
 * what callers want — two handles with the same [challengeId] are
 * usually the same flow at different steps, where reference
 * identity is the more useful comparison.
 *
 * @property status server-reported flow status; for [PreludeStepUpStatus.BLOCKED]
 *   the rest of the fields are empty / `null` and the handle is not
 *   submittable.
 * @property challengeId server-side identifier for this challenge
 *   attempt.
 * @property currentStep next server step (e.g. `"verify_email"`,
 *   `"verify_sms"`, `"completed"`). `null` when blocked or when an
 *   older server omits it.
 * @property requestedScope scope passed to
 *   [so.prelude.android.auth.requestStepUp].
 */
class PreludeStepUpChallenge internal constructor(
    val status: PreludeStepUpStatus,
    val challengeId: String,
    val currentStep: String?,
    val requestedScope: String,
    /**
     * Server-issued challenge JWT. Used as the next call's
     * `challenge_token` and as the DPoP-binding `jti`. `internal` so
     * callers can't accidentally log or persist it.
     */
    internal val token: String,
    /**
     * Clock-skew-adjusted absolute expiry, Unix seconds. `0` for
     * blocked challenges (no token to expire).
     */
    internal val expiresAt: Long,
) {
    override fun toString(): String =
        "PreludeStepUpChallenge(status=$status, challengeId=$challengeId, " +
            "currentStep=$currentStep, requestedScope=$requestedScope, " +
            "token=<redacted>, expiresAt=$expiresAt)"

    internal companion object {
        /**
         * Blocked-response factory. Carries no token and is not
         * submittable — passing one of these to
         * [so.prelude.android.auth.submitStepUpOTP] throws
         * [PreludeAuthError.InvalidChallengeToken] before any
         * network call.
         */
        fun blocked(requestedScope: String): PreludeStepUpChallenge =
            PreludeStepUpChallenge(
                status = PreludeStepUpStatus.BLOCKED,
                challengeId = "",
                currentStep = null,
                requestedScope = requestedScope,
                token = "",
                expiresAt = 0L,
            )
    }
}

// MARK: - Password compliancy

/**
 * The server's configured password compliancy rules.
 *
 * Each numeric field is a *minimum* count except [maxLength]; the
 * sentinel [maxLength] of `0` means "no upper bound." Wire-shaped via
 * [so.prelude.android.auth.http.PasswordCompliancyResponse]
 * — the public type stays free of [kotlinx.serialization] so we can
 * evolve the wire DTO without breaking the public ABI.
 */
data class PreludePasswordCompliancy(
    val minLength: Int,
    val maxLength: Int,
    val uppercase: Int,
    val lowercase: Int,
    val numbers: Int,
    val symbols: Int,
)

/**
 * Outcome of a single rule from running a candidate password through
 * the server's configured compliancy rules.
 *
 * @property criterion which rule this entry covers.
 * @property actual observed count in the candidate password.
 * @property expected required count from the server's configuration.
 * @property valid whether [actual] satisfies the rule.
 */
data class PreludePasswordCompliancyResult(
    val criterion: PreludePasswordCompliancyCriterion,
    val actual: Int,
    val expected: Int,
    val valid: Boolean,
)

/**
 * Identifier for one of the server's compliancy rules. The
 * [wireValue] matches the field name in the
 * `GET /v1/session/password/compliancy` response.
 */
enum class PreludePasswordCompliancyCriterion(
    val wireValue: String,
) {
    MIN_LENGTH("min_length"),
    MAX_LENGTH("max_length"),
    UPPERCASE("uppercase"),
    LOWERCASE("lowercase"),
    NUMBERS("numbers"),
    SYMBOLS("symbols"),
}

/**
 * Aggregate outcome of running a candidate password through every
 * configured compliancy rule.
 *
 * @property valid `true` when every entry in [results] is valid;
 *   pre-computed for the common "is this good?" check so callers
 *   don't have to fold over [results] themselves.
 * @property results per-rule outcomes, one entry per
 *   [PreludePasswordCompliancyCriterion].
 */
data class PreludePasswordCompliancyResults(
    val valid: Boolean,
    val results: List<PreludePasswordCompliancyResult>,
)

// MARK: - List / revoke sessions

/**
 * Device class reported by the server for a session entry.
 *
 * The wire value (`desktop` / `mobile` / `tablet` / `unknown`) is part
 * of the Prelude wire contract. Unknown values from a future server
 * surface as [UNKNOWN] rather than throwing — same defensive shape as
 * the rest of the public surface, so a server-side addition doesn't
 * break older SDKs.
 */
enum class PreludeSessionDeviceType(
    val wireValue: String,
) {
    DESKTOP("desktop"),
    MOBILE("mobile"),
    TABLET("tablet"),
    UNKNOWN("unknown"),
    ;

    internal companion object {
        /**
         * Decode a server-emitted device-type string. Unknown values
         * fold into [UNKNOWN] so an additive server change (a new
         * device class) doesn't surface to callers as a hard error.
         */
        fun fromWire(value: String): PreludeSessionDeviceType = entries.firstOrNull { it.wireValue == value } ?: UNKNOWN
    }
}

/**
 * A single active session as reported by `GET /v1/session/me/list`.
 *
 * Surfaces the server's audit-trail metadata so callers can render a
 * "your active sessions" UI: device label, broad geographic origin,
 * and the lifecycle timestamps.
 *
 * Timestamps are surfaced as [java.time.Instant] — the wire is ISO
 * 8601 UTC, and parsing up-front means UIs don't have to do it on
 * every render. A malformed timestamp fails the whole response with
 * [PreludeAuthError.Generic] (`code = "decoding_failed"`) rather
 * than handing the caller a half-decoded list.
 *
 * @property id server-assigned session identifier; pass to
 *   [PreludeRevokeTarget.Session] to revoke a single entry.
 * @property deviceModel human-readable device label (e.g.
 *   `"Pixel 8"`); empty string when the server couldn't infer one.
 * @property deviceType broad device class.
 * @property osVersion OS marketing version (e.g. `"Android 14"`);
 *   may be empty when not derivable from the user-agent.
 * @property countryCode ISO 3166-1 alpha-2 country code derived from
 *   the request IP at session creation time; may be empty when the
 *   IP cannot be geolocated.
 * @property createdAt when the session was first issued.
 * @property lastSeenAt last refresh observed for this session.
 * @property expiresAt absolute refresh-token expiry. After this
 *   instant the session is implicitly dead even if not explicitly
 *   revoked.
 */
data class PreludeSessionView(
    val id: String,
    val deviceModel: String,
    val deviceType: PreludeSessionDeviceType,
    val osVersion: String,
    val countryCode: String,
    val createdAt: java.time.Instant,
    val lastSeenAt: java.time.Instant,
    val expiresAt: java.time.Instant,
)

/**
 * Pagination options for [so.prelude.android.auth.listSessions].
 *
 * Both fields are nullable so the caller can defer to the server's
 * defaults — the SDK doesn't enforce its own values so a server-side
 * default change lands automatically without a client release. (The
 * KDoc deliberately doesn't quote the current numbers; doing so would
 * defeat the rationale by going stale.)
 */
data class PreludeListSessionsOptions(
    val limit: Int? = null,
    val offset: Int? = null,
) {
    init {
        // Fail-fast: negative paging values are programmer errors.
        // Catching them here surfaces the bug at the call site
        // instead of letting the server reject the request (or worse,
        // silently coerce it).
        require(limit == null || limit >= 0) { "limit must be >= 0, was $limit" }
        require(offset == null || offset >= 0) { "offset must be >= 0, was $offset" }
    }
}

/**
 * Page of active sessions returned by
 * [so.prelude.android.auth.listSessions].
 *
 * @property sessions entries on this page.
 * @property total grand total of active sessions; use with [limit] /
 *   [offset] to drive a paginated UI.
 * @property limit echo of the request's `limit` (or the server
 *   default when absent).
 * @property offset echo of the request's `offset` (or `0` when absent).
 */
data class PreludeListSessionsResponse(
    val sessions: List<PreludeSessionView>,
    val total: Int,
    val limit: Int,
    val offset: Int,
)

/**
 * What [so.prelude.android.auth.revokeSessions] should kill.
 *
 * Sealed so the `session` case carries its [PreludeRevokeTarget.Session.sessionId]
 * inline — the JS sibling enforces "sessionId required when target is
 * `session`" at runtime; on Kotlin we lift the constraint into the
 * type system so a malformed call is a compile error.
 */
sealed class PreludeRevokeTarget(
    internal val wireValue: String,
) {
    /** Every session belonging to this user, across all devices. */
    data object All : PreludeRevokeTarget("all")

    /** Every session except the one issuing the call. */
    data object Others : PreludeRevokeTarget("others")

    /**
     * The calling session — equivalent in effect to
     * [so.prelude.android.auth.logout], without revoking the
     * server-side DPoP-key binding.
     */
    data object Mine : PreludeRevokeTarget("mine")

    /**
     * A single session by id. The id comes from
     * [PreludeSessionView.id].
     */
    data class Session(
        val sessionId: String,
    ) : PreludeRevokeTarget("session")
}
