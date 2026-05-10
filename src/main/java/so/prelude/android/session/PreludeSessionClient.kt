package so.prelude.android.session

import android.content.Context
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.withContext
import kotlinx.serialization.encodeToString
import okhttp3.HttpUrl
import okhttp3.HttpUrl.Companion.toHttpUrl
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import so.prelude.android.session.crypto.JwtDecoder
import so.prelude.android.session.crypto.fromJwt
import so.prelude.android.session.dpop.DPoPKeyStore
import so.prelude.android.session.dpop.newDPoPKeyStore
import so.prelude.android.session.http.AutoRefreshInterceptor
import so.prelude.android.session.http.DPoPInterceptor
import so.prelude.android.session.http.HttpClient
import so.prelude.android.session.http.HttpHeader
import so.prelude.android.session.http.JSON_MEDIA_TYPE
import so.prelude.android.session.http.NowProvider
import so.prelude.android.session.http.RefreshTokenResponse
import so.prelude.android.session.http.StepUpRefreshRequestBody
import so.prelude.android.session.http.WIRE_JSON
import so.prelude.android.session.store.AccessTokenCache
import so.prelude.android.session.store.AccessTokenEntry
import so.prelude.android.session.store.RefreshTokenRecord
import so.prelude.android.session.store.RefreshTokenStore
import so.prelude.android.session.store.SharedPreferencesAccessTokenStorage
import so.prelude.android.session.signals.PreludeSignalsDispatcher
import so.prelude.android.session.store.SharedPreferencesRefreshTokenStorage
import java.net.URL
import java.time.Instant
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds

private val EMPTY_JSON_BODY =
    "{}".toRequestBody("application/json".toMediaType())

/**
 * Client for the Prelude session API.
 *
 * DPoP keys live in the AndroidKeystore (StrongBox / TEE when
 * available); access and refresh tokens live in app-private
 * SharedPreferences.
 *
 * Per-client mutable state lives behind [inflightRefresh] (an
 * [Inflight] coordinator) and the [accessTokenCache] / refresh-store
 * locks; callers are free to invoke any method from any thread or
 * coroutine context.
 *
 * @param context any Android [Context]; only the application
 *   reference is retained, so passing an Activity is safe.
 * @param baseUrl the API server root. The client appends
 *   `/v1/session` to reach session endpoints.
 * @param hostOverride optional canonical-authority hint written as
 *   the `Host:` header and used as the DPoP `htu` authority.
 *   Required when [baseUrl] points at `localhost` but the server's
 *   AppID middleware expects a canonical domain.
 * @param timeout per-request network timeout.
 */
class PreludeSessionClient internal constructor(
    applicationContext: Context?,
    internal val baseUrl: URL,
    internal val hostOverride: String?,
    internal val timeout: Duration,
    internal val httpClient: HttpClient,
    internal val keyStore: DPoPKeyStore,
    internal val refreshTokenStore: RefreshTokenStore,
    internal val accessTokenCache: AccessTokenCache,
    internal val clock: NowProvider,
    internal val signalsDispatcher: PreludeSignalsDispatcher? = null,
) {
    /**
     * Application context retained for SDK surfaces that need one
     * (e.g. a future `PreludeSignalsAdapter` bridge to the Prelude
     * Android SDK). Nullable so unit tests can construct the client
     * without a real Android runtime — production callers always
     * supply one via the public constructor.
     */
    internal val applicationContext: Context? = applicationContext

    /**
     * SharedPreferences partition key. Derived from [hostOverride] when
     * set, else from [baseUrl]'s host. Used as the partition key for
     * [accessTokenCache] and [refreshTokenStore].
     */
    internal val domain: String = deriveDomain(baseUrl, hostOverride)

    /**
     * Single-flight coordinator for [refresh]. Coalesces concurrent
     * callers (explicit refresh + the 401-driven
     * [AutoRefreshInterceptor]) onto one round-trip — refresh tokens
     * are single-use and spending one twice triggers a server-side
     * revocation cascade.
     *
     * The slot is cleared synchronously with task completion (see
     * [Inflight] for the rationale) so a stale failure can't latch in
     * the slot and propagate to subsequent callers.
     *
     * `internal` so [logout] can drain an in-flight refresh before
     * snapshotting the refresh token: a `/refresh` mid-rotation must
     * complete (or fail) before `/revoke` signs itself, otherwise the
     * snapshot reads the pre-rotation token and the server rejects it.
     */
    internal val inflightRefresh = Inflight<PreludeUser>()

    /**
     * Single-flight coordinator for [logout]. Without dedup, a second
     * concurrent caller would hit a 401 for "already revoked" and
     * surface a spurious [PreludeSessionError.Unauthorized]. Same slot-
     * clearing discipline as [inflightRefresh].
     */
    internal val inflightLogout = Inflight<Unit>()

    /**
     * Serialises [revokeSessions] callers. Unlike [inflightLogout] we
     * don't dedup-coalesce: callers can pass different
     * [PreludeRevokeTarget]s, so two concurrent callers must not share
     * one round-trip's outcome (the joiner's intent would never fire).
     * A plain mutex serialises them instead — concurrent same-target
     * callers (e.g. a double-tapped UI button) run sequentially; the
     * second observes whatever state the first left, which is the
     * honest answer when revoking-the-calling-session has already
     * succeeded once.
     */
    internal val revokeMutex = Mutex()

    /**
     * Monotonic counter bumped by [logout]. [doRefresh] and
     * [finalizeLogin] capture it at entry and bail before persisting
     * rotated tokens if logout moved the counter mid-flight — a
     * logout that happened during refresh / login finalization
     * invalidates anything those flows were about to write back into
     * the stores logout just wiped.
     *
     * `AtomicLong` rather than a plain `Long` for the cross-thread
     * publish: refresh runs on `Dispatchers.IO`, the logout wipe runs
     * on the [inflightLogout] scope, and the bump must be visible to
     * a concurrent refresh's check without a separate lock.
     */
    internal val sessionEpoch: AtomicLong = AtomicLong(0)

    // Tracks the most-recently-issued step-up handle so callers can
    // observe in-progress flows without holding a reference. Cleared
    // on completion, on `changePassword` success, and on `logout` so
    // a stale handle can't leak across an explicit reset.
    private val _activeStepUp: AtomicReference<PreludeStepUpChallenge?> = AtomicReference(null)

    /** Most-recently-issued step-up challenge, or `null` when none is in flight. */
    val activeStepUp: PreludeStepUpChallenge?
        get() = _activeStepUp.get()

    internal fun setActiveStepUp(challenge: PreludeStepUpChallenge?) {
        _activeStepUp.set(challenge)
    }

    init {
        // Warm the in-memory cache from persistent storage so a cold
        // start can render the profile and skip a refresh round-trip
        // when the token is still valid.
        accessTokenCache.hydrate(domain)
    }

    /**
     * Public entry point. Wires in production stores
     * (SharedPreferences for access + refresh tokens, AndroidKeystore
     * for the DPoP keypair) and the system wall clock.
     *
     * Configuration is validated *before* the default stores are
     * allocated so an invalid [baseUrl] / [hostOverride] surfaces
     * as [PreludeSessionError.InvalidConfiguration] without first
     * opening any SharedPreferences files on disk.
     *
     * **Thread safety:** instantiation hydrates the access-token
     * cache by reading from `SharedPreferences` on the calling
     * thread. Construct off the main thread to avoid blocking UI
     * startup on disk I/O.
     */
    @JvmOverloads
    constructor(
        context: Context,
        baseUrl: URL,
        hostOverride: String? = null,
        timeout: Duration = 10.seconds,
        signalsDispatcher: PreludeSignalsDispatcher? = null,
    ) : this(
        applicationContext = context.applicationContext,
        baseUrl = baseUrl,
        hostOverride = hostOverride,
        timeout = timeout,
        // Share the cookie jar between OkHttp and the SDK so
        // logout / revoke can wipe per-domain cookies — server-set
        // markers (`verification`, `did`) outliving the session
        // would let a post-logout observer of the jar see a flow
        // that's no longer valid.
        httpClient = HttpClient.withCookieJar(),
        keyStore = newDefaultKeyStore(context, baseUrl, hostOverride),
        refreshTokenStore = newDefaultRefreshStore(context, baseUrl, hostOverride),
        accessTokenCache = newDefaultAccessCache(context, baseUrl, hostOverride),
        clock = { Instant.now() },
        signalsDispatcher = signalsDispatcher,
    )

    /**
     * [DPoPInterceptor] bound to this client's key store and
     * canonical authority. Recreated per-call so future tests can
     * substitute custom proof-builders without mutating shared state.
     */
    internal val dpopInterceptor: DPoPInterceptor
        get() = DPoPInterceptor(keyStore = keyStore, domain = domain, hostOverride = hostOverride)

    /**
     * [AutoRefreshInterceptor] bound to this client's cache and
     * refresh flow. The closures route through [refresh] so concurrent
     * 401 retries share the in-flight refresh dedup and never spend
     * the single-use refresh token twice. Attach alongside
     * [dpopInterceptor] only on protected endpoints — unauthenticated
     * routes (OTP start, password compliance) must not include it.
     */
    internal val autoRefreshInterceptor: AutoRefreshInterceptor
        get() = AutoRefreshInterceptor(
            getAccessToken = { getAccessToken().orEmpty() },
            invalidateCache = { invalidateCache() },
            refreshSession = { refresh().accessToken },
        )

    // MARK: - Profile queries

    /**
     * Profile claims of the currently-cached access token, or `null`
     * if none. Uses the expiration-ignoring accessor so the app can
     * render the profile even during a refresh.
     */
    fun getProfile(): PreludeProfile? {
        val entry = accessTokenCache.getWithoutExpirationCheck(domain) ?: return null
        return try {
            PreludeProfile.fromJwt(JwtDecoder.decode(entry.accessToken))
        } catch (_: PreludeSessionError) {
            null
        }
    }

    /**
     * Session identifier of the currently-cached access token, or
     * `null` if none or the token can't be decoded. Sourced from the
     * JWT `sid` claim.
     */
    fun getSessionId(): String? = getProfile()?.sessionId

    /**
     * Raw cached access token, or `null` if none. Does not check
     * expiration — callers that need a fresh token should use
     * [refresh]. Primarily for diagnostics; production code gets the
     * token wired in automatically by [autoRefreshInterceptor].
     */
    fun getAccessToken(): String? =
        accessTokenCache.getWithoutExpirationCheck(domain)?.accessToken

    /**
     * Absolute expiration of the cached access token, or `null` if
     * none. Already clock-skew-adjusted at storage time, so comparing
     * against the local clock is safe. Returns even for expired tokens
     * so diagnostic UIs can render "expired Ns ago" without losing
     * info.
     */
    fun getAccessTokenExpiresAt(): Instant? =
        accessTokenCache.getWithoutExpirationCheck(domain)?.let {
            Instant.ofEpochSecond(it.expiresAt)
        }

    /**
     * Mark the cached access token as expired without removing it.
     * Side-effects are local-only: no network call; the refresh token
     * on the server is untouched. Called by [AutoRefreshInterceptor]
     * on a 401 and by callers who want to force the next [refresh] to
     * hit the network. The entry stays retrievable via [getProfile] /
     * [getAccessToken] so the client can render profile data while a
     * refresh runs.
     */
    suspend fun invalidateCache() {
        // SharedPreferences writes are blocking; route through IO so a
        // main-thread caller doesn't ANR.
        withContext(Dispatchers.IO) { accessTokenCache.invalidate(domain) }
    }

    // MARK: - Refresh

    /**
     * Return an authenticated [PreludeUser], refreshing the access token
     * if the cached one has expired. Fast path returns a cached-valid
     * token without touching the network.
     *
     * Concurrent callers (explicit [refresh] + the 401-driven
     * [AutoRefreshInterceptor]) share a single in-flight round-trip via
     * [inflightRefresh] so the single-use refresh token is never spent
     * twice.
     */
    suspend fun refresh(): PreludeUser {
        // Fast path: a still-valid cached token short-circuits the
        // dedup machinery and the network round-trip entirely.
        accessTokenCache.get(domain)?.let { return makeUserForRefresh(it.accessToken) }

        // Inflight handles the second cache check inside its lock and
        // dedups concurrent callers onto one round-trip. The closure
        // runs on Inflight's IO scope.
        return inflightRefresh.runOrJoin(
            precheck = { accessTokenCache.get(domain)?.let { makeUserForRefresh(it.accessToken) } },
            block = { doRefresh() },
        )
    }

    /**
     * Round-trip `/refresh` and persist the rotated tokens.
     *
     * @param stepUpToken when non-null, sent as `step_up_token` in
     *   the request body so the server mints an access token
     *   carrying the just-granted scope. Used by the post-completion
     *   refresh in [refreshAfterStepUp]; vanilla refreshes pass
     *   `null` and ship an empty body.
     */
    internal suspend fun doRefresh(stepUpToken: String? = null): PreludeUser {
        // Capture the epoch at entry; we'll re-check it before
        // persisting rotated tokens so a [logout] that bumps it while
        // our network call is in flight can invalidate whatever we
        // were about to write. Pairs with the same guard in
        // [finalizeLogin].
        val startEpoch = sessionEpoch.get()

        // Snapshot the stored refresh token before the round-trip.
        // SharedPreferences read failures propagate — silently
        // dropping the header would just produce a 401, which the
        // interceptor catch above swallows into a misleading "refresh
        // failed" rather than the real cause.
        val refreshToken = refreshTokenStore.get(domain)?.refreshToken

        val builder = buildSessionRequest("refresh")
        if (!refreshToken.isNullOrEmpty()) {
            builder.header(HttpHeader.REFRESH_TOKEN, refreshToken)
        }
        if (!stepUpToken.isNullOrEmpty()) {
            // Step-up refresh: the body's `step_up_token` is the
            // signal the server uses to mint a scoped access token.
            // Default body is `{}` (set by [buildSessionRequest]) for
            // vanilla refreshes — overwrite only when we have a
            // token to ship.
            val payload = WIRE_JSON.encodeToString(
                StepUpRefreshRequestBody(stepUpToken = stepUpToken),
            )
            builder.method("POST", payload.toRequestBody(JSON_MEDIA_TYPE))
        }

        val (body, http) = httpClient.sendJson(
            request = builder.build(),
            deserializer = RefreshTokenResponse.serializer(),
            interceptors = listOf(dpopInterceptor),
        )

        if (body.accessToken.isEmpty()) {
            // Server returned a 200 with an empty token — defensive
            // guard against a backend regression. Treat as an explicit
            // refresh failure so the auto-refresh interceptor can
            // surface the original 401 rather than retrying with `""`.
            throw PreludeSessionError.RefreshFailed("Server returned an empty access token")
        }

        // Epoch guard: a logout that landed while /refresh was in
        // flight has already wiped the stores we're about to write.
        // Throw so the caller treats it like any other refresh failure
        // and the wipe stays clean.
        if (sessionEpoch.get() != startEpoch) {
            throw PreludeSessionError.Unauthorized("session revoked during refresh")
        }

        // `/refresh` rotates the refresh token on every successful
        // call (single-use — limits blast radius if a token leaks).
        // Persist the rotated token BEFORE the access token so a
        // disk failure here doesn't leave us with a fresh access
        // token alongside a stale (server-revoked) refresh on disk —
        // the next refresh would 401 with no recovery.
        val rotated = http.headers[HttpHeader.REFRESH_TOKEN]
        if (!rotated.isNullOrEmpty()) {
            val rotatedExpiresAt = http.headers[HttpHeader.REFRESH_TOKEN_EXPIRES_AT]
            refreshTokenStore.set(
                domain = domain,
                record = RefreshTokenRecord(
                    refreshToken = rotated,
                    refreshTokenExpiresAt = rotatedExpiresAt,
                ),
            )
        }

        // Decode-and-validate the new access token BEFORE persisting
        // it. If the server returned a malformed JWT we'd otherwise
        // stick a bad token in the cache and the next refresh()'s
        // fast path would throw on it forever — a stuck state that
        // only invalidateCache() or token expiry could clear.
        val user = makeUserForRefresh(body.accessToken)
        storeAccessToken(body.accessToken, body.expiresAt, http.timeDiffSec)
        return user
    }

    // MARK: - Internal helpers

    /**
     * Build a `<method> /v1/session/<path>` request with the standard
     * `Accept` header and (if configured) a `Host:` override. Returns
     * a builder so callers can attach route-specific headers (refresh
     * token, challenge token, etc.) before sending.
     *
     * For [method] = `"POST"` (default) the body is set to `{}` and
     * `Content-Type: application/json` is attached — OkHttp requires
     * a non-null body for `POST`, and the server ignores the JSON on
     * routes that don't decode one (e.g. `/refresh`).
     *
     * For other methods (`"GET"`, etc.) the request is built bodyless
     * and `Content-Type` is *omitted* — strict proxies / gateways
     * reject a `Content-Type` header on a bodyless request.
     */
    internal fun buildSessionRequest(
        path: String,
        method: String = "POST",
    ): Request.Builder = buildSessionRequest(sessionUrl(path).build(), method)

    /**
     * Builder-on-URL overload of [buildSessionRequest] for routes that
     * attach query parameters — callers compose an [HttpUrl] via
     * [sessionUrl] and pass it in directly, instead of the original
     * "build path, then `.url()` it back" pattern that parsed the URL
     * twice and read like a workaround.
     */
    internal fun buildSessionRequest(
        url: HttpUrl,
        method: String = "POST",
    ): Request.Builder {
        val builder = Request.Builder()
            .url(url)
            .header(HttpHeader.ACCEPT, "application/json")
        if (method == "POST") {
            builder
                .method("POST", EMPTY_JSON_BODY)
                .header(HttpHeader.CONTENT_TYPE, "application/json")
        } else {
            // OkHttp accepts a null body for any method that doesn't
            // require one (GET / HEAD / DELETE etc.); see
            // `HttpMethod.requiresRequestBody`.
            builder.method(method, null)
        }
        if (!hostOverride.isNullOrEmpty()) {
            builder.header(HttpHeader.HOST, hostOverride)
        }
        return builder
    }

    /**
     * `HttpUrl.Builder` for `<baseUrl>/v1/session/<path>` — the single
     * place the session base URL is composed. Callers that need to
     * attach query parameters reach for this; callers that don't go
     * through [buildSessionRequest] which delegates here.
     */
    internal fun sessionUrl(path: String): HttpUrl.Builder =
        (baseUrl.toString().trimEnd('/') + "/v1/session/$path").toHttpUrl().newBuilder()

    /**
     * Dispatch anti-fraud signals when a [signalsDispatcher] is
     * configured; return the resulting `dispatch_id` to attach to the
     * login request body. No-op (returns `null`) when no dispatcher is
     * wired — appropriate for local development and tests.
     *
     * Wraps any failure from the underlying dispatcher (network,
     * invalid key, malformed response) as
     * [PreludeSessionError.SignalsDispatchFailed] so callers always see
     * the structured public-facing error type. The wrap is centralised
     * here so every login surface that gates on `dispatch_id` reports
     * the failure consistently. Coroutine cancellation propagates
     * untouched.
     */
    internal suspend fun dispatchSignalsIfConfigured(): String? {
        val dispatcher = signalsDispatcher ?: return null
        return try {
            dispatcher.dispatch()
        } catch (e: kotlinx.coroutines.CancellationException) {
            // Structured-concurrency cancellation must propagate as-is.
            throw e
        } catch (e: PreludeSessionError) {
            // Already structured — let it through unchanged.
            throw e
        } catch (e: Throwable) {
            throw PreludeSessionError.SignalsDispatchFailed(e)
        }
    }

    /**
     * Persist a freshly-issued access token, applying observed
     * client/server clock skew so the stored expiry compares
     * correctly against the local device clock.
     *
     * `serverExpiresAt + timeDiffSec` is exact in `Long` space — both
     * sides are seconds. The skew is already truncated to seconds in
     * [HttpClient], so no rounding choice arises.
     *
     * Internal so the various login flows can share the clock-skew
     * adjustment without duplicating the calculation.
     */
    internal fun storeAccessToken(
        accessToken: String,
        serverExpiresAt: Long,
        timeDiffSec: Long,
    ) {
        accessTokenCache.set(
            domain = domain,
            entry = AccessTokenEntry(
                accessToken = accessToken,
                expiresAt = serverExpiresAt + timeDiffSec,
            ),
        )
    }

    /**
     * Decode a [PreludeUser] from a raw access token.
     *
     * Throws the JWT decoder's [PreludeSessionError.InvalidChallengeToken]
     * if the token is malformed; the refresh path goes through
     * [makeUserForRefresh] to surface this as
     * [PreludeSessionError.RefreshFailed] per the documented contract.
     */
    internal fun makeUser(accessToken: String): PreludeUser =
        PreludeUser(
            accessToken = accessToken,
            profile = PreludeProfile.fromJwt(JwtDecoder.decode(accessToken)),
        )

    /**
     * [makeUser] wrapped for the refresh path: decode failures
     * surface as [PreludeSessionError.RefreshFailed] rather than the
     * JWT decoder's internal [PreludeSessionError.InvalidChallengeToken].
     * Centralised so every refresh entry point — both `refresh()`
     * fast paths and `doRefresh` post-network — reports the same
     * public-facing error type.
     */
    private fun makeUserForRefresh(accessToken: String): PreludeUser =
        try {
            makeUser(accessToken)
        } catch (e: PreludeSessionError.InvalidChallengeToken) {
            throw PreludeSessionError.RefreshFailed(
                "malformed access token: ${e.message}",
            )
        }

    private companion object {
        /**
         * Resolve the partition key from configuration. Throws
         * [PreludeSessionError.InvalidConfiguration] when neither
         * [hostOverride] nor [baseUrl]'s host yield a non-empty
         * value. Extracted so the public constructor can validate
         * before allocating the default stores (which open
         * SharedPreferences files).
         */
        fun deriveDomain(baseUrl: URL, hostOverride: String?): String =
            hostOverride?.takeIf { it.isNotEmpty() }
                ?: baseUrl.host?.takeIf { it.isNotEmpty() }
                ?: throw PreludeSessionError.InvalidConfiguration(
                    "baseUrl must have a host, or hostOverride must be non-empty",
                )

        /**
         * Validate the configuration up-front so an invalid
         * [baseUrl] / [hostOverride] surfaces before any of the
         * default factories opens a SharedPreferences file on disk.
         */
        fun validate(baseUrl: URL, hostOverride: String?) {
            deriveDomain(baseUrl, hostOverride)
        }

        fun newDefaultAccessCache(
            context: Context,
            baseUrl: URL,
            hostOverride: String?,
        ): AccessTokenCache {
            validate(baseUrl, hostOverride)
            return AccessTokenCache(
                storage = SharedPreferencesAccessTokenStorage(context.applicationContext),
            )
        }

        fun newDefaultRefreshStore(
            context: Context,
            baseUrl: URL,
            hostOverride: String?,
        ): RefreshTokenStore {
            validate(baseUrl, hostOverride)
            return RefreshTokenStore(
                storage = SharedPreferencesRefreshTokenStorage(context.applicationContext),
            )
        }

        fun newDefaultKeyStore(
            context: Context,
            baseUrl: URL,
            hostOverride: String?,
        ): DPoPKeyStore {
            validate(baseUrl, hostOverride)
            return newDPoPKeyStore(context.applicationContext)
        }
    }
}
