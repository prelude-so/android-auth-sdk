package so.prelude.android.auth.social

import android.content.Context
import so.prelude.android.auth.FinalizeOAuthLoginResult
import so.prelude.android.auth.InitiateOAuthLoginOptions
import so.prelude.android.auth.PreludeAuthClient
import so.prelude.android.auth.PreludeAuthError
import so.prelude.android.auth.finalizeOAuthLogin
import so.prelude.android.auth.initiateOAuthLogin
import java.net.URI
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Authenticate against an identity provider in a Custom Tab and
 * establish a session.
 *
 * One-shot: requests the authorization URL, opens the provider page,
 * and redeems the callback. Only one login can be presented at a
 * time; a concurrent call throws [PreludeAuthError.Conflict]. A
 * dismissed page throws [PreludeAuthError.Cancelled].
 *
 * [OAuthLoginOptions.redirectUri] must use the app's custom URL
 * scheme; an `http`/`https` URI throws
 * [PreludeAuthError.InvalidConfiguration] before any network call.
 */
suspend fun PreludeAuthClient.loginWithOAuth(
    context: Context,
    options: OAuthLoginOptions,
): FinalizeOAuthLoginResult = loginWithOAuth(options, CustomTabsAuthPresenter(context.applicationContext))

/** Testable core of [loginWithOAuth]: the web presenter is injected. */
internal suspend fun PreludeAuthClient.loginWithOAuth(
    options: OAuthLoginOptions,
    presenter: WebAuthPresenting,
): FinalizeOAuthLoginResult {
    val scheme = runCatching { URI(options.redirectUri).scheme }.getOrNull()?.lowercase()
    if (scheme == null || scheme == "http" || scheme == "https") {
        throw PreludeAuthError.InvalidConfiguration(
            "redirectUri must use the app's custom URL scheme",
        )
    }

    if (!OAuthLoginGate.acquire()) {
        throw PreludeAuthError.Conflict("Another social login is already in progress")
    }
    try {
        val loginContext =
            initiateOAuthLogin(InitiateOAuthLoginOptions(options.provider, options.redirectUri))
        val callbackUrl = presenter.authenticate(loginContext.authorizationUrl, scheme)

        val redirect = OAuthRedirect.parse(callbackUrl)
        redirect.error?.let { throw it }
        val token =
            (redirect as? OAuthRedirect.Challenge)?.token
                ?: throw PreludeAuthError.MissingChallengeToken(
                    OAuthRedirect.MISSING_TOKEN_MESSAGE,
                )
        return finalizeOAuthLogin(loginContext, token)
    } finally {
        OAuthLoginGate.release()
    }
}

/**
 * Serializes login presentation: the system shows at most one web
 * authentication session at a time.
 */
internal object OAuthLoginGate {
    private val active = AtomicBoolean(false)

    /** Returns `true` if the gate was free and is now held. */
    fun acquire(): Boolean = active.compareAndSet(false, true)

    fun release() {
        active.set(false)
    }
}
