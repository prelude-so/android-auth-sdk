package so.prelude.android.auth.social

import so.prelude.android.auth.OAuthProvider

/** Options for [loginWithOAuth]. */
data class OAuthLoginOptions(
    /** Provider to authenticate against. */
    val provider: OAuthProvider,
    /**
     * Where the provider redirects once authentication completes.
     * Must use the app's custom URL scheme (e.g.
     * `myapp://oauth-callback`) — the same scheme the app declares as
     * the `preludeAuthRedirectScheme` manifest placeholder — and be
     * allowlisted by the app's configuration.
     */
    val redirectUri: String,
)
