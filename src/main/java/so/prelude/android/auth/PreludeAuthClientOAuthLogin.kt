package so.prelude.android.auth

import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import okhttp3.RequestBody.Companion.toRequestBody
import so.prelude.android.auth.crypto.JwtDecoder
import so.prelude.android.auth.crypto.Pkce
import so.prelude.android.auth.http.JSON_MEDIA_TYPE
import so.prelude.android.auth.http.OAuthAuthorizeRequestBody
import so.prelude.android.auth.http.OAuthAuthorizeResponseBody
import so.prelude.android.auth.http.OAuthLinkClaims
import so.prelude.android.auth.http.WIRE_JSON
import java.net.MalformedURLException
import java.net.URL

/*
 * OAuth web-login surface for [PreludeAuthClient]: the lower-level
 * initiate/finalize pair, for callers that present the provider page
 * themselves. Kept browser-dependency-free so this surface stays small.
 */

/** Identity providers supported for OAuth login. */
enum class OAuthProvider(
    internal val wireValue: String,
) {
    GOOGLE("google"),
    APPLE("apple"),
    MICROSOFT("microsoft"),
    GITHUB("github"),
    OKTA("okta"),
    FACEBOOK("facebook"),
}

/** Options for [initiateOAuthLogin]. */
data class InitiateOAuthLoginOptions(
    /** Provider to authenticate against. */
    val provider: OAuthProvider,
    /**
     * Where the server redirects once authentication completes. Must
     * be allowlisted by the app's configuration.
     */
    val redirectUri: String,
)

/** Outcome of redeeming an OAuth login callback. */
sealed interface FinalizeOAuthLoginResult {
    /** Session established. */
    data class LoggedIn(
        val user: PreludeUser,
    ) : FinalizeOAuthLoginResult

    /**
     * Provider email unverified; a one-time code was sent to [email].
     * The login completes once the code is verified.
     */
    data class OtpRequired(
        val challengeToken: String,
        val email: String?,
    ) : FinalizeOAuthLoginResult
}

/**
 * An in-progress OAuth login. Returned by [initiateOAuthLogin] and
 * redeemed by [finalizeOAuthLogin]. Carries this attempt's PKCE
 * verifier, so parallel logins can't clobber it.
 */
class OAuthLoginContext internal constructor(
    /** Authorization URL to present in a web authentication context. */
    val authorizationUrl: URL,
    internal val codeVerifier: String,
)

private val linkClaimsJson = Json { ignoreUnknownKeys = true }

/**
 * Begin an OAuth login, returning a context to present in a web
 * authentication context.
 *
 * Generates a PKCE pair bound to the returned [OAuthLoginContext];
 * pass that same context to [finalizeOAuthLogin]. Each call is
 * self-contained, so concurrent logins never share a verifier.
 *
 * Unauthenticated: the PKCE pair is the flow's only binding.
 */
suspend fun PreludeAuthClient.initiateOAuthLogin(options: InitiateOAuthLoginOptions): OAuthLoginContext {
    val codeVerifier = Pkce.generateCodeVerifier()
    val dispatchId = dispatchSignalsIfConfigured()

    val body =
        OAuthAuthorizeRequestBody(
            redirectUri = options.redirectUri,
            codeChallenge = Pkce.codeChallenge(codeVerifier),
            codeChallengeMethod = "S256",
            dispatchId = dispatchId,
        )

    val request =
        buildSessionRequest("login/oauth/${options.provider.wireValue}/authorize")
            .method("POST", WIRE_JSON.encodeToString(body).toRequestBody(JSON_MEDIA_TYPE))
            .build()

    val (response, _) =
        httpClient.sendJson(
            request = request,
            deserializer = OAuthAuthorizeResponseBody.serializer(),
            interceptors = emptyList(),
        )

    val url =
        response.authorizationUrl?.let { raw ->
            try {
                URL(raw)
            } catch (_: MalformedURLException) {
                null
            }
        } ?: throw PreludeAuthError.Generic(
            code = "invalid_authorization_url",
            displayMessage = "authorize response did not include a valid authorization URL",
        )

    return OAuthLoginContext(authorizationUrl = url, codeVerifier = codeVerifier)
}

/**
 * Redeem the `challenge_token` delivered to [context]'s redirect URI
 * and establish a session.
 *
 * Throws [PreludeAuthError.MissingChallengeToken] for an empty token
 * and [PreludeAuthError.InvalidChallengeToken] for a malformed one.
 */
suspend fun PreludeAuthClient.finalizeOAuthLogin(
    context: OAuthLoginContext,
    challengeToken: String,
): FinalizeOAuthLoginResult {
    if (challengeToken.isEmpty()) {
        throw PreludeAuthError.MissingChallengeToken(
            "Missing challenge token from login callback",
        )
    }

    val jwt = JwtDecoder.decode(challengeToken)
    val link =
        runCatching {
            linkClaimsJson.decodeFromJsonElement(OAuthLinkClaims.serializer(), jwt.payload)
        }.getOrNull()

    if (link?.grantMode == "oauth-email-link") {
        // Unverified provider email: deliver the verification code,
        // then hand the challenge back for the caller's OTP screen.
        // The PKCE verifier isn't used on this path.
        sendOTP(challengeToken)
        return FinalizeOAuthLoginResult.OtpRequired(
            challengeToken = challengeToken,
            email = link.metadata?.oauthEmail,
        )
    }

    val user = finalizeLogin(challengeToken = challengeToken, codeVerifier = context.codeVerifier)
    return FinalizeOAuthLoginResult.LoggedIn(user)
}
