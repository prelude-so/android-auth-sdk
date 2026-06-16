package so.prelude.android.auth.social

import android.content.Context
import android.content.Intent
import kotlinx.coroutines.CompletableDeferred
import java.net.URL

/**
 * Presents a web authentication session and resolves the callback
 * URL. Abstracted so flows can be exercised without UI.
 *
 * Returns the raw redirect URL; throws [so.prelude.android.auth.PreludeAuthError.Cancelled]
 * when the person dismisses the page.
 */
internal interface WebAuthPresenting {
    suspend fun authenticate(
        authorizationUrl: URL,
        callbackScheme: String,
    ): String
}

/**
 * Chrome Custom Tabs-backed presenter. Hands the authorization URL
 * to [OAuthRedirectActivity], which opens the tab and resolves the
 * custom-scheme redirect.
 *
 * [callbackScheme] is declared in the manifest (the redirect
 * intent-filter), so it isn't needed again at launch time.
 */
internal class CustomTabsAuthPresenter(
    private val context: Context,
) : WebAuthPresenting {
    override suspend fun authenticate(
        authorizationUrl: URL,
        callbackScheme: String,
    ): String {
        val deferred = CompletableDeferred<Result<String>>()
        OAuthRedirectActivity.pending = deferred

        val intent =
            Intent(context, OAuthRedirectActivity::class.java)
                .putExtra(OAuthRedirectActivity.EXTRA_AUTH_URL, authorizationUrl.toString())
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)

        return try {
            context.startActivity(intent)
            deferred.await().getOrThrow()
        } finally {
            OAuthRedirectActivity.pending = null
        }
    }
}
