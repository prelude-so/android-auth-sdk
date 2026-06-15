package so.prelude.android.auth.social

import android.app.Activity
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import androidx.browser.customtabs.CustomTabsIntent
import kotlinx.coroutines.CompletableDeferred
import so.prelude.android.auth.PreludeAuthError

/**
 * Opens the provider page in a Custom Tab and resolves the
 * custom-scheme redirect.
 *
 * Apps add an `<intent-filter>` for their redirect scheme to this
 * activity; the SDK manifest supplies `launchMode`, theme, and a broad
 * `configChanges` so the login is not recreated mid-flow (it has no UI
 * to restore). The redirect is handled from whichever callback
 * delivers it ([onNewIntent] for a live instance, [onResume] for a
 * recreated one) and completes the login exactly once; a return with
 * no redirect is a dismissal, so the suspended caller is always
 * resumed.
 */
class OAuthRedirectActivity : Activity() {
    private var authStarted = false
    private var completed = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        authStarted = savedInstanceState?.getBoolean(KEY_AUTH_STARTED) ?: false
    }

    override fun onResume() {
        super.onResume()
        handleIntent()
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        handleIntent()
    }

    private fun handleIntent() {
        if (completed) return
        val step =
            redirectStep(
                authStarted = authStarted,
                authUrl = intent.getStringExtra(EXTRA_AUTH_URL),
                redirect = intent.data?.toString(),
            )
        when (step) {
            is RedirectStep.Launch -> {
                CustomTabsIntent.Builder().build().launchUrl(this, Uri.parse(step.authUrl))
                authStarted = true
            }

            is RedirectStep.Complete -> {
                completed = true
                resolve(step.result)
                finish()
            }
        }
    }

    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        outState.putBoolean(KEY_AUTH_STARTED, authStarted)
    }

    private fun resolve(result: Result<String>) {
        pending?.complete(result)
        pending = null
    }

    internal companion object {
        internal const val EXTRA_AUTH_URL = "so.prelude.android.auth.social.AUTH_URL"
        private const val KEY_AUTH_STARTED = "auth_started"

        /**
         * The suspended caller's slot. One login is presentable at a
         * time, so a single slot suffices to hand back the result.
         */
        @Volatile
        internal var pending: CompletableDeferred<Result<String>>? = null
    }
}

/** What [OAuthRedirectActivity] should do for the current intent. */
internal sealed interface RedirectStep {
    data class Launch(
        val authUrl: String,
    ) : RedirectStep

    data class Complete(
        val result: Result<String>,
    ) : RedirectStep
}

/**
 * Decides the next step from the current intent. A redirect is
 * honored whenever present — even on a freshly recreated instance
 * with no auth URL (host destroyed while the tab was open) — so the
 * callback is never dropped and the caller is always resumed. With no
 * redirect and nothing to launch, the page was dismissed.
 */
internal fun redirectStep(
    authStarted: Boolean,
    authUrl: String?,
    redirect: String?,
): RedirectStep =
    when {
        redirect != null -> RedirectStep.Complete(Result.success(redirect))
        !authStarted && authUrl != null -> RedirectStep.Launch(authUrl)
        else -> RedirectStep.Complete(Result.failure(PreludeAuthError.Cancelled()))
    }
