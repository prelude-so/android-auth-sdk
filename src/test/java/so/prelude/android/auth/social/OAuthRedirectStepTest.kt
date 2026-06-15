package so.prelude.android.auth.social

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import so.prelude.android.auth.PreludeAuthError

class OAuthRedirectStepTest {
    private val callback = "dev.prelude.demo://oauth-callback?challenge_token=t1"

    @Test
    fun launchesWhenAuthUrlPresentAndNotStarted() {
        val step = redirectStep(authStarted = false, authUrl = "https://idp/auth", redirect = null)
        assertEquals(RedirectStep.Launch("https://idp/auth"), step)
    }

    @Test
    fun completesWithRedirectAfterStart() {
        val step = redirectStep(authStarted = true, authUrl = null, redirect = callback)
        assertEquals(callback, (step as RedirectStep.Complete).result.getOrNull())
    }

    /** Host destroyed while the tab was open: the redirect arrives as a
     *  VIEW intent with no auth URL and authStarted reset to false. */
    @Test
    fun honorsRedirectOnRecreatedInstanceWithoutAuthUrl() {
        val step = redirectStep(authStarted = false, authUrl = null, redirect = callback)
        assertEquals(callback, (step as RedirectStep.Complete).result.getOrNull())
    }

    @Test
    fun cancelsWhenReturnedFromTabWithoutRedirect() {
        val step = redirectStep(authStarted = true, authUrl = "https://idp/auth", redirect = null)
        assertTrue((step as RedirectStep.Complete).result.exceptionOrNull() is PreludeAuthError.Cancelled)
    }

    @Test
    fun cancelsWhenNothingToLaunchOrResolve() {
        val step = redirectStep(authStarted = false, authUrl = null, redirect = null)
        assertTrue((step as RedirectStep.Complete).result.exceptionOrNull() is PreludeAuthError.Cancelled)
    }
}
