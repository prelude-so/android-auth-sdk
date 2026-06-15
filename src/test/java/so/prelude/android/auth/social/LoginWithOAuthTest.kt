package so.prelude.android.auth.social

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import so.prelude.android.auth.FinalizeOAuthLoginResult
import so.prelude.android.auth.Fixture
import so.prelude.android.auth.OAuthProvider
import so.prelude.android.auth.OtpFixtures
import so.prelude.android.auth.PreludeAuthError
import so.prelude.android.auth.StubHttpSession
import java.net.URL

/** Resolves immediately with a canned callback, recording its inputs. */
private class FakePresenter(
    private val callback: Result<String>,
) : WebAuthPresenting {
    var receivedUrl: URL? = null
    var receivedScheme: String? = null

    override suspend fun authenticate(
        authorizationUrl: URL,
        callbackScheme: String,
    ): String {
        receivedUrl = authorizationUrl
        receivedScheme = callbackScheme
        return callback.getOrThrow()
    }
}

/** Suspends inside `authenticate` until released, to hold the gate open. */
private class BlockingPresenter(
    private val callbackUrl: String,
) : WebAuthPresenting {
    private val entered = CompletableDeferred<Unit>()
    private val proceed = CompletableDeferred<Unit>()

    suspend fun waitUntilEntered() = entered.await()

    fun release() {
        proceed.complete(Unit)
    }

    override suspend fun authenticate(
        authorizationUrl: URL,
        callbackScheme: String,
    ): String {
        entered.complete(Unit)
        proceed.await()
        return callbackUrl
    }
}

class LoginWithOAuthTest {
    private val authorizePath = "/v1/session/login/oauth/google/authorize"

    private fun options() = OAuthLoginOptions(OAuthProvider.GOOGLE, "demo://oauth")

    /** Token in the redirect: a valid, non-email-link JWT. */
    private val challengeToken = OtpFixtures.JWT

    private fun successRedirect() = "demo://oauth?challenge_token=$challengeToken"

    private fun installHappyPath(fixture: Fixture) {
        fixture.http.installAll(
            authorizePath to StubHttpSession.Canned.json("""{"authorization_url":"https://provider.example/auth"}"""),
            "/v1/session/login/finalize" to OtpFixtures.finalizeOkResponse(),
        )
    }

    @Test
    fun loginWithOAuth_endToEnd() =
        runBlocking {
            val fixture = Fixture.make()
            installHappyPath(fixture)
            val presenter = FakePresenter(Result.success(successRedirect()))

            val result = fixture.client.loginWithOAuth(options(), presenter)

            assertEquals("user-1", (result as FinalizeOAuthLoginResult.LoggedIn).user.profile.userId)
            assertEquals("https://provider.example/auth", presenter.receivedUrl.toString())
            assertEquals("demo", presenter.receivedScheme)
        }

    @Test
    fun loginWithOAuth_httpsRedirectURI_throwsWithoutNetworkCall() {
        val fixture = Fixture.make()
        assertThrows(PreludeAuthError.InvalidConfiguration::class.java) {
            runBlocking {
                fixture.client.loginWithOAuth(
                    OAuthLoginOptions(OAuthProvider.GOOGLE, "https://example.com/cb"),
                    FakePresenter(Result.failure(PreludeAuthError.Cancelled())),
                )
            }
        }
        assertEquals(0, fixture.http.requestCount(authorizePath))
    }

    @Test
    fun loginWithOAuth_userCancel_surfacesCancelled_andReleasesGate() {
        val fixture = Fixture.make()
        installHappyPath(fixture)

        assertThrows(PreludeAuthError.Cancelled::class.java) {
            runBlocking {
                fixture.client.loginWithOAuth(
                    options(),
                    FakePresenter(Result.failure(PreludeAuthError.Cancelled())),
                )
            }
        }

        // Gate must be free again after the failure.
        val result =
            runBlocking {
                fixture.client.loginWithOAuth(options(), FakePresenter(Result.success(successRedirect())))
            }
        assertTrue(result is FinalizeOAuthLoginResult.LoggedIn)
    }

    @Test
    fun loginWithOAuth_concurrentLogin_throwsConflict() =
        runBlocking {
            val fixture = Fixture.make()
            installHappyPath(fixture)
            val blocking = BlockingPresenter(successRedirect())

            val first = async { fixture.client.loginWithOAuth(options(), blocking) }
            blocking.waitUntilEntered()

            assertThrows(PreludeAuthError.Conflict::class.java) {
                runBlocking {
                    fixture.client.loginWithOAuth(
                        options(),
                        FakePresenter(Result.failure(PreludeAuthError.Cancelled())),
                    )
                }
            }

            blocking.release()
            assertTrue(first.await() is FinalizeOAuthLoginResult.LoggedIn)
        }
}
