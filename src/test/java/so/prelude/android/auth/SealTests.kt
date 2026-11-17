package so.prelude.android.auth

import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import so.prelude.android.auth.StubHttpSession.Canned

class SealTests {
    private val stepUpPath = "/v1/session/stepup/request"
    private val refreshPath = "/v1/session/refresh"

    @Test
    fun seal_hidesSession_butKeepsStorage() =
        runBlocking {
            val fixture = Fixture.make()
            fixture.prePopulateStepUp()
            assertNotNull(fixture.client.getAccessToken())

            assertTrue(fixture.client.seal())

            assertTrue(fixture.client.isSealed)
            assertNull(fixture.client.getAccessToken())
            assertNull(fixture.client.getProfile())
            assertNull(fixture.accessTokenCache.getWithoutExpirationCheck(fixture.domain))
            assertNotNull(fixture.accessTokenStorage.read(fixture.domain))
        }

    @Test
    fun unseal_restoresSession_withoutNetwork() =
        runBlocking {
            val fixture = Fixture.make()
            fixture.prePopulateStepUp()

            fixture.client.seal()
            fixture.client.unseal()

            assertFalse(fixture.client.isSealed)
            assertEquals(StepUpFixtures.SCOPED_ACCESS_TOKEN, fixture.client.getAccessToken())
            assertEquals(0, fixture.http.requestCount(refreshPath))
        }

    @Test
    fun seal_withoutSession_doesNothing() =
        runBlocking {
            val fixture = Fixture.make()

            assertFalse(fixture.client.seal())
            assertFalse(fixture.client.isSealed)
        }

    @Test
    fun seal_blocksProtectedCalls_beforeAnyRequest() =
        runBlocking {
            val fixture = Fixture.make()
            fixture.prePopulateStepUp()
            fixture.client.seal()

            assertThrows(PreludeAuthError.SessionLocked::class.java) {
                runBlocking { fixture.client.requestStepUp(scope = "prld:sensitive") }
            }
            assertEquals(0, fixture.http.requestCount(stepUpPath))
            assertEquals(0, fixture.http.requestCount(refreshPath))
        }

    @Test
    fun seal_while401InFlight_throwsSessionLocked_noRefresh() =
        runBlocking {
            val fixture = Fixture.make()
            fixture.prePopulateStepUp()
            fixture.http.install(stepUpPath, StepUpFixtures.apiError("unauthorized", status = 401))
            fixture.http.installGate(stepUpPath)

            coroutineScope {
                val request = async { runCatching { fixture.client.requestStepUp(scope = "prld:sensitive") } }
                StepUpFixtures.waitUntil { fixture.http.requestCount(stepUpPath) >= 1 }
                fixture.client.seal()
                fixture.http.releaseGate(stepUpPath)

                assertTrue(request.await().exceptionOrNull() is PreludeAuthError.SessionLocked)
            }
            assertEquals(1, fixture.http.requestCount(stepUpPath))
            assertEquals(0, fixture.http.requestCount(refreshPath))
        }

    @Test
    fun seal_blocksRefresh() =
        runBlocking {
            val fixture = Fixture.make()
            fixture.prePopulateStepUp()
            fixture.client.seal()

            assertThrows(PreludeAuthError.SessionLocked::class.java) {
                runBlocking { fixture.client.refresh() }
            }
            assertEquals(0, fixture.http.requestCount(refreshPath))
        }

    /** Memory can refill after the seal (late `hydrate`, a login). */
    @Test
    fun seal_blocksRefresh_evenWithAValidCachedToken() =
        runBlocking {
            val fixture = Fixture.make()
            fixture.prePopulateStepUp()
            fixture.client.seal()
            fixture.prePopulateStepUp()

            assertThrows(PreludeAuthError.SessionLocked::class.java) {
                runBlocking { fixture.client.refresh() }
            }
            assertNull(fixture.client.getAccessToken())
        }

    @Test
    fun unseal_reopensProtectedCalls() =
        runBlocking {
            val fixture = Fixture.make()
            fixture.prePopulateStepUp()
            fixture.http.install(stepUpPath, StepUpFixtures.stepUpResponse("block"))

            fixture.client.seal()
            fixture.client.unseal()
            fixture.client.requestStepUp(scope = "prld:sensitive")

            assertEquals(1, fixture.http.requestCount(stepUpPath))
        }

    @Test
    fun logout_clearsTheSeal() =
        runBlocking {
            val fixture = Fixture.make()
            fixture.prePopulateStepUp()
            fixture.http.install("/v1/session/revoke", Canned(statusCode = 204))

            fixture.client.seal()
            fixture.client.logout()

            assertFalse(fixture.client.isSealed)
        }
}
