package so.prelude.android.auth

import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/** `listPasskeys` / `renamePasskey` / `deletePasskey`. */
class PasskeyManagementTest {
    @Test
    fun listPasskeys_mapsCredentials() =
        runBlocking {
            val fixture = Fixture.make()
            fixture.prePopulateStepUp()
            fixture.http.install(
                "/v1/session/me/passkeys",
                StubHttpSession.Canned.json(
                    """{"credentials":[{"credential_id":"c1","nickname":"Pixel","transports":["internal"],"backup_state":true,"created_at":1,"last_used_at":2}]}""",
                ),
            )

            val credentials = fixture.client.listPasskeys()

            assertEquals(1, credentials.size)
            assertEquals("c1", credentials.first().credentialId)
            assertEquals("Pixel", credentials.first().nickname)
            assertEquals(listOf("internal"), credentials.first().transports)
            assertEquals(2L, credentials.first().lastUsedAt)
        }

    @Test
    fun listPasskeys_emptyWhenNone() =
        runBlocking {
            val fixture = Fixture.make()
            fixture.prePopulateStepUp()
            fixture.http.install("/v1/session/me/passkeys", StubHttpSession.Canned.json("""{}"""))

            assertTrue(fixture.client.listPasskeys().isEmpty())
        }

    @Test
    fun renamePasskey_sendsPatchWithNickname() =
        runBlocking {
            val fixture = Fixture.make()
            fixture.prePopulateStepUp()
            fixture.http.install("/v1/session/me/passkeys/c1", StubHttpSession.Canned(statusCode = 204))

            fixture.client.renamePasskey("c1", nickname = "Work Laptop")

            val request = fixture.http.requestsFor("/v1/session/me/passkeys/c1").single()
            assertEquals("PATCH", request.method)
            assertEquals("Work Laptop", request.bodyAsJson()["nickname"]!!.jsonPrimitive.content)
        }

    @Test
    fun deletePasskey_refreshesAfterwards() =
        runBlocking {
            val fixture = Fixture.make()
            fixture.prePopulateStepUp()
            fixture.http.installAll(
                "/v1/session/me/passkeys/c1" to StubHttpSession.Canned(statusCode = 204),
                "/v1/session/refresh" to StepUpFixtures.refreshOk(),
            )

            fixture.client.deletePasskey("c1")

            val request = fixture.http.requestsFor("/v1/session/me/passkeys/c1").single()
            assertEquals("DELETE", request.method)
            assertEquals(1, fixture.http.requestCount("/v1/session/refresh"))
        }

    @Test
    fun renamePasskey_emptyCredentialId_throws_withoutNetwork() =
        runBlocking {
            val fixture = Fixture.make()
            assertThrows(PreludeAuthError.InvalidConfiguration::class.java) {
                runBlocking { fixture.client.renamePasskey("", nickname = "x") }
            }
            Unit
        }

    @Test
    fun deletePasskey_emptyCredentialId_throws_withoutNetwork() =
        runBlocking {
            val fixture = Fixture.make()
            assertThrows(PreludeAuthError.InvalidConfiguration::class.java) {
                runBlocking { fixture.client.deletePasskey("") }
            }
            Unit
        }
}
