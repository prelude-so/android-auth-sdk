package so.prelude.android.auth

import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/** `registerPasskey` request shapes, ceremony wiring, and post-finish refresh. */
class PasskeyRegisterTest {
    private fun installFlow(
        fixture: Fixture,
        alreadyRegistered: Boolean = false,
    ) {
        fixture.http.installAll(
            "/v1/session/me/passkeys/register/begin" to PasskeyFixtures.registerBegin(),
            "/v1/session/me/passkeys/register/finish" to PasskeyFixtures.registerFinish(alreadyRegistered),
            "/v1/session/refresh" to StepUpFixtures.refreshOk(),
        )
    }

    @Test
    fun registerPasskey_sendsBeginBody_ceremony_andFinishBody() =
        runBlocking {
            val fixture = Fixture.make()
            fixture.prePopulateStepUp()
            installFlow(fixture)
            val fake = FakePasskeyCeremony()

            val result =
                fixture.client.registerPasskey(
                    RegisterPasskeyOptions(username = "a@b.co", displayName = "A B", nickname = "Pixel"),
                    fake,
                )

            val beginBody =
                fixture.http
                    .requestsFor("/v1/session/me/passkeys/register/begin")
                    .single()
                    .bodyAsJson()
            assertEquals("a@b.co", beginBody["username"]!!.jsonPrimitive.content)
            assertEquals("A B", beginBody["display_name"]!!.jsonPrimitive.content)
            assertEquals("Pixel", beginBody["nickname"]!!.jsonPrimitive.content)

            // The ceremony received the server's public_key verbatim.
            val handedOptions = Json.parseToJsonElement(fake.registeredOptions!!).jsonObject
            assertEquals("example.com", handedOptions["rp"]!!.jsonObject["id"]!!.jsonPrimitive.content)

            val finishBody =
                fixture.http
                    .requestsFor("/v1/session/me/passkeys/register/finish")
                    .single()
                    .bodyAsJson()
            assertEquals("reg-tok", finishBody["registration_token"]!!.jsonPrimitive.content)
            val response = finishBody["attestation"]!!.jsonObject["response"]!!.jsonObject
            assertEquals("cdj", response["clientDataJSON"]!!.jsonPrimitive.content)
            assertEquals("att-obj", response["attestationObject"]!!.jsonPrimitive.content)

            assertEquals("cred-id", result.credential.credentialId)
            assertTrue(result.credential.backupState)
            assertFalse(result.alreadyRegistered)
        }

    @Test
    fun registerPasskey_refreshesAfterFinish() =
        runBlocking {
            val fixture = Fixture.make()
            fixture.prePopulateStepUp()
            installFlow(fixture)

            fixture.client.registerPasskey(RegisterPasskeyOptions(username = "a@b.co"), FakePasskeyCeremony())

            assertEquals(1, fixture.http.requestCount("/v1/session/refresh"))
        }

    @Test
    fun registerPasskey_alreadyRegistered_isSurfaced() =
        runBlocking {
            val fixture = Fixture.make()
            fixture.prePopulateStepUp()
            installFlow(fixture, alreadyRegistered = true)

            val result =
                fixture.client.registerPasskey(RegisterPasskeyOptions(username = "a@b.co"), FakePasskeyCeremony())

            assertTrue(result.alreadyRegistered)
        }

    @Test
    fun registerPasskey_emptyUsername_throws_withoutNetwork() =
        runBlocking {
            val fixture = Fixture.make()
            fixture.prePopulateStepUp()

            assertThrows(PreludeAuthError.InvalidConfiguration::class.java) {
                runBlocking {
                    fixture.client.registerPasskey(RegisterPasskeyOptions(username = ""), FakePasskeyCeremony())
                }
            }
            assertEquals(0, fixture.http.requestCount("/v1/session/me/passkeys/register/begin"))
        }

    @Test
    fun registerPasskey_ceremonyFailure_propagates_andSkipsFinish() =
        runBlocking {
            val fixture = Fixture.make()
            fixture.prePopulateStepUp()
            installFlow(fixture)
            val fake = FakePasskeyCeremony()
            fake.registerError = PreludeAuthError.PasskeyRegistrationFailed("boom")

            assertThrows(PreludeAuthError.PasskeyRegistrationFailed::class.java) {
                runBlocking {
                    fixture.client.registerPasskey(RegisterPasskeyOptions(username = "a@b.co"), fake)
                }
            }
            assertEquals(0, fixture.http.requestCount("/v1/session/me/passkeys/register/finish"))
        }
}
