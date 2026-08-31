package so.prelude.android.auth

import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

/** `loginWithPasskey`: ceremony wiring, finalize, and failure paths. */
class PasskeyLoginTest {
    @Test
    fun loginWithPasskey_runsCeremony_finalizes_andReturnsUser() =
        runBlocking {
            val fixture = Fixture.make()
            fixture.keyStore.getOrCreate(fixture.domain)
            fixture.http.installAll(
                "/v1/session/login/passkey/begin" to PasskeyFixtures.loginBegin(),
                "/v1/session/login/passkey/finish" to PasskeyFixtures.challengeTokenResponse("login-challenge"),
                "/v1/session/login/finalize" to StepUpFixtures.refreshOk(),
            )
            val fake = FakePasskeyCeremony()

            val user = fixture.client.loginWithPasskey(fake)

            assertEquals("user-1", user.profile.userId)

            // The ceremony received the server's request options verbatim.
            val handedOptions = Json.parseToJsonElement(fake.assertedOptions!!).jsonObject
            assertEquals("example.com", handedOptions["rpId"]!!.jsonPrimitive.content)

            val finishBody =
                fixture.http
                    .requestsFor("/v1/session/login/passkey/finish")
                    .single()
                    .bodyAsJson()
            assertEquals("login-tok", finishBody["login_token"]!!.jsonPrimitive.content)
            val response = finishBody["assertion"]!!.jsonObject["response"]!!.jsonObject
            assertEquals("sig", response["signature"]!!.jsonPrimitive.content)
            assertEquals("user-handle", response["userHandle"]!!.jsonPrimitive.content)
        }

    @Test
    fun loginWithPasskey_missingChallengeToken_throws() =
        runBlocking {
            val fixture = Fixture.make()
            fixture.http.installAll(
                "/v1/session/login/passkey/begin" to PasskeyFixtures.loginBegin(),
                "/v1/session/login/passkey/finish" to StubHttpSession.Canned.json("""{}"""),
            )

            assertThrows(PreludeAuthError.MissingChallengeToken::class.java) {
                runBlocking { fixture.client.loginWithPasskey(FakePasskeyCeremony()) }
            }
            Unit
        }

    @Test
    fun loginWithPasskey_cancelledCeremony_propagates_andSkipsFinish() =
        runBlocking {
            val fixture = Fixture.make()
            fixture.http.install("/v1/session/login/passkey/begin", PasskeyFixtures.loginBegin())
            val fake = FakePasskeyCeremony()
            fake.assertError = PreludeAuthError.Cancelled()

            assertThrows(PreludeAuthError.Cancelled::class.java) {
                runBlocking { fixture.client.loginWithPasskey(fake) }
            }
            assertEquals(0, fixture.http.requestCount("/v1/session/login/passkey/finish"))
        }
}
