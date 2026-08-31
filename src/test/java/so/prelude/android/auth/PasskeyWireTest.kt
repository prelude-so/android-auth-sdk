package so.prelude.android.auth

import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import so.prelude.android.auth.http.PasskeyLoginFinishBody
import so.prelude.android.auth.http.PasskeyRegisterFinishBody
import so.prelude.android.auth.http.PasskeyStepUpContinueBody
import so.prelude.android.auth.http.WIRE_JSON

/** Locks the passkey request-body wire shape and token redaction. */
class PasskeyWireTest {
    private val attestation = Json.parseToJsonElement(PasskeyFixtures.ATTESTATION_JSON)
    private val assertion = Json.parseToJsonElement(PasskeyFixtures.ASSERTION_JSON)

    private fun encode(value: Any): kotlinx.serialization.json.JsonObject =
        when (value) {
            is PasskeyRegisterFinishBody -> Json.parseToJsonElement(WIRE_JSON.encodeToString(value))
            is PasskeyLoginFinishBody -> Json.parseToJsonElement(WIRE_JSON.encodeToString(value))
            is PasskeyStepUpContinueBody -> Json.parseToJsonElement(WIRE_JSON.encodeToString(value))
            else -> error("unsupported")
        }.jsonObject

    @Test
    fun registerFinishBody_usesWireKeys() {
        val json = encode(PasskeyRegisterFinishBody("reg-tok", attestation))
        assertEquals("reg-tok", json["registration_token"]!!.jsonPrimitive.content)
        assertEquals(
            "att-obj",
            json["attestation"]!!
                .jsonObject["response"]!!
                .jsonObject["attestationObject"]!!
                .jsonPrimitive.content,
        )
    }

    @Test
    fun loginFinishBody_usesWireKeys() {
        val json = encode(PasskeyLoginFinishBody("login-tok", assertion))
        assertEquals("login-tok", json["login_token"]!!.jsonPrimitive.content)
        assertEquals(
            "sig",
            json["assertion"]!!
                .jsonObject["response"]!!
                .jsonObject["signature"]!!
                .jsonPrimitive.content,
        )
    }

    @Test
    fun stepUpContinueBody_usesWireKeys() {
        val json = encode(PasskeyStepUpContinueBody("chal-tok", assertion))
        assertEquals("chal-tok", json["challenge_token"]!!.jsonPrimitive.content)
        assertTrue(json.containsKey("passkey_assertion"))
    }

    @Test
    fun tokenBearingBodies_redactTokensInToString() {
        assertTrue("<redacted>" in PasskeyRegisterFinishBody("reg-tok", attestation).toString())
        assertFalse("reg-tok" in PasskeyRegisterFinishBody("reg-tok", attestation).toString())
        assertFalse("login-tok" in PasskeyLoginFinishBody("login-tok", assertion).toString())
        assertFalse("chal-tok" in PasskeyStepUpContinueBody("chal-tok", assertion).toString())
    }
}
