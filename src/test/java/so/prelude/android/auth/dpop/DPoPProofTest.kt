package so.prelude.android.auth.dpop

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.KeyPairGenerator
import java.security.spec.ECGenParameterSpec
import java.time.Instant
import java.util.Base64

class DPoPProofTest {
    /**
     * Real ES256 [DPoPKey] backed by a JCE-generated keypair. Tests
     * that need the proof to actually verify use this; tests that
     * just inspect structure could use a stub, but reusing one path
     * keeps the surface small.
     */
    private fun realKey(): DPoPKey {
        val pair =
            KeyPairGenerator
                .getInstance("EC")
                .apply {
                    initialize(ECGenParameterSpec("secp256r1"))
                }.generateKeyPair()
        return AndroidKeystoreKey(pair.private, pair.public)
    }

    private fun decodeSegment(seg: String): JsonObject {
        val raw = Base64.getUrlDecoder().decode(seg)
        return Json.parseToJsonElement(String(raw)).jsonObject
    }

    @Test
    fun proof_isThreeBase64UrlSegments() {
        val proof = createDPoPProof(realKey(), "POST", "https://api.example.com/v1/login")
        val parts = proof.split('.')
        assertEquals(3, parts.size)
        // Base64url alphabet: A-Z a-z 0-9 - _
        val b64url = Regex("^[A-Za-z0-9_-]+$")
        parts.forEach { assertTrue("segment was not base64url: $it", b64url.matches(it)) }
    }

    @Test
    fun header_hasRequiredClaimsAndJwk() {
        val proof = createDPoPProof(realKey(), "GET", "https://api.example.com/v1/me")
        val header = decodeSegment(proof.substringBefore('.'))

        assertEquals("dpop+jwt", header["typ"]?.jsonPrimitive?.content)
        assertEquals("ES256", header["alg"]?.jsonPrimitive?.content)

        val jwk = header["jwk"]?.jsonObject ?: error("jwk missing")
        assertEquals("EC", jwk["kty"]?.jsonPrimitive?.content)
        assertEquals("P-256", jwk["crv"]?.jsonPrimitive?.content)
        // Coordinates are 32 bytes → 43 base64url chars unpadded.
        assertEquals(43, jwk["x"]?.jsonPrimitive?.content?.length)
        assertEquals(43, jwk["y"]?.jsonPrimitive?.content?.length)
    }

    @Test
    fun payload_hasRequiredClaims() {
        val now = Instant.parse("2026-01-15T12:00:00Z")
        val proof =
            createDPoPProof(
                realKey(),
                method = "POST",
                url = "https://api.example.com/v1/login",
                now = now,
            )
        val payload = decodeSegment(proof.split('.')[1])

        assertEquals("POST", payload["htm"]?.jsonPrimitive?.content)
        assertEquals("https://api.example.com/v1/login", payload["htu"]?.jsonPrimitive?.content)
        assertEquals(now.epochSecond, payload["iat"]?.jsonPrimitive?.long)
        assertNotNull("jti must be present", payload["jti"]?.jsonPrimitive?.content)
    }

    @Test
    fun payload_omitsNonceWhenAbsent() {
        val proof = createDPoPProof(realKey(), "GET", "https://api.example.com/v1/me", nonce = null)
        val payload = decodeSegment(proof.split('.')[1])
        assertNull(payload["nonce"])
    }

    @Test
    fun payload_includesNonceWhenProvided() {
        val proof =
            createDPoPProof(
                realKey(),
                "GET",
                "https://api.example.com/v1/me",
                nonce = "fresh-nonce",
            )
        val payload = decodeSegment(proof.split('.')[1])
        assertEquals("fresh-nonce", payload["nonce"]?.jsonPrimitive?.content)
    }

    @Test
    fun payload_iat_appliesPositiveClockSkewMs() {
        val now = Instant.parse("2026-01-15T12:00:00Z")
        val proof =
            createDPoPProof(
                realKey(),
                method = "POST",
                url = "https://api.example.com/v1/login",
                now = now,
                clockSkewMs = 30_000L,
            )
        val payload = decodeSegment(proof.split('.')[1])
        assertEquals(now.epochSecond + 30, payload["iat"]?.jsonPrimitive?.long)
    }

    @Test
    fun payload_iat_appliesNegativeClockSkewMs() {
        val now = Instant.parse("2026-01-15T12:00:00Z")
        val proof =
            createDPoPProof(
                realKey(),
                method = "POST",
                url = "https://api.example.com/v1/login",
                now = now,
                clockSkewMs = -45_000L,
            )
        val payload = decodeSegment(proof.split('.')[1])
        assertEquals(now.epochSecond - 45, payload["iat"]?.jsonPrimitive?.long)
    }

    /**
     * `Math.floorDiv` (not truncating division) keeps the iat
     * non-overestimating when the corrected wall clock falls on a
     * sub-second tick before a whole second — a positive raw value
     * truncated toward zero would equal `floor`, but for negatives
     * `(-1500 / 1000) == -1` whereas `floorDiv(-1500, 1000) == -2`.
     */
    @Test
    fun payload_iat_negativeSubSecondSkewFloorsTowardEarlier() {
        val now = Instant.parse("2026-01-15T12:00:00Z")
        val proof =
            createDPoPProof(
                realKey(),
                method = "POST",
                url = "https://api.example.com/v1/login",
                now = now,
                clockSkewMs = -500L,
            )
        val payload = decodeSegment(proof.split('.')[1])
        assertEquals(now.epochSecond - 1, payload["iat"]?.jsonPrimitive?.long)
    }

    @Test
    fun payload_jtiCanBeOverridden() {
        val proof =
            createDPoPProof(
                realKey(),
                "POST",
                "https://api.example.com/v1/step-up",
                jti = "challenge-token-jti-pinned",
            )
        val payload = decodeSegment(proof.split('.')[1])
        assertEquals("challenge-token-jti-pinned", payload["jti"]?.jsonPrimitive?.content)
    }

    @Test
    fun payload_jtiIsFreshOnEachCallByDefault() {
        val key = realKey()
        val a = decodeSegment(createDPoPProof(key, "GET", "https://x.example/").split('.')[1])
        val b = decodeSegment(createDPoPProof(key, "GET", "https://x.example/").split('.')[1])
        assertNotEquals(
            a["jti"]?.jsonPrimitive?.content,
            b["jti"]?.jsonPrimitive?.content,
        )
    }
}
