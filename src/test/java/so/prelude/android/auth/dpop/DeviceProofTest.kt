package so.prelude.android.auth.dpop

import org.junit.Assert.assertEquals
import org.junit.Test

class DeviceProofTest {
    @Test
    fun proof_isSignedAndBound() {
        val dpopKey = newJvmDeviceKey()
        val proof =
            createDeviceProof(
                deviceKey = DeviceKey(newJvmDeviceKey(), DeviceKeyStorage.StrongBox),
                dpopKey = dpopKey,
                method = "POST",
                url = "https://auth.example/v1/session/login/finalize",
                challengeToken = "challenge-abc",
            )

        val (header, claims) = verifyDeviceProof(proof)
        assertEquals("device-proof+jwt", header.string("typ"))
        assertEquals("ES256", header.string("alg"))
        assertEquals("POST", claims.string("htm"))
        assertEquals("https://auth.example/v1/session/login/finalize", claims.string("htu"))
        assertEquals(sha256Base64Url("challenge-abc"), claims.string("cth"))
        assertEquals(jwkThumbprint(dpopKey.exportPublicJwk()), claims.string("jkt"))
        assertEquals("strongbox", claims.string("key_storage"))
    }

    /** The Go server and the iOS SDK test the same value. */
    @Test
    fun thumbprint_matchesRFC7638() {
        val jwk =
            mapOf(
                "kty" to "EC",
                "crv" to "P-256",
                "x" to "axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY",
                "y" to "T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU",
            )
        assertEquals("xx0BcA-wMohw8atYDJOe6peGModklG2wRHBlXHMvl0M", jwkThumbprint(jwk))
    }
}
