package so.prelude.android.auth.dpop

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import java.util.Base64

/** Checks the signature with the key in the `jwk` header. */
internal fun verifyDeviceProof(jwt: String): Pair<JsonObject, JsonObject> {
    val parts = jwt.split('.')
    assertEquals(3, parts.size)
    val decoder = Base64.getUrlDecoder()
    val header = Json.parseToJsonElement(String(decoder.decode(parts[0]))).jsonObject
    val claims = Json.parseToJsonElement(String(decoder.decode(parts[1]))).jsonObject

    val jwk = header["jwk"]!!.jsonObject
    val params =
        AlgorithmParameters
            .getInstance("EC")
            .apply { init(ECGenParameterSpec("secp256r1")) }
            .getParameterSpec(ECParameterSpec::class.java)
    val point =
        ECPoint(
            BigInteger(1, decoder.decode(jwk["x"]!!.jsonPrimitive.content)),
            BigInteger(1, decoder.decode(jwk["y"]!!.jsonPrimitive.content)),
        )
    val publicKey = KeyFactory.getInstance("EC").generatePublic(ECPublicKeySpec(point, params))
    val verifier = Signature.getInstance("SHA256withECDSA").apply { initVerify(publicKey) }
    verifier.update("${parts[0]}.${parts[1]}".toByteArray())
    assertTrue("device proof signature must verify", verifier.verify(rawToDer(decoder.decode(parts[2]))))
    return header to claims
}

internal fun sha256Base64Url(value: String): String =
    Base64.getUrlEncoder().withoutPadding().encodeToString(MessageDigest.getInstance("SHA-256").digest(value.toByteArray()))

internal fun JsonObject.string(name: String): String = this[name]!!.jsonPrimitive.content

private fun rawToDer(raw: ByteArray): ByteArray {
    fun integer(bytes: ByteArray): ByteArray {
        val value = BigInteger(1, bytes).toByteArray()
        return byteArrayOf(0x02, value.size.toByte()) + value
    }
    val body = integer(raw.copyOfRange(0, 32)) + integer(raw.copyOfRange(32, 64))
    return byteArrayOf(0x30, body.size.toByte()) + body
}
