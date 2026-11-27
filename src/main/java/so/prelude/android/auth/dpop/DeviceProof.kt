package so.prelude.android.auth.dpop

import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import java.security.MessageDigest
import java.util.Base64

private val base64Url = Base64.getUrlEncoder().withoutPadding()

internal fun createDeviceProof(
    deviceKey: DeviceKey,
    dpopKey: DPoPKey,
    method: String,
    url: String,
    challengeToken: String,
): String {
    val jwk = deviceKey.key.exportPublicJwk()
    val header =
        buildJsonObject {
            put("typ", JsonPrimitive("device-proof+jwt"))
            put("alg", JsonPrimitive("ES256"))
            put(
                "jwk",
                buildJsonObject {
                    put("kty", JsonPrimitive(jwk["kty"]))
                    put("crv", JsonPrimitive(jwk["crv"]))
                    put("x", JsonPrimitive(jwk["x"]))
                    put("y", JsonPrimitive(jwk["y"]))
                },
            )
        }
    val payload =
        buildJsonObject {
            put("htm", JsonPrimitive(method))
            put("htu", JsonPrimitive(url))
            put("cth", JsonPrimitive(sha256Base64Url(challengeToken.toByteArray(Charsets.UTF_8))))
            put("jkt", JsonPrimitive(jwkThumbprint(dpopKey.exportPublicJwk())))
            put("key_storage", JsonPrimitive(deviceKey.storage.wireName))
        }

    return compactES256(header, payload, deviceKey.key)
}

/** RFC 7638 JWK thumbprint. */
internal fun jwkThumbprint(jwk: Map<String, String>): String {
    val crv = jwk["crv"] ?: throw DPoPKeyStoreError.InvalidPublicKey("jwk has no crv")
    val kty = jwk["kty"] ?: throw DPoPKeyStoreError.InvalidPublicKey("jwk has no kty")
    val xCoord = jwk["x"] ?: throw DPoPKeyStoreError.InvalidPublicKey("jwk has no x")
    val yCoord = jwk["y"] ?: throw DPoPKeyStoreError.InvalidPublicKey("jwk has no y")
    val canonical =
        buildJsonObject {
            put("crv", JsonPrimitive(crv))
            put("kty", JsonPrimitive(kty))
            put("x", JsonPrimitive(xCoord))
            put("y", JsonPrimitive(yCoord))
        }.toString()
    return sha256Base64Url(canonical.toByteArray(Charsets.UTF_8))
}

private fun sha256Base64Url(data: ByteArray): String = base64Url.encodeToString(MessageDigest.getInstance("SHA-256").digest(data))
