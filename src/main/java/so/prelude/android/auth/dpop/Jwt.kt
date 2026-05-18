package so.prelude.android.auth.dpop

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonPrimitive
import java.util.Base64

// Real JWTs are well under 1 KiB. 8 KiB caps the damage if a hostile
// or misbehaving server returns a giant blob — base64-decoding that
// into a String would otherwise allocate proportionally. JWTs are
// ASCII so chars and bytes coincide here.
private const val MAX_JWT_CHARS = 8 * 1024

private val strictJson = Json { ignoreUnknownKeys = true }

/**
 * Read the `jti` claim from a compact JWT without verifying the
 * signature. The challenge interceptor needs the `jti` to bind a
 * proof to a step-up challenge token; we don't validate the token
 * here — the server already did when it issued it.
 *
 * Returns `null` for malformed tokens, oversized tokens, or missing
 * claims, so the interceptor can fall back to passing the request
 * through unchanged rather than failing the call outright.
 */
internal fun decodeJwtJti(token: String): String? {
    if (token.length > MAX_JWT_CHARS) return null
    val parts = token.split('.')
    if (parts.size != 3) return null
    return try {
        val payload = String(Base64.getUrlDecoder().decode(parts[1]), Charsets.UTF_8)
        val obj = strictJson.parseToJsonElement(payload) as? JsonObject ?: return null
        obj["jti"]?.jsonPrimitive?.contentOrNull
    } catch (_: Exception) {
        null
    }
}
