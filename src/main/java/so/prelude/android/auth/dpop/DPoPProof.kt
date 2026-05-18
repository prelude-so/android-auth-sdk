package so.prelude.android.auth.dpop

import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import java.time.Instant
import java.util.Base64
import java.util.UUID

/**
 * Build an RFC 9449 DPoP proof JWT.
 *
 * Header: `{"typ":"dpop+jwt","alg":"ES256","jwk":{kty,crv,x,y}}`.
 * Payload: `{"jti","htm","htu","iat"}` plus optional `nonce`.
 * Signature: ES256 over `base64url(header).base64url(payload)`.
 *
 * @param key the per-domain DPoP keypair handle. Public key is
 *   embedded in the header `jwk`; private key is used to sign.
 * @param method HTTP method (`GET`, `POST`, …).
 * @param url the request target URL — used as `htu` verbatim. The
 *   caller (the DPoP interceptor) is responsible for shaping this to
 *   match RFC 9449 § 4.2 (no query, no fragment) and applying any
 *   `Host:` override; see `dpopHtu(...)` in the http package.
 * @param nonce server-issued freshness token; omit on the first
 *   request to a fresh domain or for one-shot challenge proofs.
 * @param jti unique identifier for the proof. Caller may pin this
 *   to a challenge token's `jti` to prove ownership in step-up
 *   flows; otherwise a random UUID is generated.
 * @param now timestamp source. Injectable for tests.
 */
internal fun createDPoPProof(
    key: DPoPKey,
    method: String,
    url: String,
    nonce: String? = null,
    jti: String? = null,
    now: Instant = Instant.now(),
): String {
    val jwk = key.exportPublicJwk()

    val header =
        buildJsonObject {
            put("typ", JsonPrimitive("dpop+jwt"))
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
            put("jti", JsonPrimitive(jti ?: UUID.randomUUID().toString()))
            put("htm", JsonPrimitive(method))
            put("htu", JsonPrimitive(url))
            put("iat", JsonPrimitive(now.epochSecond))
            if (nonce != null) put("nonce", JsonPrimitive(nonce))
        }

    val encoder = Base64.getUrlEncoder().withoutPadding()
    val encodedHeader = encoder.encodeToString(header.toString().toByteArray(Charsets.UTF_8))
    val encodedPayload = encoder.encodeToString(payload.toString().toByteArray(Charsets.UTF_8))
    val signingInput = "$encodedHeader.$encodedPayload"
    val signature = key.signES256(signingInput.toByteArray(Charsets.UTF_8))
    return "$signingInput.${encoder.encodeToString(signature)}"
}
