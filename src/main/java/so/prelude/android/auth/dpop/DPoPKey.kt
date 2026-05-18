package so.prelude.android.auth.dpop

/**
 * A DPoP signing key. Returned by [DPoPKeyStore]; consumed by the
 * proof builder.
 */
internal interface DPoPKey {
    /** Public key as a JWK map (`kty`, `crv`, `x`, `y`). */
    fun exportPublicJwk(): Map<String, String>

    /**
     * ES256 signature (ECDSA P-256 + SHA-256), in raw `r || s` form
     * (64 bytes), as required by JWS § 3.4.
     */
    fun signES256(data: ByteArray): ByteArray
}
