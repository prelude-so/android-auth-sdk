package so.prelude.android.auth.crypto

import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64

/**
 * PKCE primitives (RFC 7636): a high-entropy code verifier and its
 * S256 code challenge, both base64url-encoded without padding.
 */
internal object Pkce {
    private val base64Url = Base64.getUrlEncoder().withoutPadding()

    /** Thread-safe and self-seeding; one instance serves all flows. */
    private val random = SecureRandom()

    /**
     * 32 random bytes, base64url-encoded — 43 chars, within the RFC's
     * 43–128 length bounds.
     */
    fun generateCodeVerifier(): String {
        val bytes = ByteArray(32)
        random.nextBytes(bytes)
        return base64Url.encodeToString(bytes)
    }

    /** S256 transform: SHA-256 of the verifier's ASCII bytes, base64url-encoded. */
    fun codeChallenge(verifier: String): String {
        val digest =
            MessageDigest
                .getInstance("SHA-256")
                .digest(verifier.toByteArray(Charsets.US_ASCII))
        return base64Url.encodeToString(digest)
    }
}
