package so.prelude.android.session.dpop

import java.math.BigInteger
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.util.Base64

private const val ES256_ALGORITHM = "SHA256withECDSA"
private const val P256_BYTES = 32

/**
 * [DPoPKey] backed by an AndroidKeystore-resident keypair. For
 * StrongBox- and TEE-backed entries the private key never leaves
 * hardware; what's held here is a proxy [PrivateKey] handle.
 *
 * Thread-safe: fields are immutable and [Signature] is instantiated
 * per call.
 */
internal class AndroidKeystoreKey(
    private val privateKey: PrivateKey,
    private val publicKey: PublicKey,
) : DPoPKey {

    override fun exportPublicJwk(): Map<String, String> {
        val ec = publicKey as? ECPublicKey
            ?: throw DPoPKeyStoreError.InvalidPublicKey("not EC: ${publicKey.algorithm}")
        val encoder = Base64.getUrlEncoder().withoutPadding()
        return mapOf(
            "kty" to "EC",
            "crv" to "P-256",
            "x" to encoder.encodeToString(fixedWidth(ec.w.affineX, P256_BYTES)),
            "y" to encoder.encodeToString(fixedWidth(ec.w.affineY, P256_BYTES)),
        )
    }

    override fun signES256(data: ByteArray): ByteArray {
        val der = try {
            Signature.getInstance(ES256_ALGORITHM).run {
                initSign(privateKey)
                update(data)
                sign()
            }
        } catch (e: Exception) {
            throw DPoPKeyStoreError.SigningFailed(e)
        }
        return derToRawEcdsa(der, P256_BYTES)
    }
}

/**
 * Render [value] as a fixed-width [length]-byte big-endian unsigned
 * integer. `BigInteger.toByteArray()` may include a leading sign byte
 * (33 bytes for a 256-bit value with high bit set) or be shorter
 * than [length] (small magnitude); JWS § 4.2 requires fixed width.
 */
private fun fixedWidth(value: BigInteger, length: Int): ByteArray {
    val raw = value.toByteArray()
    return when {
        raw.size == length -> raw
        raw.size == length + 1 && raw[0] == 0x00.toByte() ->
            raw.copyOfRange(1, raw.size)
        raw.size < length -> ByteArray(length).also {
            raw.copyInto(it, destinationOffset = length - raw.size)
        }
        else -> throw DPoPKeyStoreError.InvalidPublicKey(
            "EC coordinate is ${raw.size} bytes; expected $length",
        )
    }
}
