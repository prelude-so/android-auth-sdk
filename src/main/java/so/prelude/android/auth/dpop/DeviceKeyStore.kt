package so.prelude.android.auth.dpop

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.spec.ECGenParameterSpec

/** Where the device key lives. Reported to the server as a hint only. */
internal enum class DeviceKeyStorage(
    val wireName: String,
) {
    StrongBox("strongbox"),
    Tee("tee"),
    Software("software"),
}

internal class DeviceKey(
    val key: DPoPKey,
    val storage: DeviceKeyStorage,
)

/** One key per app install. Logout keeps it, and AndroidKeystore keeps it out of backups. */
internal interface DeviceKeyStore {
    /** A read error is thrown, never treated as "no key": a new key would change the ID. */
    fun getOrCreate(): DeviceKey

    fun delete()
}

// App-scoped, not domain-scoped: a domain change must not rotate the ID.
internal const val DEVICE_KEY_ALIAS = "so.prelude.auth.device"

// Android attests a key only at creation, so the chain is made now for a later
// attestation check. The challenge token gives freshness, so this can be fixed.
private val ATTESTATION_CHALLENGE = "so.prelude.auth.device.v1".toByteArray(Charsets.UTF_8)

internal class AndroidKeystoreDeviceKeyStore(
    private val tierProvider: () -> KeystoreTier = KeystoreTier.Companion::detect,
) : DeviceKeyStore {
    private val keyStore: KeyStore by lazy { KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) } }

    override fun getOrCreate(): DeviceKey =
        synchronized(LOCK) {
            find() ?: create()
        }

    override fun delete() =
        synchronized(LOCK) {
            try {
                if (keyStore.containsAlias(DEVICE_KEY_ALIAS)) keyStore.deleteEntry(DEVICE_KEY_ALIAS)
            } catch (e: Exception) {
                throw DPoPKeyStoreError.KeystoreFailure(e)
            }
        }

    private fun find(): DeviceKey? {
        val raw =
            try {
                keyStore.getEntry(DEVICE_KEY_ALIAS, null)
            } catch (e: Exception) {
                throw DPoPKeyStoreError.KeystoreFailure(e)
            } ?: return null
        val entry =
            raw as? KeyStore.PrivateKeyEntry
                ?: throw DPoPKeyStoreError.KeystoreFailure(
                    IllegalStateException("Alias '$DEVICE_KEY_ALIAS' is not a PrivateKeyEntry"),
                )
        return DeviceKey(AndroidKeystoreKey(entry.privateKey, entry.certificate.publicKey), storageOf(entry))
    }

    private fun create(): DeviceKey {
        val strongBox = Build.VERSION.SDK_INT >= Build.VERSION_CODES.P && tierProvider() is KeystoreTier.StrongBox
        // StrongBox or attestation can fail on some devices; a TEE key without a
        // chain is still a hardware key.
        val attempts =
            listOfNotNull(
                (true to true).takeIf { strongBox },
                false to true,
                false to false,
            )
        var lastError: Exception? = null
        for ((useStrongBox, attest) in attempts) {
            try {
                generate(strongBox = useStrongBox, attest = attest)
                return find() ?: throw IllegalStateException("device key missing after generation")
            } catch (e: Exception) {
                lastError = e
            }
        }
        throw DPoPKeyStoreError.KeyGenerationFailed(lastError ?: IllegalStateException("no attempt"))
    }

    private fun generate(
        strongBox: Boolean,
        attest: Boolean,
    ) = KeyPairGenerator
        .getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE)
        .apply {
            // No user authentication: a lock screen change must not
            // invalidate the key.
            val spec =
                KeyGenParameterSpec
                    .Builder(DEVICE_KEY_ALIAS, KeyProperties.PURPOSE_SIGN)
                    .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                    .setDigests(KeyProperties.DIGEST_SHA256)
            if (attest) spec.setAttestationChallenge(ATTESTATION_CHALLENGE)
            if (strongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) spec.setIsStrongBoxBacked(true)
            initialize(spec.build())
        }.generateKeyPair()

    private fun storageOf(entry: KeyStore.PrivateKeyEntry): DeviceKeyStorage =
        runCatching {
            val info =
                KeyFactory
                    .getInstance(entry.privateKey.algorithm, ANDROID_KEYSTORE)
                    .getKeySpec(entry.privateKey, KeyInfo::class.java)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                when (info.securityLevel) {
                    KeyProperties.SECURITY_LEVEL_STRONGBOX -> DeviceKeyStorage.StrongBox
                    KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT -> DeviceKeyStorage.Tee
                    else -> DeviceKeyStorage.Software
                }
            } else {
                @Suppress("DEPRECATION")
                if (info.isInsideSecureHardware) DeviceKeyStorage.Tee else DeviceKeyStorage.Software
            }
        }.getOrDefault(DeviceKeyStorage.Software)

    private companion object {
        // Process-wide, so two clients in one process create one key.
        val LOCK = Any()
    }
}
