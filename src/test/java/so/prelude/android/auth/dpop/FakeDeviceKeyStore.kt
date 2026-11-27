package so.prelude.android.auth.dpop

import java.security.KeyPairGenerator
import java.security.spec.ECGenParameterSpec

/** Real P-256 key on the JVM, so tests can verify device proof signatures. */
internal fun newJvmDeviceKey(): AndroidKeystoreKey {
    val pair =
        KeyPairGenerator
            .getInstance("EC")
            .apply { initialize(ECGenParameterSpec("secp256r1")) }
            .generateKeyPair()
    return AndroidKeystoreKey(pair.private, pair.public)
}

/** In-memory [DeviceKeyStore]; [failRead] mimics a keystore read error. */
internal class FakeDeviceKeyStore(
    var failRead: Boolean = false,
) : DeviceKeyStore {
    private var key: DeviceKey? = null
    var createCount = 0
        private set

    override fun getOrCreate(): DeviceKey =
        synchronized(this) {
            if (failRead) throw DPoPKeyStoreError.KeystoreFailure(IllegalStateException("read failed"))
            key ?: DeviceKey(newJvmDeviceKey(), DeviceKeyStorage.Tee).also {
                key = it
                createCount++
            }
        }

    override fun delete() =
        synchronized(this) {
            key = null
        }
}
