package so.prelude.android.auth

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import so.prelude.android.auth.dpop.DPoPKeyStoreError

/**
 * Delete the device key of this app install. The next sign-in creates
 * a new key, with a new `device_key_id`. [logout] keeps the key.
 * A step-up on a session signed in with the old key fails until the
 * user signs in again.
 */
suspend fun PreludeAuthClient.resetDeviceKey() {
    val store = deviceKeyStore ?: return
    withContext(Dispatchers.IO) {
        try {
            store.delete()
        } catch (e: DPoPKeyStoreError) {
            throw PreludeAuthError.CryptoFailure(e)
        }
    }
}
