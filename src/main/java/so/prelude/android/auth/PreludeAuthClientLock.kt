package so.prelude.android.auth

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

val PreludeAuthClient.isSealed: Boolean
    get() = sealed

/**
 * Hide the profile and token and drop the token from memory.
 * Persistent storage stays, so [unseal] needs no network.
 * Returns `false` when there is no session to seal.
 */
suspend fun PreludeAuthClient.seal(): Boolean =
    withContext(Dispatchers.IO) {
        val refreshToken = refreshTokenStore.get(domain)?.refreshToken
        if (refreshToken.isNullOrEmpty()) return@withContext false
        sealed = true
        // An in-flight refresh would repopulate memory after the evict.
        inflightRefresh.joinIfRunning()
        accessTokenCache.evict(domain)
        true
    }

/**
 * Restore the token from storage. Authenticates nothing;
 * `PreludeIdleLock` proves presence first.
 */
suspend fun PreludeAuthClient.unseal() =
    withContext(Dispatchers.IO) {
        accessTokenCache.hydrate(domain)
        sealed = false
    }

internal fun PreludeAuthClient.requireUnsealed() {
    if (sealed) {
        throw PreludeAuthError.SessionLocked("Unlock the session before making protected calls")
    }
}
