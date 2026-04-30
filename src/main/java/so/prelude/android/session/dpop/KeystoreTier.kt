package so.prelude.android.session.dpop

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.util.Log
import androidx.annotation.RequiresApi
import androidx.annotation.VisibleForTesting
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.spec.ECGenParameterSpec
import java.util.UUID

internal const val ANDROID_KEYSTORE = "AndroidKeyStore"
private const val LOG_TAG = "PreludeSession"

/** AndroidKeystore alias for [domain]'s DPoP keypair. */
internal fun aliasFor(domain: String): String = "so.prelude.session.dpop.$domain"

/** Common base spec — every tier signs ES256 over P-256. */
private fun baseSpecBuilder(alias: String): KeyGenParameterSpec.Builder =
    KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
        .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
        .setDigests(KeyProperties.DIGEST_SHA256)

/**
 * The hardware-protection tier the device offers for ECDSA-P256
 * keys, in descending strength.
 */
internal sealed interface KeystoreTier {
    /** [KeyGenParameterSpec] sized for this tier. */
    fun buildSpec(alias: String): KeyGenParameterSpec

    data object Software : KeystoreTier {
        override fun buildSpec(alias: String) = baseSpecBuilder(alias).build()
    }

    data object Tee : KeystoreTier {
        override fun buildSpec(alias: String) = baseSpecBuilder(alias).build()
    }

    /**
     * StrongBox is API 28+ — [RequiresApi] makes lint enforce that
     * any caller constructing this object is itself API-gated.
     * [detect] guarantees we never return [StrongBox] below API 28.
     */
    @RequiresApi(Build.VERSION_CODES.P)
    data object StrongBox : KeystoreTier {
        override fun buildSpec(alias: String) =
            baseSpecBuilder(alias).setIsStrongBoxBacked(true).build()
    }

    companion object {
        // Private monitor — synchronizing on the companion itself
        // would expose the lock to outside code (`KeystoreTier.Companion`
        // is publicly reachable).
        private val probeLock = Any()

        @Volatile private var cached: KeystoreTier? = null

        /**
         * Probe the device once and cache the verdict.
         *
         * The probe generates a throwaway P-256 key per tier rather
         * than trusting `PackageManager.hasSystemFeature(...)`:
         * vendors ship the StrongBox feature flag enabled with broken
         * firmware, and `KeyPairGenerator` silently downgrades
         * hardware requests on TEE-less devices, so feature flags and
         * spec acceptance both lie. Only the resulting [KeyInfo]
         * tells the truth.
         *
         * Blocking I/O on first call (hundreds of ms, sometimes >1s
         * on cheap devices). Callers must invoke from a background
         * dispatcher; the SDK does this via `withContext(Dispatchers.IO)`
         * in the DPoP interceptors.
         */
        fun detect(): KeystoreTier = cached ?: synchronized(probeLock) {
            cached ?: runProbe().also { cached = it }
        }

        /**
         * Test-only: clear the cached probe verdict so the next
         * [detect] call re-probes.
         *
         * Production callers don't need this — hardware capability
         * doesn't change mid-process. Integration tests that exercise
         * the full DPoP flow across test methods do.
         */
        @VisibleForTesting
        internal fun resetForTesting() = synchronized(probeLock) { cached = null }

        private fun runProbe(): KeystoreTier {
            val verdict = when {
                Build.VERSION.SDK_INT >= Build.VERSION_CODES.P && probeStrongBox() -> StrongBox
                probeTee() -> Tee
                else -> Software
            }
            Log.d(LOG_TAG, "DPoP keystore tier: ${verdict::class.simpleName}")
            return verdict
        }

        @RequiresApi(Build.VERSION_CODES.P)
        private fun probeStrongBox(): Boolean = withProbeKey { alias ->
            generateProbeKey(StrongBox.buildSpec(alias)) != null
        }

        private fun probeTee(): Boolean = withProbeKey { alias ->
            val key = generateProbeKey(Tee.buildSpec(alias)) ?: return@withProbeKey false
            isHardwareBacked(key)
        }

        private fun generateProbeKey(spec: KeyGenParameterSpec): PrivateKey? = try {
            KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE)
                .apply { initialize(spec) }
                .generateKeyPair()
                .private
        } catch (_: Exception) {
            null
        }

        private fun isHardwareBacked(privateKey: PrivateKey): Boolean = try {
            val factory = KeyFactory.getInstance(privateKey.algorithm, ANDROID_KEYSTORE)
            val info = factory.getKeySpec(privateKey, KeyInfo::class.java) as KeyInfo
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                info.securityLevel >= KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT
            } else {
                @Suppress("DEPRECATION")
                info.isInsideSecureHardware
            }
        } catch (e: Exception) {
            // Treat as software-backed and continue. Logged at WARN
            // so a "device should be TEE but registers as SOFTWARE"
            // bug report has a breadcrumb in logcat.
            Log.w(LOG_TAG, "DPoP keystore: KeyInfo inspection failed; treating as software", e)
            false
        }

        /** Run [block] with a unique alias, then clean the alias up. */
        private inline fun withProbeKey(block: (alias: String) -> Boolean): Boolean {
            val alias = "so.prelude.session.dpop.probe.${UUID.randomUUID()}"
            return try {
                block(alias)
            } finally {
                runCatching {
                    KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }.deleteEntry(alias)
                }
            }
        }
    }
}
