package so.prelude.android.auth.lock

import android.content.Context
import android.content.SharedPreferences
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.util.Base64
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import so.prelude.android.auth.PreludeAuthError
import java.security.GeneralSecurityException
import java.security.KeyStore
import java.security.SecureRandom
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

/**
 * App-lock credentials: a passcode and an optional biometric
 * shortcut. The passcode is never stored; it derives a key that
 * wraps a random secret, wrapped again by a Keystore key, so a
 * successful double decrypt is the verification. Attempts are
 * counted here because a short passcode has no hardware rate limit.
 */
internal class AppLockStore(
    context: Context,
    private val domain: String,
    private val maxAttempts: Int = DEFAULT_MAX_ATTEMPTS,
) {
    private val context = context.applicationContext
    private val prefs: SharedPreferences =
        this.context.getSharedPreferences(PREFS_FILE, Context.MODE_PRIVATE)
    private val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

    private val passcodeKey = "passcode:$domain"
    private val attemptsKey = "attempts:$domain"
    private val passcodeAlias = "so.prelude.auth.lock.passcode.$domain"
    private val biometricAlias = "so.prelude.auth.lock.biometric.$domain"

    // MARK: - Passcode

    /**
     * Both halves must be present: Auto Backup restores the blob
     * but not the Keystore key, and a lock with no key cannot open.
     */
    val hasPasscode: Boolean
        get() = prefs.contains(passcodeKey) && keyStore.containsAlias(passcodeAlias)

    /** Also drops the biometric shortcut, armed against the old one. */
    fun setPasscode(passcode: String) {
        if (passcode.length < 4) {
            throw PreludeAuthError.InvalidPasscode("A passcode needs at least 4 digits")
        }
        val salt = randomBytes(16)
        val blob =
            try {
                val inner = encrypt(deriveKey(passcode, salt), randomBytes(32))
                encode(salt) + ":" + encode(encrypt(getOrCreateWrappingKey(), inner))
            } catch (e: GeneralSecurityException) {
                throw PreludeAuthError.LockUnavailable("Cannot wrap the passcode: ${e.message}")
            }

        // Fallible prep is done; only now replace the old credentials.
        disableBiometrics()
        if (!prefs.edit().putString(passcodeKey, blob).commit()) {
            throw PreludeAuthError.LockUnavailable("Cannot store the passcode")
        }
        resetAttempts()
    }

    /**
     * Throws [PreludeAuthError.InvalidPasscode] on a wrong one and
     * [PreludeAuthError.LockedOut] once the attempts are spent.
     */
    fun verify(passcode: String) {
        if (!hasPasscode) {
            throw PreludeAuthError.LockUnavailable("No passcode is set")
        }
        val blob = prefs.getString(passcodeKey, null).orEmpty()
        val spent = attempts
        if (spent >= maxAttempts) {
            throw PreludeAuthError.LockedOut("Too many attempts")
        }
        val parts = blob.split(":")
        if (parts.size != 2) {
            throw PreludeAuthError.LockUnavailable("Cannot decode the passcode item")
        }
        val (salt, outer) = parts.map(::decode)
        val wrappingKey =
            keyStore.getKey(passcodeAlias, null) as? SecretKey
                ?: throw PreludeAuthError.LockUnavailable("The passcode key is missing")

        // A wrong passcode is a failed decryption; anything else is
        // the store's problem, not the user's.
        val ok =
            try {
                decrypt(deriveKey(passcode, salt), decrypt(wrappingKey, outer))
                true
            } catch (e: AEADBadTagException) {
                false
            } catch (e: GeneralSecurityException) {
                throw PreludeAuthError.LockUnavailable("Cannot read the passcode item: ${e.message}")
            }

        if (!ok) {
            setAttempts(spent + 1)
            if (spent + 1 >= maxAttempts) {
                throw PreludeAuthError.LockedOut("Too many attempts")
            }
            throw PreludeAuthError.InvalidPasscode("Wrong passcode — ${maxAttempts - spent - 1} attempts left")
        }
        resetAttempts()
    }

    // MARK: - Biometric shortcut

    val isBiometricsEnabled: Boolean
        get() = keyStore.containsAlias(biometricAlias)

    val isBiometricsAvailable: Boolean
        get() =
            try {
                BiometricManager.from(context).canAuthenticate(BIOMETRIC_STRONG) == BiometricManager.BIOMETRIC_SUCCESS
            } catch (e: NoClassDefFoundError) {
                // androidx.biometric is compile-only, so apps without biometrics do not ship it.
                false
            }

    /** Requires a passcode, so there is always a way in. */
    fun enableBiometrics() {
        if (!hasPasscode) {
            throw PreludeAuthError.LockUnavailable("Set a passcode before enabling biometrics")
        }
        if (!isBiometricsAvailable) {
            throw PreludeAuthError.LockUnavailable("No enrolled biometrics, or androidx.biometric is missing")
        }
        disableBiometrics()

        val spec =
            KeyGenParameterSpec
                .Builder(biometricAlias, KeyProperties.PURPOSE_ENCRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setUserAuthenticationRequired(true)
                .setInvalidatedByBiometricEnrollment(true)
                .apply {
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                        setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
                    } else {
                        @Suppress("DEPRECATION")
                        setUserAuthenticationValidityDurationSeconds(-1)
                    }
                }.build()
        generateKey(spec)
    }

    fun disableBiometrics() {
        keyStore.deleteEntry(biometricAlias)
    }

    /** Shows the system sheet; a completed cipher is proof of presence. */
    suspend fun verifyBiometrics(
        activity: FragmentActivity,
        title: String,
    ) {
        if (!isBiometricsEnabled) {
            throw PreludeAuthError.LockUnavailable("The biometric shortcut is not enabled")
        }
        val cipher =
            try {
                Cipher.getInstance(TRANSFORMATION).apply {
                    init(Cipher.ENCRYPT_MODE, keyStore.getKey(biometricAlias, null) as SecretKey)
                }
            } catch (e: KeyPermanentlyInvalidatedException) {
                disableBiometrics()
                throw PreludeAuthError.LockUnavailable("Biometrics changed — enable the shortcut again")
            } catch (e: GeneralSecurityException) {
                throw PreludeAuthError.LockUnavailable("Cannot use the biometric key: ${e.message}")
            }

        val info =
            BiometricPrompt.PromptInfo
                .Builder()
                .setTitle(title)
                .setNegativeButtonText("Cancel")
                .setAllowedAuthenticators(BIOMETRIC_STRONG)
                .build()

        withContext(Dispatchers.Main) {
            suspendCancellableCoroutine { continuation ->
                val prompt =
                    BiometricPrompt(
                        activity,
                        ContextCompat.getMainExecutor(activity),
                        object : BiometricPrompt.AuthenticationCallback() {
                            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                                val cipher = result.cryptoObject?.cipher
                                val ok = cipher != null && runCatching { cipher.doFinal(ByteArray(1)) }.isSuccess
                                if (ok) {
                                    continuation.resume(Unit)
                                } else {
                                    continuation.resumeWithException(
                                        PreludeAuthError.LockUnavailable("Biometric check was not confirmed"),
                                    )
                                }
                            }

                            override fun onAuthenticationError(
                                errorCode: Int,
                                errString: CharSequence,
                            ) {
                                continuation.resumeWithException(PreludeAuthError.LockUnavailable(errString.toString()))
                            }
                        },
                    )
                prompt.authenticate(info, BiometricPrompt.CryptoObject(cipher))
                continuation.invokeOnCancellation { prompt.cancelAuthentication() }
            }
        }
        resetAttempts()
    }

    // MARK: - Wipe

    fun clear() {
        clearPasscode()
        disableBiometrics()
        resetAttempts()
    }

    // MARK: - Attempts

    val attempts: Int
        get() = prefs.getInt(attemptsKey, 0)

    /** Fails closed: an unrecorded attempt refuses the passcode. */
    private fun setAttempts(value: Int) {
        if (!prefs.edit().putInt(attemptsKey, value).commit()) {
            throw PreludeAuthError.LockUnavailable("Cannot record the attempt")
        }
    }

    private fun resetAttempts() {
        prefs.edit().remove(attemptsKey).commit()
    }

    // MARK: - Crypto helpers

    private fun clearPasscode() {
        prefs.edit().remove(passcodeKey).commit()
        keyStore.deleteEntry(passcodeAlias)
    }

    private fun getOrCreateWrappingKey(): SecretKey {
        (keyStore.getKey(passcodeAlias, null) as? SecretKey)?.let { return it }
        val spec =
            KeyGenParameterSpec
                .Builder(passcodeAlias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .build()
        return generateKey(spec)
    }

    private fun generateKey(spec: KeyGenParameterSpec): SecretKey =
        try {
            KeyGenerator
                .getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
                .apply { init(spec) }
                .generateKey()
        } catch (e: Exception) {
            throw PreludeAuthError.LockUnavailable("Cannot create a lock key: ${e.message}")
        }

    private fun deriveKey(
        passcode: String,
        salt: ByteArray,
    ): SecretKey {
        val spec = PBEKeySpec(passcode.toCharArray(), salt, PBKDF2_ITERATIONS, 256)
        val bytes = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).encoded
        return SecretKeySpec(bytes, KeyProperties.KEY_ALGORITHM_AES)
    }

    private fun encrypt(
        key: SecretKey,
        plaintext: ByteArray,
    ): ByteArray {
        val cipher = Cipher.getInstance(TRANSFORMATION).apply { init(Cipher.ENCRYPT_MODE, key) }
        return cipher.iv + cipher.doFinal(plaintext)
    }

    private fun decrypt(
        key: SecretKey,
        blob: ByteArray,
    ): ByteArray {
        val cipher =
            Cipher.getInstance(TRANSFORMATION).apply {
                init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, blob, 0, GCM_IV_BYTES))
            }
        return cipher.doFinal(blob, GCM_IV_BYTES, blob.size - GCM_IV_BYTES)
    }

    private fun randomBytes(count: Int): ByteArray = ByteArray(count).also { SecureRandom().nextBytes(it) }

    private fun encode(bytes: ByteArray): String = Base64.encodeToString(bytes, Base64.NO_WRAP)

    private fun decode(text: String): ByteArray = Base64.decode(text, Base64.NO_WRAP)

    companion object {
        const val DEFAULT_MAX_ATTEMPTS = 5
        private const val PREFS_FILE = "so.prelude.auth.lock"
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val TRANSFORMATION = "AES/GCM/NoPadding"
        private const val GCM_IV_BYTES = 12
        private const val PBKDF2_ITERATIONS = 50_000
    }
}
