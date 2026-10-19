package so.prelude.android.auth.lock

import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.DefaultLifecycleObserver
import androidx.lifecycle.LifecycleOwner
import androidx.lifecycle.ProcessLifecycleOwner
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import so.prelude.android.auth.PreludeAuthClient
import so.prelude.android.auth.seal
import so.prelude.android.auth.unseal

/**
 * Seals a [PreludeAuthClient] after [thresholdMs] in the background
 * and lifts the seal once presence is proven. Calling [seal] on the
 * client directly bypasses [isLocked].
 *
 * [lockOnStart] seals in [start] so relaunching is not a way past
 * the lock; pass `false` when rebuilding mid-session.
 */
class PreludeIdleLock(
    private val client: PreludeAuthClient,
    thresholdMs: Long,
    private val unlockTitle: String = "Unlock to continue",
    private val lockOnStart: Boolean = true,
    maxAttempts: Int = AppLockStore.DEFAULT_MAX_ATTEMPTS,
) {
    private val store =
        AppLockStore(
            context = client.applicationContext ?: error("PreludeIdleLock needs a client built with a Context"),
            domain = client.domain,
            maxAttempts = maxAttempts,
        )
    private val policy = IdleLockPolicy(thresholdMs)
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)

    private val _isLocked = MutableStateFlow(false)
    private val _isEnabled = MutableStateFlow(store.hasPasscode)
    private val _isBiometricsEnabled = MutableStateFlow(store.isBiometricsEnabled)

    val isLocked: StateFlow<Boolean> = _isLocked.asStateFlow()

    /** Whether a passcode is set; show set-up while `false`. */
    val isEnabled: StateFlow<Boolean> = _isEnabled.asStateFlow()

    val isBiometricsEnabled: StateFlow<Boolean> = _isBiometricsEnabled.asStateFlow()

    val isBiometricsAvailable: Boolean
        get() = store.isBiometricsAvailable

    // MARK: - Enrollment

    /** Also drops the biometric shortcut, armed against the old one. */
    suspend fun setPasscode(passcode: String) {
        withContext(Dispatchers.IO) { store.setPasscode(passcode) }
        _isEnabled.value = true
        _isBiometricsEnabled.value = false
    }

    /** Requires a passcode, so there is always a way in. */
    suspend fun enableBiometrics() {
        withContext(Dispatchers.IO) { store.enableBiometrics() }
        _isBiometricsEnabled.value = true
    }

    suspend fun disableBiometrics() {
        withContext(Dispatchers.IO) { store.disableBiometrics() }
        _isBiometricsEnabled.value = false
    }

    /** Call on sign-out. */
    suspend fun disable() {
        withContext(Dispatchers.IO) { store.clear() }
        _isEnabled.value = false
        _isBiometricsEnabled.value = false
        _isLocked.value = false
    }

    // MARK: - Observing

    /** Start observing. Idempotent. */
    fun start() {
        scope.launch {
            if (observing) return@launch
            ProcessLifecycleOwner.get().lifecycle.addObserver(observer)
            observing = true
            if (lockOnStart && _isEnabled.value) lock()
        }
    }

    fun stop() {
        scope.launch {
            ProcessLifecycleOwner.get().lifecycle.removeObserver(observer)
            observing = false
        }
    }

    // MARK: - Locking

    /** Does nothing when signed out or with no passcode; there would be no way back in. */
    suspend fun lock() {
        if (!_isEnabled.value) return
        _isLocked.value = client.seal()
    }

    /** Throws `InvalidPasscode` while attempts remain and `LockedOut` once they are spent. */
    suspend fun unlock(passcode: String) {
        withContext(Dispatchers.IO) { store.verify(passcode) }
        lift()
    }

    /** Throws when no shortcut is armed or the match fails. */
    suspend fun unlockWithBiometrics(activity: FragmentActivity) {
        store.verifyBiometrics(activity, unlockTitle)
        lift()
    }

    /** Drop the lock without authenticating; for use after sign-out. */
    fun clear() {
        _isLocked.value = false
    }

    private suspend fun lift() {
        client.unseal()
        _isLocked.value = false
    }

    // MARK: - Lifecycle

    /** Touched on the main thread only, via [scope]. */
    private var observing = false

    // ProcessLifecycleOwner already debounces activity-to-activity
    // transitions and knows the state at subscription time.
    private val observer =
        object : DefaultLifecycleObserver {
            override fun onStart(owner: LifecycleOwner) = sealIfIdle()

            override fun onStop(owner: LifecycleOwner) = policy.markBackgrounded()
        }

    private fun sealIfIdle() {
        if (!policy.shouldSealOnForeground() || !_isEnabled.value) return
        // Published before the app draws; withdrawn if there was no session to seal.
        _isLocked.value = true
        scope.launch {
            if (!client.seal()) _isLocked.value = false
        }
    }
}
