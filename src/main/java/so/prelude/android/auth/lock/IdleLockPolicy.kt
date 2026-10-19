package so.prelude.android.auth.lock

import android.os.SystemClock

/**
 * Decides whether time in the background has earned a seal.
 * Either clock crossing [thresholdMs] seals, and so does the wall
 * clock running backwards.
 */
internal class IdleLockPolicy(
    private val thresholdMs: Long,
    private val wallClock: () -> Long = System::currentTimeMillis,
    private val steadyClock: () -> Long = SystemClock::elapsedRealtime,
) {
    private var backgroundedAt: Pair<Long, Long>? = null

    fun markBackgrounded() {
        backgroundedAt = wallClock() to steadyClock()
    }

    /**
     * Consumes the mark, so a foreground transition with no preceding
     * background one never seals.
     */
    fun shouldSealOnForeground(): Boolean {
        val (wallStart, steadyStart) = backgroundedAt ?: return false
        backgroundedAt = null

        val wall = wallClock() - wallStart
        val steady = steadyClock() - steadyStart
        return wall < 0 || wall >= thresholdMs || steady >= thresholdMs
    }
}
