package so.prelude.android.auth.lock

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class IdleLockPolicyTest {
    private class Clocks {
        var wall = 1_000_000_000L
        var steady = 500_000L
    }

    private fun makePolicy(
        clocks: Clocks,
        thresholdMs: Long = 60_000,
    ) = IdleLockPolicy(
        thresholdMs = thresholdMs,
        wallClock = { clocks.wall },
        steadyClock = { clocks.steady },
    )

    @Test
    fun withoutBackgrounding_doesNotSeal() {
        val policy = makePolicy(Clocks())
        assertFalse(policy.shouldSealOnForeground())
    }

    @Test
    fun shortTrip_doesNotSeal() {
        val clocks = Clocks()
        val policy = makePolicy(clocks)
        policy.markBackgrounded()
        clocks.wall += 10_000
        clocks.steady += 10_000
        assertFalse(policy.shouldSealOnForeground())
    }

    @Test
    fun pastThreshold_seals() {
        val clocks = Clocks()
        val policy = makePolicy(clocks)
        policy.markBackgrounded()
        clocks.wall += 61_000
        clocks.steady += 61_000
        assertTrue(policy.shouldSealOnForeground())
    }

    @Test
    fun frozenWallClock_stillSeals() {
        val clocks = Clocks()
        val policy = makePolicy(clocks)
        policy.markBackgrounded()
        clocks.steady += 61_000
        assertTrue(policy.shouldSealOnForeground())
    }

    @Test
    fun wallClockMovedBackwards_seals() {
        val clocks = Clocks()
        val policy = makePolicy(clocks)
        policy.markBackgrounded()
        clocks.wall -= 1
        clocks.steady += 10
        assertTrue(policy.shouldSealOnForeground())
    }

    @Test
    fun markIsConsumed() {
        val clocks = Clocks()
        val policy = makePolicy(clocks)
        policy.markBackgrounded()
        clocks.wall += 61_000
        clocks.steady += 61_000
        assertTrue(policy.shouldSealOnForeground())
        assertFalse(policy.shouldSealOnForeground())
    }
}
