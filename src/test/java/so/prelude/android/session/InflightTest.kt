package so.prelude.android.session

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.cancel
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.cancelChildren
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.supervisorScope
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.IOException
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger

/**
 * Unit tests for [Inflight].
 *
 * The class encodes the dedup contract for [PreludeSessionClient.refresh]:
 * concurrent callers share one round-trip, the slot clears synchronously
 * with completion, the precheck short-circuits a just-finished refresh.
 *
 * Refresh tokens are single-use, so a regression in any of these
 * properties is a credentials-burning bug — worth keeping the coverage
 * tight.
 *
 * Tests run under [runBlocking] (real dispatchers) rather than
 * [kotlinx.coroutines.test.runTest] because [Inflight] internally
 * dispatches to its own [Dispatchers.IO]-backed scope; mixing virtual
 * time with a real dispatcher makes assertions about coroutine
 * interleaving fragile.
 */
class InflightTest {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    @After
    fun tearDown() {
        scope.cancel()
    }

    private fun <T> mkInflight(): Inflight<T> = Inflight(scope)

    @Test
    fun runOrJoin_singleCaller_returnsBlockResult() = runBlocking {
        val inflight = mkInflight<String>()
        val result = inflight.runOrJoin(block = { "value" })
        assertEquals("value", result)
    }

    @Test
    fun runOrJoin_concurrentCallers_shareOneRound() = runBlocking {
        // The dedup contract: N callers in flight at once → block runs
        // once, all N receive the same value. A regression here would
        // cause the SDK to spend the single-use refresh token N times.
        val inflight = mkInflight<Int>()
        val invocations = AtomicInteger()
        val gate = CompletableDeferred<Unit>()
        val started = CompletableDeferred<Unit>()

        coroutineScope {
            val deferreds = (1..8).map {
                async {
                    inflight.runOrJoin(
                        block = {
                            invocations.incrementAndGet()
                            // Signal the test loop that the block is
                            // actually running — without this, "the
                            // task was started before we released the
                            // gate" is timing-sensitive.
                            started.complete(Unit)
                            gate.await()
                            42
                        },
                    )
                }
            }
            // Wait for the in-flight task to actually be running, so
            // the remaining 7 callers definitively race onto the same
            // slot rather than each starting their own.
            started.await()
            gate.complete(Unit)
            val results = deferreds.map { it.await() }
            assertEquals(List(8) { 42 }, results)
        }
        assertEquals("block ran exactly once across 8 callers", 1, invocations.get())
    }

    @Test
    fun precheck_shortCircuits_withoutStartingTask() = runBlocking {
        // If a value is already available when the mutex is acquired,
        // no task should start.
        val inflight = mkInflight<String>()
        var blockCalled = false
        val result = inflight.runOrJoin(
            precheck = { "cached" },
            block = {
                blockCalled = true
                "from-block"
            },
        )
        assertEquals("cached", result)
        assertEquals(false, blockCalled)
    }

    @Test
    fun runOrJoin_failureClearsSlotBeforeWaitersResume() = runBlocking {
        // The slot-clearing contract: when the block throws, the
        // in-flight slot must be cleared before any waiter resumes from
        // `await()`, so a subsequent caller starts a fresh task instead
        // of re-awaiting (and re-throwing) the settled failure.
        //
        // The race is probabilistic — under low contention the
        // cleanup almost always slips in before the next call arrives,
        // so we exercise the contract many times under contention to
        // flush out regressions.
        val iterations = 200
        val concurrent = 16
        var latchedIterations = 0

        repeat(iterations) {
            val inflight = mkInflight<String>()

            // Stage 1: a burst of concurrent failing callers. Drives
            // the cleanup hazard window the buggy implementation was
            // vulnerable to.
            coroutineScope {
                (1..concurrent).map {
                    async {
                        try {
                            inflight.runOrJoin(
                                block = { throw IOException("boom") },
                            )
                        } catch (_: IOException) {
                            // expected
                        }
                    }
                }.forEach { it.await() }
            }

            // Stage 2: a follow-up sequential caller MUST start a
            // fresh task. If the slot is still latched on Stage 1's
            // failed deferred, this caller's block won't run and the
            // counter stays at zero — the regression signature.
            val freshRan = AtomicBoolean(false)
            try {
                inflight.runOrJoin(
                    block = {
                        freshRan.set(true)
                        throw IOException("follow-up failure")
                    },
                )
            } catch (_: IOException) {
                // expected
            }
            if (!freshRan.get()) latchedIterations += 1
        }

        assertEquals(
            "follow-up caller's block must run every iteration — " +
                "latched in $latchedIterations of $iterations",
            0,
            latchedIterations,
        )
    }

    @Test
    fun runOrJoin_successClearsSlotBeforeWaitersResume() = runBlocking {
        // Symmetric to the failure-path test: even on success, the slot
        // must clear before waiters return so a subsequent caller can
        // start a fresh task. Important because PreludeSessionClient's
        // fast-path cache check can miss (e.g. the just-stored token's
        // expiry is `now`), and we don't want a follow-up call to join
        // a Deferred whose value is already-completed-and-stale.
        val inflight = mkInflight<Int>()
        val attempts = AtomicInteger()

        val first = inflight.runOrJoin(block = {
            attempts.incrementAndGet()
            1
        })
        val second = inflight.runOrJoin(block = {
            attempts.incrementAndGet()
            2
        })

        assertEquals(1, first)
        assertEquals(2, second)
        assertEquals(2, attempts.get())
    }

    @Test
    fun concurrentCallers_receiveSameValueInstance() = runBlocking {
        // Distinguishes "dedup works" from the wrong implementation
        // where every caller serializes through the mutex and runs in
        // turn. The block runs once and only once, and every caller's
        // result is the same instance (the value the single task
        // produced).
        val inflight = mkInflight<Any>()
        val gate = CompletableDeferred<Unit>()
        val produced = Any()
        val started = CompletableDeferred<Unit>()

        coroutineScope {
            val a = async {
                inflight.runOrJoin(block = {
                    started.complete(Unit)
                    gate.await()
                    produced
                })
            }
            started.await()
            val b = async { inflight.runOrJoin(block = { produced }) }
            gate.complete(Unit)
            assertSame("both callers received the same instance", a.await(), b.await())
        }
    }

    @Test
    fun precheckThrows_propagates_andLeavesSlotUntouched() = runBlocking {
        // A precheck that throws (e.g. a future cache backend that
        // surfaces read errors) must propagate the failure, but must
        // NOT poison the slot — the next call should be free to start
        // a fresh task. Pinning this contract now keeps the door open
        // for richer precheck logic later without re-litigating the
        // semantics.
        val inflight = mkInflight<String>()
        var blockRan = false

        val firstThrown = try {
            inflight.runOrJoin(
                precheck = { throw IllegalStateException("cache busted") },
                block = { "unreachable" },
            )
            false
        } catch (_: IllegalStateException) {
            true
        }
        assertTrue(firstThrown)

        val second = inflight.runOrJoin(
            block = {
                blockRan = true
                "ok"
            },
        )
        assertEquals("ok", second)
        assertTrue("block ran on the second call — slot was not latched", blockRan)
    }

    @Test
    fun runOrJoin_externalCancellation_doesNotLatchSlot() = runBlocking {
        // When the in-flight task is cancelled externally (e.g. a
        // future `close()` cancels the Inflight scope's children), the
        // coroutine becomes inactive, and any suspension inside the
        // cleanup `finally` — specifically the contended-acquire path
        // of `Mutex.withLock` — would throw `JobCancellationException`
        // before resetting `current`. That latches the cancelled
        // deferred in the slot, exactly the race this class exists to
        // prevent. The cleanup runs under `withContext(NonCancellable)`
        // so it can complete.
        //
        // Forcing the contended path is load-bearing: `Mutex.tryLock`
        // is non-suspending and never throws on cancellation, so an
        // uncontended cleanup would mask the bug. We hold the internal
        // mutex via reflection from outside, cancel the inflight
        // task's children, give the finally a head-start on
        // `lockSuspend`, then release.
        val privateScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
        try {
            val inflight = Inflight<String>(privateScope)
            val internalMutex = Inflight::class.java
                .getDeclaredField("mutex")
                .apply { isAccessible = true }
                .get(inflight) as kotlinx.coroutines.sync.Mutex

            val blockEntered = CompletableDeferred<Unit>()

            val firstCallerJob = async {
                try {
                    inflight.runOrJoin(block = {
                        blockEntered.complete(Unit)
                        // Block until cancelled.
                        kotlinx.coroutines.delay(60_000)
                        "never"
                    })
                } catch (_: CancellationException) {
                    // expected
                }
            }
            blockEntered.await()

            internalMutex.lock()
            try {
                // Cancel just the inflight scope's children (leaving
                // the scope itself alive so the follow-up call below
                // can start a fresh task). The cancelled task's
                // finally now races against our held mutex.
                privateScope.coroutineContext.cancelChildren()
                kotlinx.coroutines.delay(50)
            } finally {
                internalMutex.unlock()
            }
            firstCallerJob.await()

            // Slot must be clear: a follow-up caller starts a fresh
            // task and observes its block running. Without the
            // NonCancellable wrap, `current` would still point at the
            // cancelled deferred and this assertion would fail
            // intermittently (whenever the contended-acquire path was
            // hit).
            val freshRan = AtomicBoolean(false)
            inflight.runOrJoin(block = {
                freshRan.set(true)
                "fresh"
            })
            assertTrue(
                "follow-up block must run — slot was not latched on the cancelled deferred",
                freshRan.get(),
            )
        } finally {
            privateScope.cancel()
        }
    }

    @Test
    fun blockResultsDifferAcrossSequentialCalls() = runBlocking {
        // Pin that the slot really does clear: results from one call
        // do not leak into the next.
        val inflight = mkInflight<Int>()
        val r1 = inflight.runOrJoin(block = { 1 })
        val r2 = inflight.runOrJoin(block = { 2 })
        assertNotEquals(r1, r2)
    }

    // MARK: - joinIfRunning

    @Test
    fun joinIfRunning_withNoTask_returnsImmediately() = runBlocking {
        // Logout uses joinIfRunning to drain a possibly-in-flight
        // refresh before snapshotting. With no task in flight there
        // is nothing to await, and the call must return promptly
        // rather than block.
        val inflight = mkInflight<String>()
        inflight.joinIfRunning() // returns without throwing
    }

    @Test
    fun joinIfRunning_withInflightTask_awaitsCompletion() = runBlocking {
        // The drain semantic: callers must observe the task's side
        // effects before proceeding. Logout uses this to ensure a
        // mid-flight refresh has finished rotating the refresh token
        // before logout snapshots — `/revoke` signed with a spent
        // token would be rejected by the server.
        val inflight = mkInflight<Int>()
        val gate = CompletableDeferred<Unit>()
        val started = CompletableDeferred<Unit>()
        val sideEffectComplete = AtomicBoolean(false)

        coroutineScope {
            // Unnamed: structured concurrency means coroutineScope
            // waits for this child before returning, and the runner's
            // value isn't asserted on directly. Naming it would force
            // a `runner.await()` at the bottom whose `Int` return
            // type bubbles up through coroutineScope → runBlocking →
            // the @Test method, which JUnit 4 rejects (test methods
            // must return Unit).
            async {
                inflight.runOrJoin(block = {
                    started.complete(Unit)
                    gate.await()
                    sideEffectComplete.set(true)
                    99
                })
            }
            // Wait for the task to be running. Without this,
            // joinIfRunning could observe `current == null` and
            // return before the task latches into the slot.
            started.await()

            val joiner = async { inflight.joinIfRunning() }
            // Joiner is suspended on the task; the side effect
            // hasn't landed yet.
            assertEquals(false, sideEffectComplete.get())

            gate.complete(Unit)
            joiner.await()
            // After joinIfRunning returns the task's side effect
            // must be observable — that's the whole point.
            assertTrue(
                "joinIfRunning returned before the task's side effect landed",
                sideEffectComplete.get(),
            )
        }
    }

    @Test
    fun joinIfRunning_swallowsTaskFailure() = runBlocking {
        // Drained for side effects only: callers don't care whether
        // the in-flight task succeeded or failed, just that it has
        // settled. Logout couldn't reasonably propagate the
        // refresh's error anyway — its own `/revoke` round-trip is
        // about to run and surface its own outcome.
        val inflight = mkInflight<Int>()
        val gate = CompletableDeferred<Unit>()
        val started = CompletableDeferred<Unit>()

        coroutineScope {
            // Unnamed for the same reason as in the awaitsCompletion
            // test: a trailing `runner.await()` would surface an
            // `Any`-typed value (try-as-Int / catch-as-Unit) through
            // the test method's return type, which JUnit 4 rejects.
            async {
                try {
                    inflight.runOrJoin(block = {
                        started.complete(Unit)
                        gate.await()
                        throw IOException("refresh failed")
                    })
                } catch (_: IOException) {
                    // expected — runOrJoin surfaces the failure to
                    // the elected caller.
                }
            }
            started.await()

            // joinIfRunning must NOT propagate the IOException,
            // even though the underlying task throws.
            val joiner = async { inflight.joinIfRunning() }
            gate.complete(Unit)
            joiner.await() // must not throw
        }
    }

    @Test
    fun joinIfRunning_propagatesCallerCancellation() = runBlocking {
        // Cooperative cancellation must propagate so structured
        // concurrency holds. If `joinIfRunning` swallowed
        // [CancellationException] under a generic `catch (_: Throwable)`,
        // a parent that cancelled this caller would block forever
        // waiting for a child that quietly resumed past the await.
        //
        // The setup pins a never-completing task in flight, launches a
        // joiner, cancels it, and asserts the joiner's job ends up
        // cancelled. If `joinIfRunning` had eaten the
        // CancellationException, the joiner would have completed
        // normally instead — exactly the regression we're guarding.
        val inflight = mkInflight<Int>()
        val started = CompletableDeferred<Unit>()

        coroutineScope {
            // Long-running task; we never let it finish naturally.
            val runner = async {
                try {
                    inflight.runOrJoin(block = {
                        started.complete(Unit)
                        kotlinx.coroutines.delay(60_000)
                        99
                    })
                } catch (_: CancellationException) {
                    // expected once we tear the scope down
                }
            }
            started.await()

            val joiner = async { inflight.joinIfRunning() }
            // Give the joiner a tick to suspend on `task.await()`,
            // otherwise we'd cancel before it ever entered the try
            // block and the assertion would be vacuous.
            kotlinx.coroutines.yield()
            joiner.cancelAndJoin()
            assertTrue(
                "joinIfRunning must propagate caller cancellation",
                joiner.isCancelled,
            )

            runner.cancelAndJoin()
        }
    }

    // MARK: - replace

    /**
     * `replace` on an empty slot is just `runOrJoin` — install our
     * task and return its result. Nobody to drain. The simplest
     * possible cut-through path.
     */
    @Test
    fun replace_emptySlot_runsBlock_andReturnsResult() = runBlocking {
        val inflight = mkInflight<Int>()
        val result = inflight.replace { 42 }
        assertEquals(42, result)
    }

    /**
     * `replace` waits for an in-flight task to settle BEFORE running
     * its own block. The point is to avoid running concurrently with
     * the racing task (e.g. in step-up: a vanilla refresh would
     * mint an UNSCOPED token while a stepup refresh waits to install).
     */
    @Test
    fun replace_drainsInFlightTask_thenRunsBlock() = runBlocking {
        val inflight = mkInflight<String>()
        val firstStarted = CompletableDeferred<Unit>()
        val firstGate = CompletableDeferred<Unit>()
        val firstFinished = AtomicBoolean(false)
        val secondStartedBeforeFirstFinished = AtomicBoolean(false)

        coroutineScope {
            val first = async {
                inflight.runOrJoin {
                    firstStarted.complete(Unit)
                    firstGate.await()
                    firstFinished.set(true)
                    "first"
                }
            }
            firstStarted.await()

            val second = async {
                inflight.replace {
                    if (!firstFinished.get()) {
                        secondStartedBeforeFirstFinished.set(true)
                    }
                    "second"
                }
            }
            // Give `replace` a moment to enter the drain.
            kotlinx.coroutines.delay(20)

            firstGate.complete(Unit)

            assertEquals("first", first.await())
            assertEquals("second", second.await())
        }
        assertTrue(
            "replace's block must not start until the first task settles",
            !secondStartedBeforeFirstFinished.get(),
        )
    }

    /**
     * After `replace` installs its task, concurrent `runOrJoin`
     * callers join it instead of starting their own — the standard
     * slot-sharing semantics. In step-up terms: a `refresh()` racing
     * a stepup post-completion refresh piggybacks on the scoped
     * refresh and observes the same scoped result.
     */
    @Test
    fun replace_installedTask_isJoinedByConcurrentRunOrJoin() = runBlocking {
        val inflight = mkInflight<Int>()
        val replaceGate = CompletableDeferred<Unit>()
        val replaceStarted = CompletableDeferred<Unit>()
        val blockRunCount = AtomicInteger(0)

        coroutineScope {
            val replacing = async {
                inflight.replace {
                    blockRunCount.incrementAndGet()
                    replaceStarted.complete(Unit)
                    replaceGate.await()
                    99
                }
            }
            replaceStarted.await()

            // Three concurrent runOrJoin callers — all must join
            // the in-flight replace and observe `99`, not start a
            // fresh task that runs the block again.
            val joiners = (0 until 3).map {
                async { inflight.runOrJoin { error("must not start a new task") } }
            }
            kotlinx.coroutines.delay(20)
            replaceGate.complete(Unit)

            assertEquals(99, replacing.await())
            joiners.forEach { assertEquals(99, it.await()) }
        }
        assertEquals(
            "block must run exactly once across replace + 3 joiners",
            1,
            blockRunCount.get(),
        )
    }

    /**
     * When the in-flight task fails, `replace` swallows the failure
     * (it's not its task's outcome — only the slot occupancy
     * matters) and runs its own block. The drain is for ordering,
     * not for surfacing the prior task's result.
     */
    @Test
    fun replace_drainSwallowsInFlightFailure_thenRunsBlock() = runBlocking {
        val inflight = mkInflight<Int>()
        val gate = CompletableDeferred<Unit>()

        coroutineScope {
            val first = async {
                runCatching {
                    inflight.runOrJoin {
                        gate.await()
                        throw IOException("boom")
                    }
                }
            }
            // Wait until first is scheduled.
            kotlinx.coroutines.delay(20)
            val second = async { inflight.replace { 7 } }
            kotlinx.coroutines.delay(20)

            gate.complete(Unit)
            assertTrue(first.await().isFailure)
            assertEquals(7, second.await())
        }
    }

    @Test
    fun replace_propagatesCallerCancellation() = runBlocking {
        // Same rule the `joinIfRunning_propagatesCallerCancellation`
        // test pins: cooperative cancellation must propagate through
        // the drain loop so structured concurrency holds. If the
        // drain swallowed [CancellationException] the
        // `while (true)` would keep spinning and the caller's
        // completion exception would be `null` instead of cancelled.
        val inflight = mkInflight<Int>()
        val started = CompletableDeferred<Unit>()

        // `supervisorScope` so the cancelled child doesn't tear down
        // the test scope before we can read its completion cause.
        supervisorScope {
            // Pin a never-completing task in the slot; `replace`'s
            // first iteration will block in `existing.await()`.
            val runner = async {
                try {
                    inflight.runOrJoin {
                        started.complete(Unit)
                        kotlinx.coroutines.delay(60_000)
                        99
                    }
                } catch (_: CancellationException) {
                    // expected once we tear the scope down
                }
            }
            started.await()

            val replacer = async { inflight.replace { 42 } }
            // Give `replace` a tick to enter the drain loop and
            // suspend on `existing.await()`, otherwise we'd cancel
            // before it ever entered the try block and the assertion
            // would be vacuous.
            kotlinx.coroutines.yield()
            replacer.cancel()
            replacer.join()

            val cause = replacer.getCompletionExceptionOrNull()
            assertTrue(
                "replace must surface CancellationException to the caller, was $cause",
                cause is CancellationException,
            )

            runner.cancel()
            runner.join()
        }
    }
}
