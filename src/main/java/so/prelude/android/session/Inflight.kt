package so.prelude.android.session

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext

/**
 * Coalesces concurrent callers onto a single in-flight task — the
 * "single-flight" pattern.
 *
 * Concurrent callers of [runOrJoin] share one [Deferred]; the
 * in-flight slot is cleared inside the task's `finally` so by the time
 * any waiter resumes from `task.await()` the slot is already null. A
 * subsequent caller therefore never re-awaits a settled task, which
 * matters most on the failure path: re-awaiting would propagate the
 * same stale error to every concurrent caller.
 *
 * Refresh tokens are single-use, so two concurrent 401 retries that
 * each spent the refresh token would trigger a server-side revocation
 * cascade. The dedup ensures one round-trip per logical refresh,
 * regardless of how many callers race.
 *
 * @param scope owns the unstructured task. Decoupling from the
 *   triggering caller's coroutine means a cancelled caller doesn't
 *   take the in-flight task down — concurrent waiters still receive
 *   the result and any persistence side-effects still land.
 *   `SupervisorJob` so a thrown task doesn't poison the scope.
 *   `Dispatchers.IO` because the refresh path performs blocking
 *   SharedPreferences reads/writes around the network call.
 */
internal class Inflight<T>(
    private val scope: CoroutineScope =
        CoroutineScope(SupervisorJob() + Dispatchers.IO),
) {
    private val mutex = Mutex()
    private var current: Deferred<T>? = null

    /**
     * Run [block] if no task is in flight, otherwise join the
     * existing one. Both paths await the same [Deferred] and so
     * surface the same result or exception.
     *
     * [precheck] runs under the mutex before the dedup decision, so a
     * value that arrived while the caller was queued for the lock
     * (e.g. another caller just finished and populated a shared cache)
     * short-circuits without spinning up a redundant task. Returning
     * `null` falls through to the dedup path.
     */
    suspend fun runOrJoin(
        precheck: () -> T? = { null },
        block: suspend () -> T,
    ): T {
        val task = mutex.withLock {
            precheck()?.let { return it }
            current ?: start(block)
        }
        return task.await()
    }

    /**
     * Await the in-flight task if one exists, otherwise return
     * immediately. Never starts a new task and swallows any failure
     * the in-flight task surfaces — callers use this purely to
     * rendezvous on the side-effects of a task that's already
     * running, not to learn its outcome.
     *
     * Used by `logout()` to wait for an in-flight refresh before
     * snapshotting the refresh token: if `/refresh` is mid-rotation,
     * the snapshot must read the post-rotation value or `/revoke`
     * will sign itself with a token the server has already retired.
     * A failed in-flight refresh is irrelevant — `logout()` proceeds
     * with whatever the stores hold.
     */
    suspend fun joinIfRunning() {
        val task = mutex.withLock { current }
        if (task != null) {
            try {
                task.await()
            } catch (e: CancellationException) {
                // Cooperative cancellation must propagate so structured
                // concurrency holds. Swallowing here would let a
                // cancelled caller carry on past `joinIfRunning` and
                // silently strand its parent.
                throw e
            } catch (_: Throwable) {
                // Drained for side-effects only; callers don't care
                // whether the in-flight task succeeded or failed.
            }
        }
    }

    /**
     * Drain any in-flight task, then install [block] as the new
     * in-flight task and return its result. Concurrent callers of
     * [runOrJoin] arriving while [block] runs join it instead of
     * starting their own — the standard slot-sharing semantics.
     *
     * Used by the step-up post-completion refresh: a vanilla
     * `refresh()` racing in the slot would mint an *unscoped*
     * access token, so step-up can't piggyback on its dedup. We
     * wait for the racing refresh to settle, then install our
     * scoped refresh in the slot so any further [runOrJoin]
     * callers (including a 401-driven [AutoRefreshInterceptor])
     * piggyback on the scoped result.
     *
     * Loops until our installation wins — between observing the
     * slot empty and acquiring the lock to install, a sibling can
     * race in and start a new task. The worst-case is N drains for
     * N racing siblings, which in practice means at most one
     * (concurrent refreshes already coalesce via [runOrJoin]).
     */
    suspend fun replace(block: suspend () -> T): T {
        while (true) {
            val existing = mutex.withLock { current }
            if (existing != null) {
                try {
                    existing.await()
                } catch (e: CancellationException) {
                    // Cooperative cancellation must propagate so
                    // structured concurrency holds — same rule as
                    // `joinIfRunning`. Swallowing here would let a
                    // cancelled caller carry on past `replace` and
                    // silently strand its parent (e.g. the
                    // post-step-up refresh would keep spinning even
                    // after the surrounding flow was cancelled).
                    throw e
                } catch (_: Throwable) {
                    // Drained for side-effects only — callers don't
                    // care whether the racing task succeeded or failed.
                }
                continue
            }
            // Slot was observed empty; try to install atomically.
            // If a racing caller filled it between the observe and
            // the lock acquire, drop back into the drain loop.
            val installed = mutex.withLock {
                if (current == null) start(block) else null
            }
            if (installed != null) return installed.await()
        }
    }

    /**
     * Caller MUST hold [mutex]. The slot is cleared inside the task's
     * `finally`, before the [Deferred] transitions to completed — what
     * makes [runOrJoin] safe against latching a stale failure in the
     * slot.
     */
    private fun start(block: suspend () -> T): Deferred<T> {
        lateinit var task: Deferred<T>
        task = scope.async {
            try {
                block()
            } finally {
                // [NonCancellable] is load-bearing: when the block raises
                // [CancellationException] the coroutine is already in a
                // cancelled state, and any suspension inside
                // [Mutex.withLock] — at minimum the contended-acquire
                // path — would re-throw before clearing [current], which
                // would latch the cancelled deferred in the slot.
                //
                // `===` is defensive: the only writer to [current] is
                // [start], which only runs while holding [mutex] AND
                // [current] is null, so a clobber should be impossible.
                // The guard costs nothing and documents the invariant.
                withContext(NonCancellable) {
                    mutex.withLock {
                        if (current === task) current = null
                    }
                }
            }
        }
        current = task
        return task
    }
}
