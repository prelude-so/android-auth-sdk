package so.prelude.android.session

import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test
import so.prelude.android.session.http.HttpHeader

/**
 * `requestStepUp` request shape (scope, dispatch_id) and the
 * AutoRefresh 401-recovery path. Status branches + error mapping
 * live in [RequestStepUpTest].
 */
class RequestStepUpAuthTest {

    @Test
    fun requestStepUp_postsScope_andOmitsDispatchIdWhenUnconfigured() = runBlocking {
        val fixture = Fixture.make()
        fixture.prePopulateStepUp()
        fixture.http.install(
            "/v1/session/stepup/request",
            StepUpFixtures.stepUpResponse("continue", StepUpFixtures.verifyEmailToken),
        )

        fixture.client.requestStepUp(scope = "prld:pwd:write")

        val body = fixture.http.requestsFor("/v1/session/stepup/request")
            .single().bodyAsJson()
        assertEquals("prld:pwd:write", body["scope"]!!.jsonPrimitive.content)
        // No dispatcher configured → `dispatch_id` is omitted (encoder
        // skips defaults), not sent as null.
        assertFalse("dispatch_id should be omitted", body.containsKey("dispatch_id"))
        Unit
    }

    @Test
    fun requestStepUp_attachesDispatchId_whenSignalsDispatcherConfigured() = runBlocking {
        var dispatched = 0
        val fixture = Fixture.make(
            signalsDispatcher = {
                dispatched += 1
                "dispatch-stepup"
            },
        )
        fixture.prePopulateStepUp()
        fixture.http.install(
            "/v1/session/stepup/request",
            StepUpFixtures.stepUpResponse("continue", StepUpFixtures.verifyEmailToken),
        )

        fixture.client.requestStepUp(scope = "prld:pwd:write")

        // One dispatch for /stepup/request. /otp delivery is now
        // caller-driven via `sendStepUpOTP` (see SendStepUpOTPTest).
        assertEquals(1, dispatched)
        val stepUpBody = fixture.http.requestsFor("/v1/session/stepup/request")
            .single().bodyAsJson()
        assertEquals("dispatch-stepup", stepUpBody["dispatch_id"]!!.jsonPrimitive.content)
    }

    @Test
    fun requestStepUp_401_triggersRefresh_andRetriesWithFreshBearer() = runBlocking {
        // /stepup/request is on the protected surface — a 401 driven by
        // a stale bearer must be silently recovered: AutoRefresh
        // invalidates the cache, refreshes, then replays the request
        // with the rotated bearer.
        val rotatedAccessToken =
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyLTEiLCJzaWQiOiJzZXNzLTIifQ.sig"
        val rotatedRefreshOk = StubHttpSession.Canned.json(
            """{"access_token":"$rotatedAccessToken","expires_at":${StepUpFixtures.BASE_EPOCH + 3_600}}""",
            headers = mapOf(
                HttpHeader.REFRESH_TOKEN to "refresh-v2",
                HttpHeader.REFRESH_TOKEN_EXPIRES_AT to "2099-01-01T00:00:00Z",
            ),
        )

        val fixture = Fixture.make()
        fixture.prePopulateStepUp()
        fixture.http.installAll(
            "/v1/session/stepup/request" to StepUpFixtures.apiError("unauthorized", status = 401),
            "/v1/session/refresh" to rotatedRefreshOk,
        )
        // Gate /refresh so we can swap /stepup/request to its success
        // response while refresh suspends — the AutoRefresh retry runs
        // after refresh returns and picks up the swap.
        fixture.http.installGate("/v1/session/refresh")

        coroutineScope {
            val deferred = async { fixture.client.requestStepUp("prld:pwd:write") }
            StepUpFixtures.waitUntil { fixture.http.requestCount("/v1/session/refresh") >= 1 }
            fixture.http.install(
                "/v1/session/stepup/request",
                StepUpFixtures.stepUpResponse("continue", StepUpFixtures.verifyEmailToken),
            )
            fixture.http.releaseGate("/v1/session/refresh")

            val challenge = deferred.await()
            assertEquals(PreludeStepUpStatus.CONTINUE, challenge.status)
        }

        // Two /stepup/request hops: original 401 + retry.
        val stepupReqs = fixture.http.requestsFor("/v1/session/stepup/request")
        assertEquals(2, stepupReqs.size)
        // Original carried the stale bearer; retry the rotated one.
        assertEquals(
            "Bearer ${StepUpFixtures.SCOPED_ACCESS_TOKEN}",
            stepupReqs[0].header(HttpHeader.AUTHORIZATION),
        )
        assertEquals(
            "Bearer $rotatedAccessToken",
            stepupReqs[1].header(HttpHeader.AUTHORIZATION),
        )
        assertEquals(1, fixture.http.requestCount("/v1/session/refresh"))
    }

    @Test
    fun concurrentProtectedCalls_each401_shareOneRefresh_thenRetryWithRotatedBearer() = runBlocking {
        // Two protected calls hit 401 in parallel. Refresh is single-
        // flight: both AutoRefresh paths must coalesce onto one
        // /refresh round-trip, and both retries must ship the rotated
        // bearer. The single-use refresh token can't survive two
        // independent rotations.
        val rotatedAccessToken =
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyLTEiLCJzaWQiOiJzZXNzLTIifQ.sig"
        val rotatedRefreshOk = StubHttpSession.Canned.json(
            """{"access_token":"$rotatedAccessToken","expires_at":${StepUpFixtures.BASE_EPOCH + 3_600}}""",
            headers = mapOf(
                HttpHeader.REFRESH_TOKEN to "refresh-v2",
                HttpHeader.REFRESH_TOKEN_EXPIRES_AT to "2099-01-01T00:00:00Z",
            ),
        )

        val fixture = Fixture.make()
        fixture.prePopulateStepUp()
        fixture.http.installAll(
            "/v1/session/stepup/request" to StepUpFixtures.apiError("unauthorized", status = 401),
            "/v1/session/refresh" to rotatedRefreshOk,
        )
        // Gate /refresh so the second racer arrives in the Inflight
        // slot before the first releases — without this the first
        // can complete its retry before the second's intercept even
        // sees its 401, and the dedup window never opens.
        fixture.http.installGate("/v1/session/refresh")

        coroutineScope {
            val a = async { fixture.client.requestStepUp("prld:pwd:write") }
            val b = async { fixture.client.requestStepUp("prld:pwd:write") }
            // Wait for the first refresh to be in flight at the gate;
            // the second racer attaches to the same Inflight slot.
            StepUpFixtures.waitUntil { fixture.http.requestCount("/v1/session/refresh") >= 1 }
            // Swap /stepup/request to a success response so each
            // retry observes a 2xx after refresh returns.
            fixture.http.install(
                "/v1/session/stepup/request",
                StepUpFixtures.stepUpResponse("continue", StepUpFixtures.verifyEmailToken),
            )
            fixture.http.releaseGate("/v1/session/refresh")
            a.await()
            b.await()
        }

        // Single-flight: 2 callers, 1 refresh round-trip.
        assertEquals(1, fixture.http.requestCount("/v1/session/refresh"))
        // Each caller fired the original (401) + the retry.
        val stepupReqs = fixture.http.requestsFor("/v1/session/stepup/request")
        assertEquals("2 callers × (original + retry)", 4, stepupReqs.size)
        // Both retries carry the rotated bearer — no caller is left
        // replaying the stale token.
        val retryAuths = stepupReqs.drop(2).map { it.header(HttpHeader.AUTHORIZATION) }
        assertEquals(
            listOf("Bearer $rotatedAccessToken", "Bearer $rotatedAccessToken"),
            retryAuths,
        )
    }
}
