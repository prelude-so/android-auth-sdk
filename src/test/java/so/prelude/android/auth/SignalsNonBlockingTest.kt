package so.prelude.android.auth

import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertFalse
import org.junit.Test

/**
 * Anti-fraud signals are best-effort: a failing
 * [so.prelude.android.auth.signals.PreludeSignalsDispatcher] must
 * not break login. The auth call proceeds and the wire body omits
 * `dispatch_id`.
 */
class SignalsNonBlockingTest {
    @Test
    fun startOTPLogin_dispatcherThrows_proceedsWithoutDispatchId() =
        runBlocking {
            val fixture =
                Fixture.make(
                    signalsDispatcher = { error("boom") },
                )
            fixture.http.install(
                "/v1/session/otp",
                StubHttpSession.Canned.json("{}", statusCode = 204),
            )

            // Must not throw — signals failures degrade gracefully.
            fixture.client.startOTPLogin(
                StartOTPLoginOptions(identifier = OtpFixtures.emailIdentifier),
            )

            val body =
                fixture.http
                    .requestsFor("/v1/session/otp")
                    .single()
                    .bodyAsJson()
            assertFalse(
                "dispatch_id must be omitted when the dispatcher fails",
                body.containsKey("dispatch_id"),
            )
        }
}
