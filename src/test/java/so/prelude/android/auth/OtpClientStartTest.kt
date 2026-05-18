package so.prelude.android.auth

import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Tests for `startOTPLogin` and `resendOTP`. The check + finalize
 * surface lives in [OtpClientCheckTest] / [OtpClientFinalizeTest];
 * unauthenticated-header guards live in [OtpClientAuthHeadersTest].
 *
 * Uses [runBlocking] (not `runTest`) because the production path
 * routes through `withContext(Dispatchers.IO)` inside the DPoP
 * interceptor; mixing virtual time with a real dispatcher makes
 * suspending state-mutation assertions fragile.
 */
class OtpClientStartTest {
    @Test
    fun startOTPLogin_postsIdentifier_andOmitsDispatchIdWhenUnconfigured() =
        runBlocking {
            val fixture = Fixture.make()
            fixture.http.install(
                "/v1/session/otp",
                StubHttpSession.Canned.json("{}", statusCode = 204),
            )

            fixture.client.startOTPLogin(
                StartOTPLoginOptions(identifier = OtpFixtures.emailIdentifier),
            )

            val req = fixture.http.requestsFor("/v1/session/otp").single()
            val body = req.bodyAsJson()
            assertEquals(
                "email_address",
                body["identifier"]!!.jsonObject["type"]!!.jsonPrimitive.content,
            )
            assertEquals(
                "alice@example.com",
                body["identifier"]!!.jsonObject["value"]!!.jsonPrimitive.content,
            )
            // No dispatcher configured → `dispatch_id` is omitted entirely
            // (encoder skips defaults) rather than sent as null.
            assertFalse("dispatch_id should be omitted", body.containsKey("dispatch_id"))
            // No login_config_id supplied → also omitted.
            assertFalse(
                "login_config_id should be omitted",
                body.containsKey("login_config_id"),
            )
            Unit
        }

    @Test
    fun startOTPLogin_attachesDispatchId_whenSignalsDispatcherIsConfigured() =
        runBlocking {
            var dispatched = 0
            val fixture =
                Fixture.make(
                    signalsDispatcher = {
                        dispatched += 1
                        "dispatch-xyz"
                    },
                )
            fixture.http.install(
                "/v1/session/otp",
                StubHttpSession.Canned.json("{}", statusCode = 204),
            )

            fixture.client.startOTPLogin(
                StartOTPLoginOptions(
                    identifier = OtpFixtures.emailIdentifier,
                    loginConfigId = "cfg-1",
                ),
            )

            assertEquals(1, dispatched)
            val body =
                fixture.http
                    .requestsFor("/v1/session/otp")
                    .single()
                    .bodyAsJson()
            assertEquals("dispatch-xyz", body["dispatch_id"]!!.jsonPrimitive.content)
            assertEquals("cfg-1", body["login_config_id"]!!.jsonPrimitive.content)
            Unit
        }

    @Test
    fun startOTPLogin_dispatcherFailure_wrapsAsSignalsDispatchFailed_andSkipsHttp() {
        val fixture = Fixture.make(signalsDispatcher = { error("boom") })
        fixture.http.install(
            "/v1/session/otp",
            StubHttpSession.Canned.json("{}", statusCode = 204),
        )

        val thrown =
            assertThrows(PreludeAuthError.SignalsDispatchFailed::class.java) {
                runBlocking {
                    fixture.client.startOTPLogin(
                        StartOTPLoginOptions(identifier = OtpFixtures.emailIdentifier),
                    )
                }
            }
        // Underlying dispatcher exception preserved so diagnostic UIs
        // can drill into the real failure.
        assertTrue(
            "expected IllegalStateException cause, got ${thrown.cause}",
            thrown.cause is IllegalStateException,
        )
        // HTTP must not have fired — silently shipping a login without
        // anti-fraud coverage would be the worst possible failure mode.
        assertTrue(fixture.http.requestsFor("/v1/session/otp").isEmpty())
    }

    @Test
    fun startOTPLogin_rateLimited_mapsToStructuredError() {
        val fixture = Fixture.make()
        fixture.http.install(
            "/v1/session/otp",
            OtpFixtures.apiError("rate_limited", "slow down", status = 429),
        )

        assertThrows(PreludeAuthError.RateLimited::class.java) {
            runBlocking {
                fixture.client.startOTPLogin(
                    StartOTPLoginOptions(identifier = OtpFixtures.emailIdentifier),
                )
            }
        }
    }

    @Test
    fun resendOTP_postsToRetryPath_withEmptyBody() =
        runBlocking {
            val fixture = Fixture.make()
            fixture.http.install(
                "/v1/session/otp/retry",
                StubHttpSession.Canned.json("{}", statusCode = 204),
            )

            fixture.client.resendOTP()

            val req = fixture.http.requestsFor("/v1/session/otp/retry").single()
            assertEquals("POST", req.method)
            // Default empty `{}` body is fine; servers that ignore it stay
            // untouched, decoders parse a no-op object.
            assertEquals("{}", req.bodyAsString())
            Unit
        }
}
