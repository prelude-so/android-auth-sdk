package so.prelude.android.auth

import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test
import so.prelude.android.auth.http.HttpHeader

/**
 * End-to-end OTP login → logout over the mocked network. Drives
 * the public surface ([startOTPLogin], [checkOTP], [logout]) so
 * the proof-attachment policy, token persistence, DPoP signing
 * on `/login/finalize` and `/revoke`, and the store wipe all
 * participate in a single test. Small inter-stage pauses
 * approximate real-world inter-network latency; if any future
 * state machine quietly races, the delay widens the window
 * enough for the race to surface.
 *
 * `runBlocking` (real dispatchers) is intentional — the auth
 * stack hops through `Dispatchers.IO` inside its interceptor
 * chain and inflight-coordinator, and mixing virtual time with
 * a real dispatcher makes coroutine-interleaving assertions
 * fragile (see [LogoutTests] for the same reasoning).
 */
class OtpLoginLogoutE2ETest {
    // payload: {"sub":"user-1"}
    private val jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyLTEifQ.sig"

    @Test
    fun otpLogin_thenLogout_endToEnd() =
        runBlocking {
            val fixture = Fixture.make()
            installLoginAndLogoutSequence(fixture)

            // Stage 1: start OTP. Unauthenticated.
            fixture.client.startOTPLogin(
                StartOTPLoginOptions(identifier = OtpFixtures.emailIdentifier),
            )
            delayBetweenStages()
            val otpReq = fixture.http.requestsFor("/v1/session/otp").single()
            assertNull("/otp must not carry DPoP", otpReq.header(HttpHeader.DPOP))
            assertNull(otpReq.header(HttpHeader.AUTHORIZATION))

            // Stage 2: submit OTP code. `/otp/check` unauthenticated;
            // `/login/finalize` is DPoP-bound.
            val user = fixture.client.checkOTP("123456")
            delayBetweenStages()
            assertEquals("user-1", user.profile.userId)
            assertEquals(jwt, user.accessToken)

            val checkReq = fixture.http.requestsFor("/v1/session/otp/check").single()
            assertNull("/otp/check must not carry DPoP", checkReq.header(HttpHeader.DPOP))
            // Body roundtrips the challenge token from /otp/check.
            val finalizeReq = fixture.http.requestsFor("/v1/session/login/finalize").single()
            assertNotNull(
                "/login/finalize must be DPoP-signed",
                finalizeReq.header(HttpHeader.DPOP),
            )
            assertEquals(
                "challenge-abc",
                finalizeReq.bodyAsJson()["challenge_token"]!!.jsonPrimitive.content,
            )

            // Stores hydrated.
            assertEquals(
                "refresh-v1",
                fixture.refreshTokenStore.get(fixture.domain)!!.refreshToken,
            )
            assertEquals(
                jwt,
                fixture.accessTokenCache.getWithoutExpirationCheck(fixture.domain)!!.accessToken,
            )

            // Stage 3: logout. `/revoke` must be DPoP-signed and
            // carry the pre-rotation refresh token. Wipes stores.
            fixture.client.logout()
            val revokeReq = fixture.http.requestsFor("/v1/session/revoke").single()
            assertNotNull("/revoke must be DPoP-signed", revokeReq.header(HttpHeader.DPOP))
            assertEquals("refresh-v1", revokeReq.header(HttpHeader.REFRESH_TOKEN))

            assertWiped(fixture)
        }

    /**
     * Same flow under a slow network: each path is gated so we
     * can interleave inter-stage delays and prove the inflight
     * coordination logic doesn't deadlock or skip stages.
     */
    @Test
    fun otpLogin_thenLogout_endToEnd_withSlowNetwork() =
        runBlocking {
            val fixture = Fixture.make()
            installLoginAndLogoutSequence(fixture)
            for (path in slowPaths) fixture.http.installGate(path)

            coroutineScope {
                val stage1 =
                    async {
                        fixture.client.startOTPLogin(
                            StartOTPLoginOptions(identifier = OtpFixtures.emailIdentifier),
                        )
                    }
                delayBetweenStages()
                fixture.http.releaseGate("/v1/session/otp")
                stage1.await()

                val stage2 = async { fixture.client.checkOTP("123456") }
                delayBetweenStages()
                fixture.http.releaseGate("/v1/session/otp/check")
                delayBetweenStages()
                fixture.http.releaseGate("/v1/session/login/finalize")
                val user = stage2.await()
                assertEquals("user-1", user.profile.userId)

                val stage3 = async { fixture.client.logout() }
                delayBetweenStages()
                fixture.http.releaseGate("/v1/session/revoke")
                stage3.await()
            }

            assertEquals(1, fixture.http.requestCount("/v1/session/revoke"))
            assertWiped(fixture)
        }

    // MARK: - Helpers

    private val slowPaths =
        listOf(
            "/v1/session/otp",
            "/v1/session/otp/check",
            "/v1/session/login/finalize",
            "/v1/session/revoke",
        )

    private fun installLoginAndLogoutSequence(fixture: Fixture) {
        fixture.http.installAll(
            "/v1/session/otp" to StubHttpSession.Canned(statusCode = 204),
            "/v1/session/otp/check" to OtpFixtures.checkOkResponse(),
            "/v1/session/login/finalize" to
                OtpFixtures.finalizeOkResponse(
                    refreshToken = "refresh-v1",
                    refreshExpiresAt = "2099-01-01T00:00:00Z",
                ),
            "/v1/session/revoke" to StubHttpSession.Canned(statusCode = 204),
        )
    }

    private fun assertWiped(fixture: Fixture) {
        assertNull("DPoP key not wiped", fixture.keyStore.get(fixture.domain))
        assertNull("DPoP nonce not wiped", fixture.keyStore.getNonce(fixture.domain))
        assertNull("DPoP clock skew not wiped", fixture.keyStore.getClockSkewMs(fixture.domain))
        assertNull("Refresh token not wiped", fixture.refreshTokenStore.get(fixture.domain))
        assertNull(
            "Access token cache not wiped",
            fixture.accessTokenCache.getWithoutExpirationCheck(fixture.domain),
        )
    }

    /** 20 ms — long enough that any reordering bug would have
     *  already settled, short enough that the suite stays fast. */
    private suspend fun delayBetweenStages() = delay(20)
}
