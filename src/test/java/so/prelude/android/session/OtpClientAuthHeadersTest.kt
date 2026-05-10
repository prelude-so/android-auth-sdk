package so.prelude.android.session

import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test
import so.prelude.android.session.http.HttpHeader

/**
 * Pin which OTP-flow hops carry DPoP / bearer headers.
 *
 *   /otp           — unauthenticated. Neither.
 *   /otp/retry     — unauthenticated. Neither.
 *   /otp/check     — unauthenticated. Neither. The OTP code in the
 *                    body is the credential; no session key exists
 *                    yet to bind a DPoP proof to.
 *   /login/finalize — DPoP-signed (binds issued tokens to device key).
 *                    No bearer — there's nothing to refresh until this
 *                    hop returns one.
 */
class OtpClientAuthHeadersTest {

    @Test
    fun startOTPLogin_isUnauthenticated_attachesNeitherDPoPNorBearer() = runBlocking {
        val fixture = Fixture.make()
        fixture.http.install(
            "/v1/session/otp",
            StubHttpSession.Canned.json("{}", statusCode = 204),
        )

        fixture.client.startOTPLogin(
            StartOTPLoginOptions(identifier = OtpFixtures.emailIdentifier),
        )

        val req = fixture.http.requestsFor("/v1/session/otp").single()
        assertNull(req.header(HttpHeader.DPOP))
        assertNull(req.header(HttpHeader.AUTHORIZATION))
        Unit
    }

    @Test
    fun resendOTP_isUnauthenticated_attachesNeitherDPoPNorBearer() = runBlocking {
        val fixture = Fixture.make()
        fixture.http.install(
            "/v1/session/otp/retry",
            StubHttpSession.Canned.json("{}", statusCode = 204),
        )

        fixture.client.resendOTP()

        val req = fixture.http.requestsFor("/v1/session/otp/retry").single()
        assertNull(req.header(HttpHeader.DPOP))
        assertNull(req.header(HttpHeader.AUTHORIZATION))
        Unit
    }

    @Test
    fun checkOTP_otpCheckIsUnauthenticated_attachesNeitherDPoPNorBearer() = runBlocking {
        val fixture = Fixture.make()
        fixture.http.installAll(
            "/v1/session/otp/check" to OtpFixtures.checkOkResponse(),
            "/v1/session/login/finalize" to OtpFixtures.finalizeOkResponse(),
        )

        fixture.client.checkOTP("123456")

        val checkReq = fixture.http.requestsFor("/v1/session/otp/check").single()
        assertNull(checkReq.header(HttpHeader.DPOP))
        assertNull(checkReq.header(HttpHeader.AUTHORIZATION))
        Unit
    }

    /**
     * `buildSessionRequest("…")` POSTs ship a JSON body (default `{}`)
     * and must carry `Content-Type: application/json`. The compliancy
     * GET pins the inverse — a bodyless GET must NOT carry one — so
     * symmetric coverage here keeps the contract tight on both sides.
     * Pinned on /otp because it's the first POST in the flow that
     * everyone touches.
     */
    @Test
    fun startOTPLogin_postRequestCarriesJsonContentType() = runBlocking {
        val fixture = Fixture.make()
        fixture.http.install(
            "/v1/session/otp",
            StubHttpSession.Canned.json("{}", statusCode = 204),
        )

        fixture.client.startOTPLogin(
            StartOTPLoginOptions(identifier = OtpFixtures.emailIdentifier),
        )

        val req = fixture.http.requestsFor("/v1/session/otp").single()
        assertEquals("application/json", req.header(HttpHeader.CONTENT_TYPE))
    }

    @Test
    fun checkOTP_finalizeLoginIsDPoPSigned_andAttachesNoBearer() = runBlocking {
        val fixture = Fixture.make()
        fixture.http.installAll(
            "/v1/session/otp/check" to OtpFixtures.checkOkResponse(),
            "/v1/session/login/finalize" to OtpFixtures.finalizeOkResponse(),
        )

        fixture.client.checkOTP("123456")

        val finalizeReq = fixture.http.requestsFor("/v1/session/login/finalize").single()
        assertNotNull(finalizeReq.header(HttpHeader.DPOP))
        assertNull(finalizeReq.header(HttpHeader.AUTHORIZATION))
        Unit
    }
}
