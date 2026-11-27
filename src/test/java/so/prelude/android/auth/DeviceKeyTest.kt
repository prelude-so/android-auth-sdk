package so.prelude.android.auth

import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import okhttp3.Protocol
import okhttp3.Request
import okhttp3.Response
import okhttp3.ResponseBody.Companion.toResponseBody
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Test
import so.prelude.android.auth.dpop.FakeDPoPKeyStore
import so.prelude.android.auth.dpop.FakeDeviceKeyStore
import so.prelude.android.auth.dpop.jwkThumbprint
import so.prelude.android.auth.dpop.sha256Base64Url
import so.prelude.android.auth.dpop.string
import so.prelude.android.auth.dpop.verifyDeviceProof
import so.prelude.android.auth.http.DeviceProofInterceptor
import so.prelude.android.auth.http.HttpHeader

class DeviceKeyTest {
    @Test
    fun finalize_sendsDeviceProofBoundToChallengeAndDPoPKey() =
        runBlocking {
            val fixture = Fixture.make(deviceKeyStore = FakeDeviceKeyStore())
            installLogin(fixture)

            fixture.client.checkOTP("123456")

            val request = fixture.http.requestsFor("/v1/session/login/finalize").single()
            val (header, claims) = verifyDeviceProof(request.header(HttpHeader.DEVICE_PROOF)!!)
            assertEquals("device-proof+jwt", header.string("typ"))
            assertEquals("ES256", header.string("alg"))
            assertEquals("POST", claims.string("htm"))
            assertEquals("https://${fixture.domain}/v1/session/login/finalize", claims.string("htu"))
            assertEquals(sha256Base64Url("challenge-abc"), claims.string("cth"))
            assertEquals("tee", claims.string("key_storage"))
            val dpopKey = fixture.keyStore.get(fixture.domain)!!
            assertEquals(jwkThumbprint(dpopKey.exportPublicJwk()), claims.string("jkt"))
            Unit
        }

    @Test
    fun deviceKey_survivesLogout() =
        runBlocking {
            val fixture = Fixture.make(deviceKeyStore = FakeDeviceKeyStore())
            installLogin(fixture)
            fixture.http.install("/v1/session/revoke", StubHttpSession.Canned(statusCode = 204))

            fixture.client.checkOTP("123456")
            fixture.client.logout()
            fixture.client.checkOTP("123456")

            val keys = fixture.http.requestsFor("/v1/session/login/finalize").map { deviceKeyThumbprint(it) }
            assertEquals(2, keys.size)
            assertEquals("device key must survive logout", keys[0], keys[1])
        }

    @Test
    fun resetDeviceKey_givesANewKey() =
        runBlocking {
            val fixture = Fixture.make(deviceKeyStore = FakeDeviceKeyStore())
            installLogin(fixture)

            fixture.client.checkOTP("123456")
            fixture.client.resetDeviceKey()
            fixture.client.checkOTP("123456")

            val keys = fixture.http.requestsFor("/v1/session/login/finalize").map { deviceKeyThumbprint(it) }
            assertNotEquals(keys[0], keys[1])
        }

    @Test
    fun finalize_keystoreError_sendsNoProof_andCreatesNoKey() =
        runBlocking {
            val store = FakeDeviceKeyStore(failRead = true)
            val fixture = Fixture.make(deviceKeyStore = store)
            installLogin(fixture)

            fixture.client.checkOTP("123456")

            val request = fixture.http.requestsFor("/v1/session/login/finalize").single()
            assertNull(request.header(HttpHeader.DEVICE_PROOF))
            assertEquals(0, store.createCount)
        }

    @Test
    fun stepUpOTP_sendsDeviceProofBoundToTheChallenge() =
        runBlocking {
            val fixture = Fixture.make(deviceKeyStore = FakeDeviceKeyStore())
            fixture.prePopulateStepUp()
            val challenge = StepUpFixtures.verifyEmailToken
            fixture.http.installAll(
                "/v1/session/stepup/request" to StepUpFixtures.stepUpResponse("continue", challenge),
                "/v1/session/otp/check" to StubHttpSession.Canned.json("""{"challenge_token":"$challenge"}"""),
            )

            val started = fixture.client.requestStepUp("prld:pwd:write")
            runCatching { fixture.client.submitStepUpOTP(started, code = "123456") }

            val request = fixture.http.requestsFor("/v1/session/otp/check").last()
            val (_, claims) = verifyDeviceProof(request.header(HttpHeader.DEVICE_PROOF)!!)
            assertEquals(sha256Base64Url(challenge), claims.string("cth"))
            assertEquals("https://${fixture.domain}/v1/session/otp/check", claims.string("htu"))
            assertEquals(jwkThumbprint(fixture.keyStore.get(fixture.domain)!!.exportPublicJwk()), claims.string("jkt"))
            Unit
        }

    @Test
    fun noDeviceKeyStore_sendsNoProof() =
        runBlocking {
            val fixture = Fixture.make()
            installLogin(fixture)

            fixture.client.checkOTP("123456")

            assertNull(
                fixture.http
                    .requestsFor("/v1/session/login/finalize")
                    .single()
                    .header(HttpHeader.DEVICE_PROOF),
            )
        }

    @Test
    fun signIn_invalidDeviceProof_retriesWithoutProof() =
        runBlocking {
            val sent = mutableListOf<Request>()
            val interceptor = interceptor(DeviceProofInterceptor.Mode.Login)

            val response =
                interceptor.intercept(finalizeRequest()) { request ->
                    sent += request
                    if (sent.size == 1) response(request, 400, """{"code":"invalid_device_proof"}""") else response(request, 200, "{}")
                }

            assertEquals(200, response.code)
            assertEquals(2, sent.size)
            assertNotNull(sent[0].header(HttpHeader.DEVICE_PROOF))
            assertNull(sent[1].header(HttpHeader.DEVICE_PROOF))
        }

    @Test
    fun stepUp_invalidDeviceProof_doesNotRetry() =
        runBlocking {
            var calls = 0
            val response =
                interceptor(DeviceProofInterceptor.Mode.StepUp).intercept(finalizeRequest()) { request ->
                    calls++
                    response(request, 400, """{"code":"invalid_device_proof"}""")
                }

            assertEquals(400, response.code)
            assertEquals(1, calls)
        }

    @Test
    fun stepUp_keystoreError_doesNotSendTheRequest() =
        runBlocking {
            val dpopKeys = FakeDPoPKeyStore().apply { getOrCreate("auth.example") }
            val interceptor =
                DeviceProofInterceptor(
                    mode = DeviceProofInterceptor.Mode.StepUp,
                    domain = "auth.example",
                    keyStore = dpopKeys,
                    deviceKeyStore = FakeDeviceKeyStore(failRead = true),
                    challengeToken = "challenge-abc",
                    hostOverride = null,
                )
            var calls = 0

            assertThrows(PreludeAuthError.CryptoFailure::class.java) {
                runBlocking {
                    interceptor.intercept(finalizeRequest()) { request ->
                        calls++
                        response(request, 200, "{}")
                    }
                }
            }
            assertEquals(0, calls)
        }

    private fun installLogin(fixture: Fixture) {
        fixture.http.installAll(
            "/v1/session/otp/check" to OtpFixtures.checkOkResponse(),
            "/v1/session/login/finalize" to OtpFixtures.finalizeOkResponse(),
        )
    }

    private fun interceptor(mode: DeviceProofInterceptor.Mode) =
        DeviceProofInterceptor(
            mode = mode,
            domain = "auth.example",
            keyStore = FakeDPoPKeyStore(),
            deviceKeyStore = FakeDeviceKeyStore(),
            challengeToken = "challenge-abc",
            hostOverride = null,
        )

    private fun finalizeRequest() = Request.Builder().url("https://auth.example/v1/session/login/finalize").build()

    private fun response(
        request: Request,
        code: Int,
        body: String,
    ) = Response
        .Builder()
        .request(request)
        .protocol(Protocol.HTTP_1_1)
        .code(code)
        .message("")
        .body(body.toResponseBody())
        .build()

    private fun deviceKeyThumbprint(request: Request): String {
        val (header, _) = verifyDeviceProof(request.header(HttpHeader.DEVICE_PROOF)!!)
        val jwk = header["jwk"]!!.jsonObject.mapValues { it.value.jsonPrimitive.content }
        return jwkThumbprint(jwk)
    }
}
