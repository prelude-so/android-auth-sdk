package so.prelude.android.auth.http

import okhttp3.Cookie
import okhttp3.HttpUrl.Companion.toHttpUrl
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Cookie-jar contracts the OTP login flow relies on:
 *
 *     POST /v1/session/otp        → server sets `__Host-did_<appId>`
 *                                   and `__Host-verification-login_<appId>`
 *     POST /v1/session/otp/check  → request must replay both
 *     POST /v1/session/login/finalize
 *
 * The auth client never touches these cookies — OkHttp's
 * [okhttp3.CookieJar] does, and [InMemoryCookieJar] is ours.
 */
class InMemoryCookieJarTest {
    private val origin = "https://otp-test.example/v1/session/otp".toHttpUrl()
    private val checkUrl = "https://otp-test.example/v1/session/otp/check".toHttpUrl()

    // ----- did (device id) cookie ----------------------------------

    // Hard-coded literal so a rename on either side fails here.
    private val didName = "__Host-did_app-1"

    private fun didCookie(
        value: String = "device-uuid-abc",
        host: String = origin.host,
        // 1y matches the backend's `DeviceID(...)` expiry.
        expiresAt: Long = System.currentTimeMillis() + 365L * 24 * 3600 * 1000,
    ): Cookie =
        Cookie
            .Builder()
            .name(didName)
            .value(value)
            .hostOnlyDomain(host)
            .path("/")
            .secure()
            .httpOnly()
            .expiresAt(expiresAt)
            .build()

    @Test
    fun didCookie_isReplayedOnNextHop() {
        val jar = InMemoryCookieJar()
        jar.saveFromResponse(origin, listOf(didCookie()))

        val replayed = jar.loadForRequest(checkUrl)
        assertEquals(
            listOf(didName to "device-uuid-abc"),
            replayed.map { it.name to it.value },
        )
    }

    @Test
    fun didCookie_doesNotLeakAcrossHosts() {
        val jar = InMemoryCookieJar()
        jar.saveFromResponse(origin, listOf(didCookie()))

        val foreign = "https://other-tenant.example/v1/session/otp/check".toHttpUrl()
        assertTrue(jar.loadForRequest(foreign).isEmpty())
    }

    @Test
    fun didCookie_reissued_replacesOldValue() {
        // DeviceID middleware re-emits on every session route; a rotation
        // must replace, not append.
        val jar = InMemoryCookieJar()
        jar.saveFromResponse(origin, listOf(didCookie(value = "old")))
        jar.saveFromResponse(origin, listOf(didCookie(value = "new")))

        val replayed = jar.loadForRequest(checkUrl)
        assertEquals(listOf(didName to "new"), replayed.map { it.name to it.value })
    }

    @Test
    fun didCookie_expired_isNotPersisted() {
        val jar = InMemoryCookieJar()
        jar.saveFromResponse(
            origin,
            listOf(didCookie(expiresAt = System.currentTimeMillis() - 1_000)),
        )
        assertTrue(jar.loadForRequest(checkUrl).isEmpty())
    }

    @Test
    fun didCookie_secure_blocksPlainHttp() {
        val jar = InMemoryCookieJar()
        jar.saveFromResponse(origin, listOf(didCookie()))

        val plain = "http://otp-test.example/v1/session/otp/check".toHttpUrl()
        assertTrue(jar.loadForRequest(plain).isEmpty())
    }

    /**
     * Mirrors `verificationLoginCookie_attributesArePreservedThroughJar`
     * but for the device-id cookie. Backend ships the same wire shape
     * for both `__Host-` cookies — pin it via the parser so a Set-Cookie
     * round-trip keeps every attribute the security model leans on.
     */
    @Test
    fun didCookie_attributesArePreservedThroughJar() {
        val setCookie =
            "__Host-did_app-1=device-uuid-abc; Path=/; HttpOnly; Secure; Max-Age=31536000"
        val parsed = Cookie.parse(origin, setCookie)
        assertNotNull("parse: $setCookie", parsed)

        val jar = InMemoryCookieJar()
        jar.saveFromResponse(origin, listOf(parsed!!))

        val replayed = jar.loadForRequest(checkUrl).single()
        assertTrue("__Host- prefix", replayed.name.startsWith("__Host-"))
        assertEquals("device-uuid-abc", replayed.value)
        assertTrue("HttpOnly", replayed.httpOnly)
        assertTrue("Secure", replayed.secure)
        assertEquals("/", replayed.path)
        // __Host- cookies must not carry a Domain attribute.
        assertTrue("hostOnly (no Domain)", replayed.hostOnly)
    }

    @Test
    fun didCookie_setOnLogin_replaysOnRefresh() {
        // Path=/ + same host means the device id persists across every
        // Prelude hop — including /v1/session/refresh — without
        // per-call gymnastics.
        val jar = InMemoryCookieJar()
        val finalizeUrl = "https://otp-test.example/v1/session/login/finalize".toHttpUrl()
        val refreshUrl = "https://otp-test.example/v1/session/refresh".toHttpUrl()

        jar.saveFromResponse(finalizeUrl, listOf(didCookie()))

        val replayed = jar.loadForRequest(refreshUrl)
        assertEquals(
            listOf(didName to "device-uuid-abc"),
            replayed.map { it.name to it.value },
        )
    }

    // ----- verification-login cookie -------------------------------

    @Test
    fun verificationLoginCookie_attributesArePreservedThroughJar() {
        // Pin the wire shape backend issues on POST /v1/session/otp:
        // __Host- prefix, HttpOnly, Secure, Path=/, no Domain (host-only).
        val setCookie =
            "__Host-verification-login_app-1=vt-xyz; Path=/; HttpOnly; Secure"
        val parsed = Cookie.parse(origin, setCookie)
        assertNotNull("parse: $setCookie", parsed)

        val jar = InMemoryCookieJar()
        jar.saveFromResponse(origin, listOf(parsed!!))

        val replayed = jar.loadForRequest(checkUrl).single()
        assertTrue("__Host- prefix", replayed.name.startsWith("__Host-"))
        assertEquals("vt-xyz", replayed.value)
        assertTrue("HttpOnly", replayed.httpOnly)
        assertTrue("Secure", replayed.secure)
        assertEquals("/", replayed.path)
        // __Host- cookies must not carry a Domain attribute.
        assertTrue("hostOnly", replayed.hostOnly)
    }
}
