package so.prelude.android.auth.http

import okhttp3.Request
import org.junit.Assert.assertEquals
import org.junit.Test

class DPoPHtuTest {
    private fun req(url: String): Request = Request.Builder().url(url).build()

    @Test
    fun stripsQueryAndFragment() {
        val htu = dpopHtu(req("https://api.example.com/v1/login?foo=bar#frag"), hostOverride = null)
        assertEquals("https://api.example.com/v1/login", htu)
    }

    @Test
    fun preservesPercentEncodedPath() {
        val htu = dpopHtu(req("https://api.example.com/v1/users/a%20b/sessions"), hostOverride = null)
        assertEquals("https://api.example.com/v1/users/a%20b/sessions", htu)
    }

    @Test
    fun replacesHostFromOverride() {
        val htu =
            dpopHtu(
                req("https://127.0.0.1:3000/v1/session/login"),
                hostOverride = "sessdev.example.com",
            )
        // Override replaces the entire authority — original port is dropped.
        assertEquals("https://sessdev.example.com/v1/session/login", htu)
    }

    /**
     * Regression: previously [dpopHtu] did
     * `request.url.newBuilder().host(hostOverride)`, which throws on a
     * value containing `:port`. The override must accept `host:port`.
     */
    @Test
    fun replacesHostAndPortFromOverride_withPort() {
        val htu =
            dpopHtu(
                req("https://127.0.0.1:3000/v1/users/a%20b/sessions?token=xyz"),
                hostOverride = "sessdev.example.com:443",
            )
        assertEquals("https://sessdev.example.com:443/v1/users/a%20b/sessions", htu)
    }

    @Test
    fun emptyOverride_leavesUrlUntouched() {
        val htu = dpopHtu(req("https://api.example.com/v1/me"), hostOverride = "")
        assertEquals("https://api.example.com/v1/me", htu)
    }

    @Test
    fun nullOverride_stripsQueryFragmentOnly() {
        val htu =
            dpopHtu(
                req("https://api.example.com:8443/v1/me?x=1#anchor"),
                hostOverride = null,
            )
        assertEquals("https://api.example.com:8443/v1/me", htu)
    }
}
