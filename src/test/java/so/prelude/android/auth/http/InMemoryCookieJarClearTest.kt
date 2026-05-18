package so.prelude.android.auth.http

import okhttp3.Cookie
import okhttp3.HttpUrl.Companion.toHttpUrl
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * `clear(host)` is what `clearAllStores` calls on logout / revoke
 * to drop server-set cookies (`verification`, `did`, …) so they
 * don't outlive the session.
 */
class InMemoryCookieJarClearTest {
    private fun cookie(
        name: String,
        value: String,
        host: String,
    ): Cookie =
        Cookie
            .Builder()
            .name(name)
            .value(value)
            .domain(host)
            .path("/")
            .build()

    @Test
    fun clear_removesEveryCookieForHost() {
        val jar = InMemoryCookieJar()
        val url = "https://example.com/".toHttpUrl()
        jar.saveFromResponse(
            url,
            listOf(
                cookie("verification", "abc", "example.com"),
                cookie("did", "device-1", "example.com"),
            ),
        )
        assertEquals(2, jar.loadForRequest(url).size)

        jar.clear("example.com")

        assertTrue("post-clear jar must be empty", jar.loadForRequest(url).isEmpty())
    }

    @Test
    fun clear_leavesOtherHostsUntouched() {
        val jar = InMemoryCookieJar()
        val a = "https://a.example.com/".toHttpUrl()
        val b = "https://b.example.com/".toHttpUrl()
        jar.saveFromResponse(a, listOf(cookie("verification", "a-val", "a.example.com")))
        jar.saveFromResponse(b, listOf(cookie("verification", "b-val", "b.example.com")))

        jar.clear("a.example.com")

        assertTrue(jar.loadForRequest(a).isEmpty())
        assertEquals(1, jar.loadForRequest(b).size)
    }

    @Test
    fun clear_unknownHost_isNoOp() {
        val jar = InMemoryCookieJar()
        // Must not throw.
        jar.clear("never-saw-this-host.example")
    }
}
