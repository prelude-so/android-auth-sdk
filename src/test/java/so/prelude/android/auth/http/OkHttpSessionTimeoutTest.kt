package so.prelude.android.auth.http

import org.junit.Assert.assertEquals
import org.junit.Test
import kotlin.time.Duration.Companion.seconds
import kotlin.time.toJavaDuration

/**
 * Regression: `timeout` passed to the public [PreludeAuthClient]
 * constructor must reach the underlying [OkHttpClient]. Previously
 * the field was stored but never wired, so callers asking for a
 * 30s budget silently inherited OkHttp's 10s default.
 */
class OkHttpSessionTimeoutTest {
    @Test
    fun defaultClient_appliesTimeoutToEveryPhase() {
        val timeout = 7.seconds
        val client = OkHttpSession.defaultClient(InMemoryCookieJar(), timeout)

        val expectedMs = timeout.toJavaDuration().toMillis().toInt()
        assertEquals(expectedMs, client.connectTimeoutMillis)
        assertEquals(expectedMs, client.readTimeoutMillis)
        assertEquals(expectedMs, client.writeTimeoutMillis)
        assertEquals(expectedMs, client.callTimeoutMillis)
    }
}
