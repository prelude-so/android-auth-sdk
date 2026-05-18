package so.prelude.android.auth

import okhttp3.Cookie
import okhttp3.HttpUrl.Companion.toHttpUrl
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import so.prelude.android.auth.dpop.FakeDPoPKeyStore
import so.prelude.android.auth.http.HttpClient
import so.prelude.android.auth.http.InMemoryCookieJar
import so.prelude.android.auth.store.AccessTokenCache
import so.prelude.android.auth.store.InMemoryAccessTokenStorage
import so.prelude.android.auth.store.InMemoryRefreshTokenStorage
import so.prelude.android.auth.store.RefreshTokenStore
import java.net.URL
import java.time.Instant
import kotlin.time.Duration.Companion.seconds

/**
 * Regression: when `hostOverride` is set, [PreludeAuthClient.domain]
 * diverges from `baseUrl.host`. The cookie jar buckets by request URL
 * host, so the wipe in [clearAllStores] must key on `baseUrl.host` —
 * not [domain] — otherwise server-set cookies (`verification`, `did`)
 * survive logout / revoke.
 */
class ClearAllStoresCookieJarTest {
    private val baseUrl = URL("https://localhost")
    private val hostOverride = "myapp.auth.prelude.dev"
    private val clock = Instant.ofEpochSecond(1_700_000_000)

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

    private fun newClient(jar: InMemoryCookieJar): PreludeAuthClient =
        PreludeAuthClient(
            applicationContext = null,
            baseUrl = baseUrl,
            hostOverride = hostOverride,
            timeout = 1.seconds,
            httpClient = HttpClient(session = StubHttpSession(), clock = { clock }, cookieJar = jar),
            keyStore = FakeDPoPKeyStore(),
            refreshTokenStore = RefreshTokenStore(storage = InMemoryRefreshTokenStorage()),
            accessTokenCache = AccessTokenCache(clock = { clock }, storage = InMemoryAccessTokenStorage()),
            clock = { clock },
            signalsDispatcher = null,
        )

    @Test
    fun clearAllStores_wipesCookiesUnderBaseUrlHost_whenHostOverrideIsSet() {
        val jar = InMemoryCookieJar()
        val requestUrl = "https://${baseUrl.host}/".toHttpUrl()
        jar.saveFromResponse(
            requestUrl,
            listOf(
                cookie("verification", "abc", baseUrl.host),
                cookie("did", "device-1", baseUrl.host),
            ),
        )
        assertEquals("pre-clear sanity", 2, jar.loadForRequest(requestUrl).size)

        val client = newClient(jar)
        assertEquals("fixture must reproduce the divergence", hostOverride, client.domain)

        client.clearAllStores()

        assertTrue(
            "cookies under baseUrl.host must be wiped",
            jar.loadForRequest(requestUrl).isEmpty(),
        )
    }
}
