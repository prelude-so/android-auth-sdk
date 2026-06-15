package so.prelude.android.auth

import so.prelude.android.auth.dpop.FakeDPoPKeyStore
import so.prelude.android.auth.http.DeviceIDInterceptor
import so.prelude.android.auth.http.HttpClient
import so.prelude.android.auth.signals.PreludeSignalsDispatcher
import so.prelude.android.auth.store.AccessTokenCache
import so.prelude.android.auth.store.AccessTokenStorage
import so.prelude.android.auth.store.DeviceIDStorage
import so.prelude.android.auth.store.DeviceIDStore
import so.prelude.android.auth.store.InMemoryAccessTokenStorage
import so.prelude.android.auth.store.InMemoryDeviceIDStorage
import so.prelude.android.auth.store.InMemoryRefreshTokenStorage
import so.prelude.android.auth.store.RefreshTokenStorage
import so.prelude.android.auth.store.RefreshTokenStore
import java.net.URL
import java.time.Instant
import kotlin.time.Duration.Companion.seconds

/**
 * Pre-wired [PreludeAuthClient] + backing stores + stub HTTP
 * session, so each test focuses on behaviour rather than setup.
 *
 * The internal [PreludeAuthClient] constructor accepts a nullable
 * `applicationContext` — tests pass `null` because none of the
 * in-memory test doubles need a Context.
 */
internal class Fixture(
    val baseUrl: URL,
    val domain: String,
    val clock: Instant,
    val signalsDispatcher: PreludeSignalsDispatcher? = null,
    // Injected so failure-mode tests can substitute a faulting double
    // (e.g. `FailingRefreshTokenStorage`) without rebuilding the rest
    // of the wiring.
    val refreshTokenStorage: RefreshTokenStorage = InMemoryRefreshTokenStorage(),
    // Same shape as [refreshTokenStorage] — failure-mode tests inject
    // a [FailingAccessTokenStorage] to assert the access-token cache
    // delete is on the wipe path.
    val accessTokenStorage: AccessTokenStorage = InMemoryAccessTokenStorage(),
    // Same shape — failure-mode tests inject a [FailingDeviceIDStorage]
    // to assert a device-id fault never fails the request chain.
    val deviceIDStorage: DeviceIDStorage = InMemoryDeviceIDStorage(),
) {
    val keyStore = FakeDPoPKeyStore()
    val accessTokenCache =
        AccessTokenCache(
            clock = { clock },
            storage = accessTokenStorage,
        )
    val refreshTokenStore = RefreshTokenStore(storage = refreshTokenStorage)
    val deviceIDStore = DeviceIDStore(storage = deviceIDStorage)
    val http = StubHttpSession()
    val httpClient =
        HttpClient(
            session = http,
            clock = { clock },
            defaultInterceptors = listOf(DeviceIDInterceptor(deviceIDStore, domain)),
        )

    val client: PreludeAuthClient =
        PreludeAuthClient(
            applicationContext = null,
            baseUrl = baseUrl,
            hostOverride = null,
            timeout = 1.seconds,
            httpClient = httpClient,
            keyStore = keyStore,
            refreshTokenStore = refreshTokenStore,
            accessTokenCache = accessTokenCache,
            clock = { clock },
            signalsDispatcher = signalsDispatcher,
        )

    companion object {
        /**
         * Build a fixture for `domain`. Defaults to a fixed clock
         * (epoch 1_700_000_000) so the [StubHttpSession]'s `Date:`
         * header lines up with the client's clock and `timeDiffSec`
         * stays at zero.
         */
        fun make(
            domain: String = "otp-test.example",
            clock: Instant = Instant.ofEpochSecond(1_700_000_000),
            signalsDispatcher: PreludeSignalsDispatcher? = null,
            refreshTokenStorage: RefreshTokenStorage = InMemoryRefreshTokenStorage(),
            accessTokenStorage: AccessTokenStorage = InMemoryAccessTokenStorage(),
            deviceIDStorage: DeviceIDStorage = InMemoryDeviceIDStorage(),
        ): Fixture =
            Fixture(
                baseUrl = URL("https://$domain"),
                domain = domain,
                clock = clock,
                signalsDispatcher = signalsDispatcher,
                refreshTokenStorage = refreshTokenStorage,
                accessTokenStorage = accessTokenStorage,
                deviceIDStorage = deviceIDStorage,
            )
    }
}
