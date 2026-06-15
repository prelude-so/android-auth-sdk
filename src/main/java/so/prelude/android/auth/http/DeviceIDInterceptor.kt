package so.prelude.android.auth.http

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.Request
import okhttp3.Response
import so.prelude.android.auth.store.DeviceIDStore

/**
 * Stamps the persisted device id from [DeviceIDStore] onto every
 * request as [HttpHeader.DEVICE_ID]. The store handles lazy
 * creation and concurrent-caller convergence; only the cold path
 * (cache miss) hops to [Dispatchers.IO] so warm requests don't
 * pay a dispatcher switch.
 *
 * Best-effort: if the store fails (e.g. storage write rejection)
 * the request proceeds without the header — a missing device id
 * must never fail the chain.
 */
internal class DeviceIDInterceptor(
    private val store: DeviceIDStore,
    private val domain: String,
) : PreludeInterceptor {
    override suspend fun intercept(
        request: Request,
        next: SendFunction,
    ): Response {
        val deviceID =
            store.cached(domain)
                ?: withContext(Dispatchers.IO) { runCatching { store.getOrCreate(domain) }.getOrNull() }
        val builder = request.newBuilder()
        if (deviceID != null) builder.header(HttpHeader.DEVICE_ID, deviceID)
        return next(builder.build())
    }
}
