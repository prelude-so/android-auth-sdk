package so.prelude.android.session.http

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json
import okhttp3.Request
import okhttp3.Response
import so.prelude.android.session.PreludeSessionError
import so.prelude.android.session.dpop.DPoPKey
import so.prelude.android.session.dpop.DPoPKeyStore
import so.prelude.android.session.dpop.DPoPKeyStoreError
import so.prelude.android.session.dpop.createDPoPProof

private const val USE_DPOP_NONCE_CODE = "use_dpop_nonce"
// 4 KiB: production error bodies are sub-200 bytes; this caps the
// damage of a misbehaving server returning a giant non-JSON 4xx page.
private const val MAX_PEEK_BYTES = 4L * 1024L
private val json = Json { ignoreUnknownKeys = true }

/**
 * Attaches a DPoP proof to every outgoing request, persists any
 * `DPoP-Nonce` the server returns, and recovers transparently from
 * a `use_dpop_nonce` 4xx by retrying once with the fresh nonce.
 *
 * Designed to be composed after auth/refresh interceptors but
 * before the base session, so the proof's `htu` and `htm` line up
 * with what actually goes on the wire.
 *
 * @param keyStore source of the per-domain DPoP keypair and nonce.
 * @param domain key/nonce namespace for this client (typically the
 *   Prelude API origin).
 * @param hostOverride canonical authority to use for the `htu`
 *   claim when the request is being routed through a non-canonical
 *   host (e.g. `localhost` in dev). When `null` the request URL is
 *   used verbatim.
 */
internal class DPoPInterceptor(
    private val keyStore: DPoPKeyStore,
    private val domain: String,
    private val hostOverride: String? = null,
) : PreludeInterceptor {

    /**
     * Wrapped in [withContext]`(Dispatchers.IO)` because the body
     * does blocking I/O — keystore lookups, prefs reads/writes, and
     * an OkHttp `peekBody().string()` decode. The wrap makes the
     * dispatcher contract explicit; without it a main-thread caller
     * would ANR.
     */
    override suspend fun intercept(request: Request, next: SendFunction): Response =
        withContext(Dispatchers.IO) {
            try {
                val key = keyStore.getOrCreate(domain)
                // [DPoPNonceStore] normalises empty-string writes to
                // delete, so `getNonce` should never return `""` here;
                // the `takeIf` is defense-in-depth against a stale
                // entry left by an older SDK version.
                val nonce = keyStore.getNonce(domain)?.takeIf { it.isNotEmpty() }

                val response = next(request.withProof(key, nonce))

                if (response.code !in 200..299 && response.isUseDPoPNonce()) {
                    val freshNonce = response.header(HttpHeader.DPOP_NONCE)
                    if (freshNonce == null) {
                        // Server demanded a fresh nonce but didn't supply one.
                        // That's a server bug — surface it as a structured
                        // error rather than letting the generic 4xx through,
                        // where it would mask the real cause of failure.
                        response.close()
                        throw PreludeSessionError.Generic(
                            code = "missing_dpop_nonce_header",
                            displayMessage = "Server returned $USE_DPOP_NONCE_CODE without a ${HttpHeader.DPOP_NONCE} header",
                        )
                    }
                    response.close()
                    // Persist before the retry. RFC 9449 §8 requires the client
                    // to use this nonce on all subsequent proofs; if the retry
                    // throws or its response omits `DPoP-Nonce`, we'd otherwise
                    // lose it and pay for another challenge round-trip on the
                    // next request. Re-harvested below in case the retry
                    // response advances the nonce.
                    keyStore.setNonce(domain, freshNonce)
                    val retry = next(request.withProof(key, freshNonce))
                    retry.header(HttpHeader.DPOP_NONCE)?.let { keyStore.setNonce(domain, it) }
                    return@withContext retry
                }

                response.header(HttpHeader.DPOP_NONCE)?.let { keyStore.setNonce(domain, it) }
                response
            } catch (e: DPoPKeyStoreError) {
                // Internal crypto failure — wrap into the public error
                // contract so callers see one error hierarchy.
                throw PreludeSessionError.CryptoFailure(e)
            }
        }

    private fun Request.withProof(key: DPoPKey, nonce: String?): Request {
        val proof = createDPoPProof(key, method, dpopHtu(this, hostOverride), nonce)
        return newBuilder().header(HttpHeader.DPOP, proof).build()
    }

    /**
     * Snapshot the response body (without consuming it) and check
     * whether the error code is `use_dpop_nonce`. Any decode failure
     * — non-JSON body, unexpected shape, body too large — falls
     * through to "no, it's not a nonce challenge", because retrying
     * on an unrelated error would mask the real failure.
     */
    private fun Response.isUseDPoPNonce(): Boolean = try {
        val body = peekBody(MAX_PEEK_BYTES).string()
        json.decodeFromString(ApiErrorJson.serializer(), body).code == USE_DPOP_NONCE_CODE
    } catch (_: Exception) {
        false
    }
}
