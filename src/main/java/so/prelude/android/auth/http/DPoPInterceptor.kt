package so.prelude.android.auth.http

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json
import okhttp3.Request
import okhttp3.Response
import so.prelude.android.auth.PreludeAuthError
import so.prelude.android.auth.dpop.DPoPKey
import so.prelude.android.auth.dpop.DPoPKeyStore
import so.prelude.android.auth.dpop.DPoPKeyStoreError
import so.prelude.android.auth.dpop.createDPoPProof
import kotlin.math.abs

private const val USE_DPOP_NONCE_CODE = "use_dpop_nonce"
private const val INVALID_DPOP_PROOF_CODE = "invalid_dpop_proof"

/**
 * Minimum |skew| (ms) that warrants retrying with a corrected
 * `iat`. Below this an `invalid_dpop_proof` is unlikely to be
 * caused by clock drift, so we don't retry.
 */
private const val CLOCK_SKEW_RETRY_THRESHOLD_MS = 1_000L

// 4 KiB: production error bodies are sub-200 bytes; this caps the
// damage of a misbehaving server returning a giant non-JSON 4xx page.
private const val MAX_PEEK_BYTES = 4L * 1024L
private val json = Json { ignoreUnknownKeys = true }

/**
 * Attaches a DPoP proof to every request, persists `DPoP-Nonce`
 * responses, and retries (one-shot) on:
 *  - `use_dpop_nonce`: re-sign with the fresh nonce.
 *  - `invalid_dpop_proof` + `Date:` header indicating
 *    |skew| ≥ [CLOCK_SKEW_RETRY_THRESHOLD_MS]: re-sign with the
 *    corrected `iat` and persist the skew for future requests.
 */
internal class DPoPInterceptor(
    private val keyStore: DPoPKeyStore,
    private val domain: String,
    private val hostOverride: String? = null,
) : PreludeInterceptor {
    override suspend fun intercept(
        request: Request,
        next: SendFunction,
    ): Response =
        withContext(Dispatchers.IO) {
            try {
                val key = keyStore.getOrCreate(domain)
                val nonce = keyStore.getNonce(domain)?.takeIf { it.isNotEmpty() }
                val skewMs = keyStore.getClockSkewMs(domain) ?: 0L

                val response = next(request.signedWith(key, nonce, skewMs))
                // RFC 9449 §8: server SHOULD echo `DPoP-Nonce` on
                // every response. Harvest unconditionally up here
                // so the retry paths stay focused on their own
                // concern (use_dpop_nonce or clock skew) and read
                // any rotated nonce from the store.
                val rotatedNonce = response.harvestNonce()
                if (response.code in 200..299) return@withContext response

                when (response.errorCode()) {
                    USE_DPOP_NONCE_CODE -> {
                        retryWithFreshNonce(request, response, key, skewMs, rotatedNonce, next)
                    }

                    INVALID_DPOP_PROOF_CODE -> {
                        retryWithCorrectedSkew(request, response, key, next) ?: response
                    }

                    else -> {
                        response
                    }
                }
            } catch (e: DPoPKeyStoreError) {
                throw PreludeAuthError.CryptoFailure(e)
            }
        }

    private suspend fun retryWithFreshNonce(
        request: Request,
        response: Response,
        key: DPoPKey,
        skewMs: Long,
        freshNonce: String?,
        next: SendFunction,
    ): Response {
        if (freshNonce == null) {
            response.close()
            throw PreludeAuthError.Generic(
                code = "missing_dpop_nonce_header",
                displayMessage = "Server returned $USE_DPOP_NONCE_CODE without a ${HttpHeader.DPOP_NONCE} header",
            )
        }
        response.close()
        return next(request.signedWith(key, freshNonce, skewMs)).also { it.harvestNonce() }
    }

    /** `null` when no Date header / unparseable / sub-threshold —
     *  caller falls through to the normal error path. A
     *  sub-threshold result still *clears* any persisted skew so
     *  a stale correction (e.g. from before a device-clock
     *  re-sync) can't keep poisoning future requests. */
    private suspend fun retryWithCorrectedSkew(
        request: Request,
        response: Response,
        key: DPoPKey,
        next: SendFunction,
    ): Response? {
        val skewMs = response.serverSkewMs() ?: return null
        if (abs(skewMs) < CLOCK_SKEW_RETRY_THRESHOLD_MS) {
            keyStore.deleteClockSkewMs(domain)
            return null
        }
        response.close()
        // Persisted skew is sticky until the next
        // `invalid_dpop_proof` either resets or clears it. After
        // a device-clock re-sync the first request burns one
        // server rejection to self-heal — acceptable in exchange
        // for not invalidating skew on every refresh.
        keyStore.setClockSkewMs(domain, skewMs)
        val nonce = keyStore.getNonce(domain)?.takeIf { it.isNotEmpty() }
        return next(request.signedWith(key, nonce, skewMs)).also { it.harvestNonce() }
    }

    private fun Request.signedWith(
        key: DPoPKey,
        nonce: String?,
        clockSkewMs: Long,
    ): Request {
        val proof = createDPoPProof(key, method, dpopHtu(this, hostOverride), nonce, clockSkewMs = clockSkewMs)
        return newBuilder().header(HttpHeader.DPOP, proof).build()
    }

    /** Persist a rotated `DPoP-Nonce` if present and return it. */
    private fun Response.harvestNonce(): String? {
        val nonce = header(HttpHeader.DPOP_NONCE)?.takeIf { it.isNotEmpty() }
        nonce?.let { keyStore.setNonce(domain, it) }
        return nonce
    }

    /** `serverTime - localTime` in ms; `null` on missing or
     *  unparseable header so the caller can skip the retry. */
    private fun Response.serverSkewMs(): Long? {
        val dateHeader = header(HttpHeader.DATE) ?: return null
        val serverInstant = HttpDate.parse(dateHeader) ?: return null
        return serverInstant.toEpochMilli() - System.currentTimeMillis()
    }

    /** Peek the body and return the JSON error code, or `null` on
     *  any decode failure. Unrelated 4xx then surfaces as itself
     *  instead of being retried. */
    private fun Response.errorCode(): String? =
        try {
            val body = peekBody(MAX_PEEK_BYTES).string()
            json.decodeFromString(ApiErrorJson.serializer(), body).code
        } catch (_: Exception) {
            null
        }
}
