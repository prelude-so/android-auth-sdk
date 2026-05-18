package so.prelude.android.auth.http

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.Request
import okhttp3.Response
import so.prelude.android.auth.PreludeAuthError
import so.prelude.android.auth.dpop.DPoPKeyStore
import so.prelude.android.auth.dpop.DPoPKeyStoreError
import so.prelude.android.auth.dpop.createDPoPProof
import so.prelude.android.auth.dpop.decodeJwtJti

/**
 * Attaches a DPoP proof bound to the [challengeToken]'s `jti` —
 * used in step-up flows to prove ownership of the challenge.
 *
 * Two deliberate departures from [DPoPInterceptor]:
 *
 *  1. Uses [DPoPKeyStore.get], not `getOrCreate`. If the domain has
 *     no key, the proof is skipped and the request passes through
 *     unchanged — step-up only makes sense once a session key
 *     already exists.
 *  2. No nonce is included, and no nonce is persisted from the
 *     response. The challenge proof is one-shot ownership; the
 *     `htu`/`iat`/`jti` triple is what the server validates.
 *
 * @param keyStore source of the existing DPoP keypair.
 * @param domain key namespace for this client.
 * @param challengeToken the JWT issued by the server's step-up
 *   endpoint. Its `jti` is bound into the proof.
 * @param hostOverride canonical authority for the `htu` claim;
 *   see [DPoPInterceptor] for semantics.
 */
internal class ChallengeDPoPInterceptor(
    private val keyStore: DPoPKeyStore,
    private val domain: String,
    private val challengeToken: String,
    private val hostOverride: String? = null,
) : PreludeInterceptor {
    /**
     * `withContext(Dispatchers.IO)` because the body does blocking
     * keystore I/O via [DPoPKeyStore.get] and runs ECDSA signing in
     * [createDPoPProof]. Same reasoning as [DPoPInterceptor].
     */
    override suspend fun intercept(
        request: Request,
        next: SendFunction,
    ): Response =
        withContext(Dispatchers.IO) {
            try {
                val key = keyStore.get(domain) ?: return@withContext next(request)
                val jti = decodeJwtJti(challengeToken) ?: return@withContext next(request)

                val proof =
                    createDPoPProof(
                        key = key,
                        method = request.method,
                        url = dpopHtu(request, hostOverride),
                        nonce = null,
                        jti = jti,
                    )
                next(request.newBuilder().header(HttpHeader.DPOP, proof).build())
            } catch (e: DPoPKeyStoreError) {
                throw PreludeAuthError.CryptoFailure(e)
            }
        }
}
