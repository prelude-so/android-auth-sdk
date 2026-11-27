package so.prelude.android.auth.http

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.Request
import okhttp3.Response
import so.prelude.android.auth.PreludeAuthError
import so.prelude.android.auth.dpop.DPoPKeyStore
import so.prelude.android.auth.dpop.DeviceKeyStore
import so.prelude.android.auth.dpop.createDeviceProof
import kotlin.coroutines.cancellation.CancellationException

private const val INVALID_DEVICE_PROOF_CODE = "invalid_device_proof"

/**
 * Adds the `Prelude-Device-Proof` header. Place it outside the DPoP
 * interceptor so a DPoP retry resends the same device proof.
 */
internal class DeviceProofInterceptor(
    private val mode: Mode,
    private val domain: String,
    private val keyStore: DPoPKeyStore,
    private val deviceKeyStore: DeviceKeyStore,
    private val challengeToken: String,
    private val hostOverride: String?,
) : PreludeInterceptor {
    enum class Mode {
        /** On `invalid_device_proof`, retries without the proof, so an SDK bug never blocks a sign-in. */
        Login,

        /** No retry: the server requires the proof. */
        StepUp,
    }

    override suspend fun intercept(
        request: Request,
        next: SendFunction,
    ): Response {
        val proof = withContext(Dispatchers.IO) { makeProof(request) } ?: return next(request)

        val response = next(request.newBuilder().header(HttpHeader.DEVICE_PROOF, proof).build())
        if (mode == Mode.Login && response.code == 400 && response.apiErrorCode() == INVALID_DEVICE_PROOF_CODE) {
            response.close()
            return next(request)
        }
        return response
    }

    private fun makeProof(request: Request): String? =
        try {
            val dpopKey = if (mode == Mode.Login) keyStore.getOrCreate(domain) else keyStore.get(domain)
            dpopKey?.let {
                createDeviceProof(
                    deviceKey = deviceKeyStore.getOrCreate(),
                    dpopKey = it,
                    method = request.method,
                    url = dpopHtu(request, hostOverride),
                    challengeToken = challengeToken,
                )
            }
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            // At step-up the server refuses a request without a proof.
            if (mode == Mode.StepUp) throw PreludeAuthError.CryptoFailure(e)
            null
        }
}
