package so.prelude.android.auth.passkey

import android.content.Context
import android.os.Build
import androidx.credentials.CreatePublicKeyCredentialRequest
import androidx.credentials.CreatePublicKeyCredentialResponse
import androidx.credentials.CredentialManager
import androidx.credentials.GetCredentialRequest
import androidx.credentials.GetPublicKeyCredentialOption
import androidx.credentials.PublicKeyCredential
import androidx.credentials.exceptions.CreateCredentialCancellationException
import androidx.credentials.exceptions.CreateCredentialException
import androidx.credentials.exceptions.GetCredentialCancellationException
import androidx.credentials.exceptions.GetCredentialException
import androidx.credentials.exceptions.NoCredentialException
import androidx.credentials.exceptions.domerrors.InvalidStateError
import androidx.credentials.exceptions.publickeycredential.CreatePublicKeyCredentialDomException
import so.prelude.android.auth.PreludeAuthError
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Platform passkey ceremony backed by the AndroidX Credential
 * Manager. Consumes and returns raw WebAuthn JSON.
 *
 * `androidx.credentials` is a `compileOnly` dependency of the SDK, so
 * apps that don't use passkeys pull no extra weight; passkey
 * integrators add the runtime artifact (and
 * `credentials-play-services-auth` on API < 34) themselves.
 *
 * [context] should be an Activity so the system can present the
 * ceremony sheet. The instance is short-lived — one ceremony per
 * call site — so the reference is not retained beyond the call.
 */
internal class CredentialManagerCeremony(
    private val context: Context,
) : PasskeyCeremony {
    private val credentialManager = CredentialManager.create(context)

    override suspend fun register(optionsJson: String): String =
        withCeremonyGate {
            try {
                val response =
                    credentialManager.createCredential(
                        context = context,
                        request = CreatePublicKeyCredentialRequest(optionsJson),
                    )
                (response as? CreatePublicKeyCredentialResponse)?.registrationResponseJson
                    ?: throw PreludeAuthError.PasskeyRegistrationFailed(
                        "Unexpected credential type from authenticator",
                    )
            } catch (_: CreateCredentialCancellationException) {
                // A dismissed sheet is control flow, not a failure.
                throw PreludeAuthError.Cancelled()
            } catch (e: CreatePublicKeyCredentialDomException) {
                // InvalidStateError means an excluded credential already
                // exists here: the account has a passkey on this device.
                if (e.domError is InvalidStateError) {
                    throw PreludeAuthError.PasskeyAlreadyRegistered(
                        "A passkey for this account already exists on this device",
                    )
                }
                throw PreludeAuthError.PasskeyRegistrationFailed(
                    e.message ?: "Passkey registration ceremony failed",
                )
            } catch (e: CreateCredentialException) {
                throw PreludeAuthError.PasskeyRegistrationFailed(
                    e.message ?: "Passkey registration ceremony failed",
                )
            }
        }

    override suspend fun assert(optionsJson: String): String =
        withCeremonyGate {
            try {
                val request = GetCredentialRequest(listOf(GetPublicKeyCredentialOption(optionsJson)))
                val response = credentialManager.getCredential(context = context, request = request)
                (response.credential as? PublicKeyCredential)?.authenticationResponseJson
                    ?: throw PreludeAuthError.PasskeyStepUnavailable(
                        "Unexpected credential type from authenticator",
                    )
            } catch (_: GetCredentialCancellationException) {
                throw PreludeAuthError.Cancelled()
            } catch (e: NoCredentialException) {
                throw PreludeAuthError.PasskeyStepUnavailable(
                    e.message ?: "No passkey available for this account",
                )
            } catch (e: GetCredentialException) {
                throw PreludeAuthError.PasskeyStepUnavailable(
                    e.message ?: "Passkey assertion ceremony failed",
                )
            }
        }

    /**
     * Serialise presentation: the system shows one ceremony sheet at
     * a time. Releases on every exit path, including coroutine
     * cancellation, so a dismissed ceremony never latches the gate.
     */
    private inline fun <T> withCeremonyGate(block: () -> T): T {
        if (!gate.compareAndSet(false, true)) {
            throw PreludeAuthError.Conflict("Another passkey ceremony is already in progress")
        }
        try {
            return block()
        } finally {
            gate.set(false)
        }
    }

    companion object {
        private val gate = AtomicBoolean(false)

        /**
         * Concrete ceremony for [context], or a clear
         * [PreludeAuthError.PasskeyNotSupported] on OS versions that
         * predate platform WebAuthn support (passkeys need API 28+).
         */
        fun create(context: Context): PasskeyCeremony {
            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.P) {
                throw PreludeAuthError.PasskeyNotSupported(
                    "Passkeys require Android 9 (API 28) or later",
                )
            }
            return CredentialManagerCeremony(context)
        }
    }
}
