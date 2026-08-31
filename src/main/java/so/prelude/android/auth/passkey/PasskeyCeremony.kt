package so.prelude.android.auth.passkey

/**
 * Drives the platform passkey ceremony. Abstracted so the client
 * flows can be exercised without system UI.
 *
 * Options and results travel as raw WebAuthn JSON: the platform
 * Credential Manager consumes the server's credential options and
 * returns the attestation / assertion in exactly that shape, so the
 * SDK forwards both untouched rather than re-modelling every field.
 */
internal interface PasskeyCeremony {
    /** Create a credential; returns the attestation JSON. */
    suspend fun register(optionsJson: String): String

    /** Assert an existing credential; returns the assertion JSON. */
    suspend fun assert(optionsJson: String): String
}
