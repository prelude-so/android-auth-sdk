package so.prelude.android.session.dpop

/** Failure modes surfaced by the DPoP store. */
internal sealed class DPoPKeyStoreError(message: String, cause: Throwable? = null) :
    Exception(message, cause) {

    internal class KeyGenerationFailed(cause: Throwable) :
        DPoPKeyStoreError("DPoP key generation failed: ${cause.message}", cause)

    internal class KeystoreFailure(cause: Throwable) :
        DPoPKeyStoreError("AndroidKeystore failure: ${cause.message}", cause)

    internal class SigningFailed(cause: Throwable) :
        DPoPKeyStoreError("ECDSA signing failed: ${cause.message}", cause)

    internal class InvalidPublicKey(message: String) :
        DPoPKeyStoreError("Invalid DPoP public key: $message")

    /**
     * DER signature blob from the keystore was unparseable.
     *
     * Declared as a regular `class` — not `object` — so each `throw`
     * creates a fresh instance and `fillInStackTrace` runs at the
     * throw site. A shared singleton would carry whichever stack
     * trace got captured at class-init, hiding the real DER offset
     * that triggered the failure across unrelated callers (same
     * reasoning as `PreludeSessionError.Timeout`).
     */
    internal class MalformedSignature :
        DPoPKeyStoreError("DPoP signature DER is malformed")
}
