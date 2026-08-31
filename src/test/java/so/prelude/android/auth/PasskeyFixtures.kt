package so.prelude.android.auth

import so.prelude.android.auth.passkey.PasskeyCeremony

/**
 * Fake ceremony driver + canned wire fragments for the passkey test
 * suite. Records the options it was handed and returns canned WebAuthn
 * JSON (or a preset error).
 */
internal class FakePasskeyCeremony : PasskeyCeremony {
    var attestationJson: String = PasskeyFixtures.ATTESTATION_JSON
    var assertionJson: String = PasskeyFixtures.ASSERTION_JSON
    var registerError: Throwable? = null
    var assertError: Throwable? = null

    var registeredOptions: String? = null
        private set
    var assertedOptions: String? = null
        private set

    override suspend fun register(optionsJson: String): String {
        registeredOptions = optionsJson
        registerError?.let { throw it }
        return attestationJson
    }

    override suspend fun assert(optionsJson: String): String {
        assertedOptions = optionsJson
        assertError?.let { throw it }
        return assertionJson
    }
}

internal object PasskeyFixtures {
    /** Minimal valid `public_key` for `register/begin`. */
    const val CREATION_OPTIONS_JSON =
        """{"rp":{"id":"example.com","name":"Example"},"user":{"id":"dXNlcg","name":"a@b.co","displayName":"A B"},"challenge":"Y2hhbGxlbmdl","pubKeyCredParams":[{"type":"public-key","alg":-7}]}"""

    /** Minimal valid `public_key` for `login/begin` and step-up. */
    const val REQUEST_OPTIONS_JSON = """{"challenge":"Y2hhbGxlbmdl","rpId":"example.com"}"""

    /** Canned ceremony outputs (WebAuthn JSON). */
    const val ATTESTATION_JSON =
        """{"id":"cred-id","rawId":"cred-id","type":"public-key","response":{"clientDataJSON":"cdj","attestationObject":"att-obj"}}"""
    const val ASSERTION_JSON =
        """{"id":"cred-id","rawId":"cred-id","type":"public-key","response":{"clientDataJSON":"cdj","authenticatorData":"auth-data","signature":"sig","userHandle":"user-handle"}}"""

    fun registerBegin(registrationToken: String = "reg-tok") =
        StubHttpSession.Canned.json(
            """{"public_key":$CREATION_OPTIONS_JSON,"registration_token":"$registrationToken"}""",
        )

    fun registerFinish(alreadyRegistered: Boolean = false) =
        StubHttpSession.Canned.json(
            """{"credential":{"credential_id":"cred-id","nickname":"Pixel","transports":["internal"],"backup_state":true,"created_at":10,"last_used_at":10},"already_registered":$alreadyRegistered}""",
        )

    fun loginBegin(loginToken: String = "login-tok") =
        StubHttpSession.Canned.json(
            """{"public_key":$REQUEST_OPTIONS_JSON,"login_token":"$loginToken"}""",
        )

    fun challengeTokenResponse(challengeToken: String) = StubHttpSession.Canned.json("""{"challenge_token":"$challengeToken"}""")

    /** `stepup/request` response whose issued step is `verify_passkey`. */
    fun stepUpVerifyPasskey(challengeToken: String) =
        StubHttpSession.Canned.json(
            """{"status":"continue","challenge_token":"$challengeToken","public_key_credential_request_options":$REQUEST_OPTIONS_JSON}""",
        )
}
