package so.prelude.android.auth.http

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject

/*
 * Wire DTOs for the passkey (WebAuthn) surface.
 *
 * The server speaks the WebAuthn JSON wire format and the platform
 * Credential Manager consumes / produces that same JSON verbatim, so
 * the credential-creation / request options (`public_key`) and the
 * ceremony output (`attestation` / `assertion`) travel as raw
 * [JsonElement] — passing them through untouched avoids dropping any
 * WebAuthn field the SDK doesn't model.
 */

// MARK: - Register

/** Body posted to `POST /v1/session/me/passkeys/register/begin`. */
@Serializable
internal data class PasskeyRegisterBeginBody(
    val username: String,
    @SerialName("display_name") val displayName: String? = null,
    val nickname: String? = null,
)

/**
 * Response from `register/begin`. `publicKey` is nullable so a
 * malformed payload surfaces a structured error instead of a generic
 * decode failure.
 */
@Serializable
internal data class PasskeyRegisterBeginResponse(
    @SerialName("public_key") val publicKey: JsonObject? = null,
    @SerialName("registration_token") val registrationToken: String? = null,
)

/** Body posted to `POST /v1/session/me/passkeys/register/finish`. */
@Serializable
internal data class PasskeyRegisterFinishBody(
    @SerialName("registration_token") val registrationToken: String,
    val attestation: JsonElement,
) {
    /** The registration token is a bearer-equivalent for the in-flight ceremony. */
    override fun toString(): String = "PasskeyRegisterFinishBody(registrationToken=<redacted>, attestation=…)"
}

/** Response from `register/finish`. */
@Serializable
internal data class PasskeyRegisterFinishResponse(
    val credential: PasskeyCredentialResponse? = null,
    @SerialName("already_registered") val alreadyRegistered: Boolean? = null,
)

// MARK: - Login

/** Body posted to `POST /v1/session/login/passkey/begin`. */
@Serializable
internal data class PasskeyLoginBeginBody(
    @SerialName("dispatch_id") val dispatchId: String? = null,
)

/** Response from `login/passkey/begin`. */
@Serializable
internal data class PasskeyLoginBeginResponse(
    @SerialName("public_key") val publicKey: JsonObject? = null,
    @SerialName("login_token") val loginToken: String? = null,
)

/** Body posted to `POST /v1/session/login/passkey/finish`. */
@Serializable
internal data class PasskeyLoginFinishBody(
    @SerialName("login_token") val loginToken: String,
    val assertion: JsonElement,
) {
    /** The login token binds begin to finish — keep it out of logs. */
    override fun toString(): String = "PasskeyLoginFinishBody(loginToken=<redacted>, assertion=…)"
}

// MARK: - Step-up

/** Body posted to `POST /v1/session/stepup/continue` for a verify_passkey step. */
@Serializable
internal data class PasskeyStepUpContinueBody(
    @SerialName("challenge_token") val challengeToken: String,
    @SerialName("passkey_assertion") val passkeyAssertion: JsonElement,
) {
    /** The challenge token is a single-use bearer-equivalent for the step. */
    override fun toString(): String = "PasskeyStepUpContinueBody(challengeToken=<redacted>, passkeyAssertion=…)"
}

// MARK: - Management

/** Body posted to `PATCH /v1/session/me/passkeys/{id}`. An empty nickname clears the label. */
@Serializable
internal data class PasskeyRenameBody(
    val nickname: String,
)

/** Response from `GET /v1/session/me/passkeys`. */
@Serializable
internal data class PasskeyListResponse(
    val credentials: List<PasskeyCredentialResponse>? = null,
)

/**
 * Wire-shaped projection of
 * [so.prelude.android.auth.PreludePasskeyCredential]. Every field
 * defaults so a partial server response decodes into sentinels rather
 * than throwing a structural decode error.
 */
@Serializable
internal data class PasskeyCredentialResponse(
    @SerialName("credential_id") val credentialId: String = "",
    val nickname: String? = null,
    val transports: List<String>? = null,
    @SerialName("backup_state") val backupState: Boolean? = null,
    @SerialName("created_at") val createdAt: Long? = null,
    @SerialName("last_used_at") val lastUsedAt: Long? = null,
)
