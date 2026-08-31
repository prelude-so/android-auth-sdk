package so.prelude.android.auth

import so.prelude.android.auth.http.PasskeyCredentialResponse

// MARK: - Passkey public types

/**
 * Options for [so.prelude.android.auth.registerPasskey].
 *
 * @property username shown by the authenticator; usually the user's
 *   email or phone.
 * @property displayName human-friendly name; defaults to [username]
 *   when `null`.
 * @property nickname optional server-side label ("Pixel", "YubiKey").
 */
data class RegisterPasskeyOptions(
    val username: String,
    val displayName: String? = null,
    val nickname: String? = null,
)

/**
 * A passkey registered to the authenticated user.
 *
 * @property credentialId server-side identifier; pass to
 *   [so.prelude.android.auth.renamePasskey] /
 *   [so.prelude.android.auth.deletePasskey].
 * @property nickname user-facing label, or `null` when unset.
 * @property transports WebAuthn transports the credential advertises.
 * @property backupState whether the credential is backed up (synced).
 * @property createdAt Unix seconds the credential was registered.
 * @property lastUsedAt Unix seconds of the last assertion; equals
 *   [createdAt] until first use.
 */
data class PreludePasskeyCredential(
    val credentialId: String,
    val nickname: String?,
    val transports: List<String>,
    val backupState: Boolean,
    val createdAt: Long,
    val lastUsedAt: Long,
)

/**
 * Outcome of [so.prelude.android.auth.registerPasskey].
 *
 * @property credential the stored credential.
 * @property alreadyRegistered `true` when the authenticator
 *   re-offered a credential that already existed server-side.
 */
data class PreludePasskeyRegistration(
    val credential: PreludePasskeyCredential,
    val alreadyRegistered: Boolean,
)

/** Map a wire credential to its public type. */
internal fun PasskeyCredentialResponse.toPublic(): PreludePasskeyCredential =
    PreludePasskeyCredential(
        credentialId = credentialId,
        nickname = nickname,
        transports = transports ?: emptyList(),
        backupState = backupState ?: false,
        createdAt = createdAt ?: 0L,
        lastUsedAt = lastUsedAt ?: 0L,
    )
