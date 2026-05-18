package so.prelude.android.auth.store

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * A persisted refresh token record for a single Prelude domain.
 *
 * The expiry is stored verbatim as the ISO 8601 string the backend
 * returned — the server is the authority on refresh-token validity,
 * the SDK doesn't compare it against the local clock.
 *
 * @property refreshToken opaque token issued by `/login/finalize`
 *   and rotated on every successful `/refresh`.
 * @property refreshTokenExpiresAt server-provided ISO 8601 expiry,
 *   or `null` when the server omitted the
 *   `X-Refresh-Token-Expires-At` header.
 */
@Serializable
internal data class RefreshTokenRecord(
    @SerialName("refresh_token") val refreshToken: String,
    @SerialName("refresh_token_expires_at") val refreshTokenExpiresAt: String? = null,
)
