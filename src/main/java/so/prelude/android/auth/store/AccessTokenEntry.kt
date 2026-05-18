package so.prelude.android.auth.store

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * A cached access token plus its absolute expiration.
 *
 * The persisted keys are snake_case to match the server's `/refresh`
 * response shape; the blob is per-platform private state.
 *
 * @property accessToken the JWT access token verbatim, ready to use
 *   as the `Authorization: Bearer` value.
 * @property expiresAt seconds since the Unix epoch, already adjusted
 *   for observed client/server clock skew at cache time so a comparison
 *   against the local clock is meaningful.
 */
@Serializable
internal data class AccessTokenEntry(
    @SerialName("access_token") val accessToken: String,
    @SerialName("expires_at") val expiresAt: Long,
)
