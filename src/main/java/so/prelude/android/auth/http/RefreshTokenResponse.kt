package so.prelude.android.auth.http

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * Body returned by `POST /v1/session/refresh`.
 *
 * The rotated refresh token (when present) arrives via the
 * `X-Refresh-Token` response header — *not* in this body — and its
 * paired ISO 8601 expiry via `X-Refresh-Token-Expires-At`.
 *
 * @property accessToken JWT access token, ready to use as the
 *   `Authorization: Bearer` value.
 * @property expiresAt absolute server-side expiry, in Unix seconds.
 *   The client adds the observed clock-skew offset before persisting
 *   so a comparison against the local device clock is meaningful.
 */
@Serializable
internal data class RefreshTokenResponse(
    @SerialName("access_token") val accessToken: String,
    @SerialName("expires_at") val expiresAt: Long,
)
