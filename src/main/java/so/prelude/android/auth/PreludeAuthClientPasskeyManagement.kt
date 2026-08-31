package so.prelude.android.auth

import kotlinx.serialization.encodeToString
import okhttp3.RequestBody.Companion.toRequestBody
import so.prelude.android.auth.http.JSON_MEDIA_TYPE
import so.prelude.android.auth.http.PasskeyListResponse
import so.prelude.android.auth.http.PasskeyRenameBody
import so.prelude.android.auth.http.WIRE_JSON

/*
 * Passkey management surface for [PreludeAuthClient].
 *
 * List / rename / delete the authenticated user's credentials. All
 * three routes are protected — bearer-authenticated and DPoP-bound —
 * so they run through `[autoRefreshInterceptor, dpopInterceptor]`.
 */

/**
 * List the authenticated user's registered passkeys. Returns an
 * empty list when the user has none.
 */
suspend fun PreludeAuthClient.listPasskeys(): List<PreludePasskeyCredential> {
    val request = buildSessionRequest("me/passkeys", method = "GET").build()
    val (body, _) =
        httpClient.sendJson(
            request = request,
            deserializer = PasskeyListResponse.serializer(),
            interceptors = listOf(autoRefreshInterceptor, dpopInterceptor),
        )
    return body.credentials?.map { it.toPublic() } ?: emptyList()
}

/**
 * Rename a passkey. An empty [nickname] clears the label. Cosmetic —
 * no step-up scope required.
 *
 * Throws [PreludeAuthError.InvalidConfiguration] for an empty
 * [credentialId].
 */
suspend fun PreludeAuthClient.renamePasskey(
    credentialId: String,
    nickname: String,
) {
    if (credentialId.isEmpty()) {
        throw PreludeAuthError.InvalidConfiguration("renamePasskey requires a non-empty credential id")
    }
    val url = sessionUrl("me/passkeys").addPathSegment(credentialId).build()
    val payload = WIRE_JSON.encodeToString(PasskeyRenameBody(nickname = nickname))
    // Start from the POST builder (which attaches Content-Type) and
    // swap the verb: OkHttp requires a body for PATCH.
    val request =
        buildSessionRequest(url)
            .method("PATCH", payload.toRequestBody(JSON_MEDIA_TYPE))
            .build()
    httpClient.sendExpectingNoBody(
        request = request,
        interceptors = listOf(autoRefreshInterceptor, dpopInterceptor),
    )
}

/**
 * Delete a passkey. Refreshes the session afterwards since removing
 * the last credential can flip the `has_passkey` claim.
 *
 * Throws [PreludeAuthError.InvalidConfiguration] for an empty
 * [credentialId].
 */
suspend fun PreludeAuthClient.deletePasskey(credentialId: String) {
    if (credentialId.isEmpty()) {
        throw PreludeAuthError.InvalidConfiguration("deletePasskey requires a non-empty credential id")
    }
    val url = sessionUrl("me/passkeys").addPathSegment(credentialId).build()
    val request = buildSessionRequest(url, method = "DELETE").build()
    httpClient.sendExpectingNoBody(
        request = request,
        interceptors = listOf(autoRefreshInterceptor, dpopInterceptor),
    )

    refreshAfterPasskeyMutation()
}

/**
 * Force the next access token to reflect a changed `has_passkey`
 * claim: invalidate the cached token, then mint a fresh one.
 */
internal suspend fun PreludeAuthClient.refreshAfterPasskeyMutation() {
    invalidateCache()
    refresh()
}
