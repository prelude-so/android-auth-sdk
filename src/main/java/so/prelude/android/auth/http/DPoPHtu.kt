package so.prelude.android.auth.http

import okhttp3.Request

/**
 * Build the `htu` claim for [request].
 *
 * Per RFC 9449 § 4.2 the value omits query and fragment. When
 * [hostOverride] is non-null its authority replaces the request URL's
 * — completely — so a client routing through `localhost:3000` can
 * still produce a canonical `htu` that matches what the server
 * reconstructs from its `Host:` header.
 *
 * The override is concatenated verbatim, including any port. We
 * deliberately don't push it through `HttpUrl.Builder.host(...)`
 * because (a) OkHttp's builder rejects port-bearing strings and
 * (b) `HttpUrl.toString()` elides the scheme's default port (`:443`
 * for https, `:80` for http), which the server doesn't elide when it
 * reconstructs `htu` from its `Host:` header.
 */
internal fun dpopHtu(
    request: Request,
    hostOverride: String?,
): String {
    val base =
        request.url
            .newBuilder()
            .query(null)
            .fragment(null)
            .build()

    if (hostOverride.isNullOrEmpty()) return base.toString()

    return "${base.scheme}://$hostOverride${base.encodedPath}"
}
