package so.prelude.android.auth

import so.prelude.android.auth.http.PasswordCompliancyResponse

/*
 * Password-compliancy surface for [PreludeAuthClient].
 *
 * Three entry points:
 *
 *   - [getPasswordCompliancy] — fetch the server's configured rules.
 *   - [PreludePasswordCompliancy.validate] — pure local classifier;
 *     useful for typing UIs (live "your password is compliant" hint)
 *     where re-fetching the rules on every keystroke would be
 *     wasteful.
 *   - [validatePassword] — convenience that fetches + classifies in
 *     one call.
 *
 * The endpoint is unauthenticated — the rules are public configuration
 * — so the request runs without DPoP and without a bearer. Same
 * empty interceptor list as the OTP-start surface, for the same
 * reason.
 */

/**
 * Fetch the server's configured password compliancy rules.
 *
 * `GET /v1/session/password/compliancy`. Unauthenticated: the rules
 * are public configuration, exposed so callers can render password-
 * input UIs that match exactly what the server will accept on
 * [loginWithPassword] and [changePassword].
 *
 * The request runs with no interceptors — no DPoP, no auto-refresh,
 * no bearer. Sending a DPoP proof against an unauthenticated route
 * would leak the device's `jkt` into the anti-fraud audit log
 * against an unauthenticated identity, same caveat as
 * [loginWithPassword]'s first hop.
 *
 * The request is bodyless and ships without a `Content-Type` header
 * — strict proxies reject a `Content-Type` on a bodyless request.
 * [PreludeAuthClient.buildSessionRequest] handles this when the
 * `method` argument is anything other than `"POST"`.
 *
 * Throws the standard transport hierarchy
 * ([PreludeAuthError.Network], [PreludeAuthError.Timeout]),
 * [PreludeAuthError.BadRequest] when password auth is not configured
 * for the app, and [PreludeAuthError.Generic] for any other unmapped
 * server code.
 */
suspend fun PreludeAuthClient.getPasswordCompliancy(): PreludePasswordCompliancy {
    val request = buildSessionRequest("password/compliancy", method = "GET").build()

    val (body, _) =
        httpClient.sendJson(
            request = request,
            deserializer = PasswordCompliancyResponse.serializer(),
            // Public configuration — no DPoP, no bearer. See file header.
            interceptors = emptyList(),
        )

    return PreludePasswordCompliancy(
        minLength = body.minLength,
        maxLength = body.maxLength,
        uppercase = body.uppercase,
        lowercase = body.lowercase,
        numbers = body.numbers,
        symbols = body.symbols,
    )
}

/**
 * Validate a candidate [password] against the server's configured
 * compliancy rules. Convenience for UIs that don't already hold a
 * cached [PreludePasswordCompliancy] — fetches the rules in one round-
 * trip, then calls [PreludePasswordCompliancy.validate].
 *
 * Live-typing UIs that classify on every keystroke should call
 * [getPasswordCompliancy] once and reuse the result with
 * [PreludePasswordCompliancy.validate] instead — there's no need to
 * re-fetch public configuration per keystroke.
 *
 * Throws the same errors as [getPasswordCompliancy].
 */
suspend fun PreludeAuthClient.validatePassword(password: String): PreludePasswordCompliancyResults {
    val compliancy = getPasswordCompliancy()
    return compliancy.validate(password)
}

/**
 * Classify [password] against `this` rule set. Pure function — no
 * network, no I/O — so live-typing UIs can call it on every
 * keystroke after a single [getPasswordCompliancy] fetch.
 *
 * Counting iterates Unicode *code points*, not grapheme clusters.
 * A regional-indicator flag (e.g. `🇫🇷`,
 * which is one grapheme cluster but two code points) therefore
 * counts as 2 toward [PreludePasswordCompliancy.minLength] /
 * [PreludePasswordCompliancy.maxLength] — the same way the server
 * counts when it computes the rule outcome itself.
 *
 * Character classification uses the JVM's Unicode `generalCategory`
 * (`Character.getType`). Only cased letters count toward
 * [PreludePasswordCompliancyCriterion.UPPERCASE] /
 * [PreludePasswordCompliancyCriterion.LOWERCASE] (Latin, Greek,
 * Cyrillic, …); uncased letters (CJK, Arabic, Hebrew, Thai,
 * Devanagari, …), non-decimal numerals (Roman numerals,
 * superscripts, …), punctuation and whitespace all count toward
 * [PreludePasswordCompliancyCriterion.SYMBOLS]. Only decimal digits
 * count toward [PreludePasswordCompliancyCriterion.NUMBERS].
 *
 * `maxLength == 0` is the server's "no upper bound" sentinel —
 * the corresponding entry in [PreludePasswordCompliancyResults.results]
 * is unconditionally [PreludePasswordCompliancyResult.valid].
 */
fun PreludePasswordCompliancy.validate(password: String): PreludePasswordCompliancyResults {
    var uppercase = 0
    var lowercase = 0
    var numbers = 0
    var symbols = 0
    var length = 0

    // Walk code points, not chars: a single code point above the BMP
    // is two `Char`s in a Kotlin `String`, but should count as one
    // toward length and as one classification.
    var i = 0
    while (i < password.length) {
        val cp = password.codePointAt(i)
        when (Character.getType(cp).toByte()) {
            Character.UPPERCASE_LETTER -> uppercase++
            Character.LOWERCASE_LETTER -> lowercase++
            Character.DECIMAL_DIGIT_NUMBER -> numbers++
            else -> symbols++
        }
        length++
        i += Character.charCount(cp)
    }

    val results =
        listOf(
            PreludePasswordCompliancyResult(
                criterion = PreludePasswordCompliancyCriterion.MIN_LENGTH,
                actual = length,
                expected = minLength,
                valid = length >= minLength,
            ),
            PreludePasswordCompliancyResult(
                criterion = PreludePasswordCompliancyCriterion.MAX_LENGTH,
                actual = length,
                expected = maxLength,
                // `0` is the "no upper bound" sentinel — short-circuit so
                // the server's "off" state isn't reported as a failure.
                valid = maxLength == 0 || length <= maxLength,
            ),
            PreludePasswordCompliancyResult(
                criterion = PreludePasswordCompliancyCriterion.UPPERCASE,
                actual = uppercase,
                expected = this.uppercase,
                valid = uppercase >= this.uppercase,
            ),
            PreludePasswordCompliancyResult(
                criterion = PreludePasswordCompliancyCriterion.LOWERCASE,
                actual = lowercase,
                expected = this.lowercase,
                valid = lowercase >= this.lowercase,
            ),
            PreludePasswordCompliancyResult(
                criterion = PreludePasswordCompliancyCriterion.NUMBERS,
                actual = numbers,
                expected = this.numbers,
                valid = numbers >= this.numbers,
            ),
            PreludePasswordCompliancyResult(
                criterion = PreludePasswordCompliancyCriterion.SYMBOLS,
                actual = symbols,
                expected = this.symbols,
                valid = symbols >= this.symbols,
            ),
        )

    return PreludePasswordCompliancyResults(
        valid = results.all { it.valid },
        results = results,
    )
}
