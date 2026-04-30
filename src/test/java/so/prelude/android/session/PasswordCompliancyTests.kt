package so.prelude.android.session

import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import so.prelude.android.session.http.HttpHeader

/**
 * Unit tests for the password-compliancy surface
 * ([getPasswordCompliancy] / [validatePassword] /
 * [PreludePasswordCompliancy.validate]).
 */
class PasswordCompliancyTests {

    private val standardRules = PreludePasswordCompliancy(
        minLength = 8,
        maxLength = 64,
        uppercase = 1,
        lowercase = 1,
        numbers = 1,
        symbols = 1,
    )

    // MARK: - Network surface

    @Test
    fun getPasswordCompliancy_decodesAllFields_andShipsBodylessGet() = runBlocking {
        // Verifies the wire shape (snake_case keys), the GET method,
        // and the strict-proxy contract that a bodyless request must
        // not carry `Content-Type`.
        val fixture = Fixture.make()
        fixture.http.install(
            "/v1/session/password/compliancy",
            StubHttpSession.Canned.json(
                """
                {
                  "min_length": 8,
                  "max_length": 64,
                  "uppercase": 1,
                  "lowercase": 1,
                  "numbers": 1,
                  "symbols": 0
                }
                """.trimIndent(),
            ),
        )

        val compliancy = fixture.client.getPasswordCompliancy()

        assertEquals(
            PreludePasswordCompliancy(
                minLength = 8,
                maxLength = 64,
                uppercase = 1,
                lowercase = 1,
                numbers = 1,
                symbols = 0,
            ),
            compliancy,
        )

        val req = fixture.http.requestsFor("/v1/session/password/compliancy").single()
        assertEquals("GET", req.method)
        assertEquals("application/json", req.header(HttpHeader.ACCEPT))
        // Strict proxies / gateways reject a Content-Type header on a
        // bodyless request — `buildSessionRequest` skips it for any
        // method other than POST.
        assertNull(
            "bodyless GET must not carry Content-Type",
            req.header(HttpHeader.CONTENT_TYPE),
        )
        // Unauthenticated public-config endpoint: no bearer, no DPoP.
        // Sending a DPoP proof here would leak the device's `jkt`
        // into the audit log against an unauthenticated identity.
        assertNull(
            "compliancy fetch must NOT carry an Authorization header",
            req.header(HttpHeader.AUTHORIZATION),
        )
        assertNull(
            "compliancy fetch must NOT carry a DPoP proof",
            req.header(HttpHeader.DPOP),
        )
    }

    @Test
    fun getPasswordCompliancy_serverError_propagates() = runBlocking {
        // 5xx must surface as the structured transport error rather
        // than being swallowed.
        val fixture = Fixture.make()
        fixture.http.install(
            "/v1/session/password/compliancy",
            StubHttpSession.Canned.json(
                """{"code":"internal_server_error","message":"boom"}""",
                statusCode = 500,
            ),
        )

        val thrown = try {
            fixture.client.getPasswordCompliancy()
            null
        } catch (e: PreludeSessionError) {
            e
        }
        assertTrue(
            "expected InternalServerError, got $thrown",
            thrown is PreludeSessionError.InternalServerError,
        )
    }

    // MARK: - Pure classification

    @Test
    fun validate_passwordMeetsAllRules_isValid() {
        // 8 code points, 1 upper, 6 lower, 1 digit, 1 symbol — every
        // criterion passes against `standardRules`.
        val result = standardRules.validate("Abcdef1!")

        assertTrue(result.valid)
        assertEquals(6, result.results.size)
        for (entry in result.results) {
            assertTrue(
                "criterion ${entry.criterion} should pass",
                entry.valid,
            )
        }
    }

    @Test
    fun validate_tooShort_failsMinLengthOnly() {
        // 4 code points — fails minLength (8 expected). Every other
        // criterion still satisfies the rule. Pins per-rule isolation.
        val result = standardRules.validate("Ab1!")

        assertFalse(result.valid)
        val byCriterion = result.results.associateBy { it.criterion }

        val min = byCriterion[PreludePasswordCompliancyCriterion.MIN_LENGTH]!!
        assertEquals(false, min.valid)
        assertEquals(4, min.actual)
        assertEquals(8, min.expected)

        val max = byCriterion[PreludePasswordCompliancyCriterion.MAX_LENGTH]!!
        assertEquals(true, max.valid)
    }

    @Test
    fun validate_maxLengthZero_treatedAsNoUpperBound() {
        // `maxLength == 0` is the server's "no upper bound" sentinel.
        // A 10k-char password against `maxLength = 0` must validate
        // — the short-circuit in the classifier kicks in.
        val rules = PreludePasswordCompliancy(
            minLength = 1,
            maxLength = 0,
            uppercase = 0,
            lowercase = 0,
            numbers = 0,
            symbols = 0,
        )

        val result = rules.validate("a".repeat(10_000))

        val max = result.results.first {
            it.criterion == PreludePasswordCompliancyCriterion.MAX_LENGTH
        }
        assertEquals(true, max.valid)
    }

    @Test
    fun validate_missingUppercase_failsJustUppercase() {
        // 8 lowercase + 1 digit + 1 symbol — every rule passes
        // except `uppercase >= 1`. Pins that an isolated rule
        // failure doesn't drag down the unrelated entries.
        val result = standardRules.validate("abcdef1!")

        assertFalse(result.valid)
        for (entry in result.results) {
            if (entry.criterion != PreludePasswordCompliancyCriterion.UPPERCASE) {
                assertTrue(
                    "${entry.criterion} should have passed",
                    entry.valid,
                )
            }
        }
        val upper = result.results.first {
            it.criterion == PreludePasswordCompliancyCriterion.UPPERCASE
        }
        assertEquals(0, upper.actual)
        assertEquals(false, upper.valid)
    }

    @Test
    fun validate_countsUnicodeCodePoints_notUtf16Chars() {
        // A regional-indicator flag (`🇫🇷`) is one grapheme cluster
        // but two code points (each above the BMP — 4 UTF-16 chars
        // total). The classifier counts code points via
        // `String.codePointAt` iteration. Counting `String.length`
        // (UTF-16 chars) would say 4, counting graphemes would say 1
        // — neither matches the server. Pins the iteration step.
        val flag = "🇫🇷" // 🇫🇷 — RIS_F + RIS_R
        // Sanity-check the test input: 4 UTF-16 chars but 2 code points.
        assertEquals(4, flag.length)
        assertEquals(2, flag.codePointCount(0, flag.length))

        val rules = PreludePasswordCompliancy(
            minLength = 2,
            maxLength = 0,
            uppercase = 0,
            lowercase = 0,
            numbers = 0,
            symbols = 2,
        )
        val result = rules.validate(flag)

        val min = result.results.first {
            it.criterion == PreludePasswordCompliancyCriterion.MIN_LENGTH
        }
        assertEquals(2, min.actual)
        assertEquals(true, min.valid)

        val symbols = result.results.first {
            it.criterion == PreludePasswordCompliancyCriterion.SYMBOLS
        }
        assertEquals(2, symbols.actual)
        assertEquals(true, symbols.valid)
    }

    @Test
    fun validate_classifiesNonASCIILetters() {
        // Unicode letters outside ASCII land in uppercase / lowercase
        // via `Character.getType` (Lu / Ll), not in symbols. Greek
        // capital alpha is Lu; small beta and gamma are Ll.
        val rules = PreludePasswordCompliancy(
            minLength = 1,
            maxLength = 0,
            uppercase = 0,
            lowercase = 0,
            numbers = 0,
            symbols = 0,
        )

        val result = rules.validate("Αβγ")

        val byCriterion = result.results.associateBy { it.criterion }
        assertEquals(
            1,
            byCriterion[PreludePasswordCompliancyCriterion.UPPERCASE]!!.actual,
        )
        assertEquals(
            2,
            byCriterion[PreludePasswordCompliancyCriterion.LOWERCASE]!!.actual,
        )
        assertEquals(
            0,
            byCriterion[PreludePasswordCompliancyCriterion.SYMBOLS]!!.actual,
        )
    }

    @Test
    fun validate_supplementaryDigit_isCountedOnce() {
        // Mathematical bold digit `𝟏` (U+1D7CF) is a single code
        // point in `Nd` general category but two UTF-16 chars. It
        // must count once toward `numbers` and once toward `length`,
        // not twice. Pins that the classifier walks code points and
        // increments `length` / classification once per code point.
        val rules = PreludePasswordCompliancy(
            minLength = 1,
            maxLength = 0,
            uppercase = 0,
            lowercase = 0,
            numbers = 1,
            symbols = 0,
        )

        val result = rules.validate("𝟏") // U+1D7CF MATHEMATICAL BOLD DIGIT ONE

        val byCriterion = result.results.associateBy { it.criterion }
        assertEquals(
            1,
            byCriterion[PreludePasswordCompliancyCriterion.MIN_LENGTH]!!.actual,
        )
        assertEquals(
            1,
            byCriterion[PreludePasswordCompliancyCriterion.NUMBERS]!!.actual,
        )
        assertTrue(result.valid)
    }

    // MARK: - End-to-end through the HTTP stack

    @Test
    fun validatePassword_fetchesCompliancy_andAppliesIt() = runBlocking {
        // The client-bound convenience must (1) round-trip
        // `/password/compliancy` and (2) pass the parsed rules to
        // the pure classifier — same observable result as calling
        // both in sequence by hand.
        val fixture = Fixture.make()
        fixture.http.install(
            "/v1/session/password/compliancy",
            StubHttpSession.Canned.json(
                """
                {
                  "min_length": 8,
                  "max_length": 0,
                  "uppercase": 0,
                  "lowercase": 0,
                  "numbers": 0,
                  "symbols": 0
                }
                """.trimIndent(),
            ),
        )

        val result = fixture.client.validatePassword("longenoughpw")

        assertTrue(result.valid)
        val min = result.results.first {
            it.criterion == PreludePasswordCompliancyCriterion.MIN_LENGTH
        }
        assertEquals(12, min.actual)

        // Exactly one fetch — the convenience does not poll.
        assertEquals(
            1,
            fixture.http.requestCount("/v1/session/password/compliancy"),
        )
    }
}
