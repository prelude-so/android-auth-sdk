package so.prelude.android.auth.http

import java.time.Instant
import java.time.LocalDateTime
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter
import java.util.Locale

/**
 * Permissive HTTP `Date:` header parser. RFC 7231 §7.1.1.1 allows
 * three forms — `IMF-fixdate` (canonical), `rfc850-date`, and
 * `asctime-date`. Each formatter only matches one pattern, so we
 * try them in turn and fall through to `null` for anything
 * unparseable.
 */
internal object HttpDate {
    fun parse(header: String): Instant? {
        for (formatter in FORMATTERS) {
            try {
                return LocalDateTime.parse(header, formatter).toInstant(ZoneOffset.UTC)
            } catch (_: Exception) {
                // try next
            }
        }
        return null
    }

    private val FORMATTERS: List<DateTimeFormatter> =
        listOf(
            // IMF-fixdate, canonical: "Sun, 06 Nov 1994 08:49:37 GMT"
            DateTimeFormatter.ofPattern("EEE, dd MMM yyyy HH:mm:ss 'GMT'", Locale.US),
            // RFC 850 (obsolete): "Sunday, 06-Nov-94 08:49:37 GMT"
            DateTimeFormatter.ofPattern("EEEE, dd-MMM-yy HH:mm:ss 'GMT'", Locale.US),
            // asctime, single- or double-space day (obsolete):
            //   "Sun Nov  6 08:49:37 1994"
            DateTimeFormatter.ofPattern("EEE MMM ppd HH:mm:ss yyyy", Locale.US),
        )
}
