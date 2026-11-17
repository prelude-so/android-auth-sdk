package so.prelude.android.auth

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Test
import so.prelude.android.auth.signals.pickSignalsSdkKey

class SignalsSdkKeyTest {
    @Test
    fun `explicit key wins and the manifest is not read`() {
        var manifestRead = false
        val key =
            pickSignalsSdkKey(" sdk_explicit ") {
                manifestRead = true
                "sdk_manifest"
            }
        assertEquals("sdk_explicit", key)
        assertFalse(manifestRead)
    }

    @Test
    fun `missing or blank explicit key falls back to the manifest`() {
        assertEquals("sdk_manifest", pickSignalsSdkKey(null) { "sdk_manifest" })
        assertEquals("sdk_manifest", pickSignalsSdkKey("  ") { " sdk_manifest " })
    }

    @Test
    fun `no key anywhere gives null`() {
        assertNull(pickSignalsSdkKey(null) { null })
        assertNull(pickSignalsSdkKey("") { "  " })
    }
}
