package so.prelude.android.auth.signals

import android.content.Context
import android.content.pm.PackageManager
import kotlinx.coroutines.withTimeoutOrNull
import so.prelude.android.sdk.Prelude

/**
 * [PreludeSignalsDispatcher] backed by the Prelude Android SDK
 * (`so.prelude.android:sdk`).
 *
 * The SDK key is [sdkKey] when it is not blank, else the
 * [MANIFEST_SDK_KEY] `<meta-data>` entry of the application manifest.
 * With no key in either place the adapter is a no-op: [dispatch]
 * returns `null` and logins carry no `dispatch_id`.
 *
 * [timeoutMs] bounds each request and the whole dispatch.
 *
 * [so.prelude.android.auth.PreludeAuthClient] builds one of these by
 * itself when it gets no dispatcher, so most apps only add the
 * manifest entry.
 */
class PreludeSignalsAdapter
    @JvmOverloads
    constructor(
        context: Context,
        sdkKey: String? = null,
        private val timeoutMs: Long = DEFAULT_TIMEOUT_MS,
    ) : PreludeSignalsDispatcher {
        private val prelude: Prelude? =
            pickSignalsSdkKey(sdkKey) { manifestSdkKey(context) }?.let { key ->
                // Only calls that have the same JVM signature in the 0.x
                // and the 1.x signals SDK. `Configuration(...)` with default
                // arguments does not: it breaks when the app resolves the
                // other line.
                Prelude(context.applicationContext ?: context, key).also {
                    it.configuration.requestTimeout = timeoutMs
                }
            }

        override suspend fun dispatch(): String? {
            val client = prelude ?: return null
            // The signals SDK retries each request: bound the whole dispatch.
            val result = withTimeoutOrNull(timeoutMs) { client.dispatchSignals() } ?: return null
            // The auth client lets an Error pass; the signals SDK reports
            // LinkageError as a failure, so rethrow it as an Exception.
            return result.getOrElse { throw it as? Exception ?: IllegalStateException("signals dispatch failed", it) }
        }

        companion object {
            /** `<meta-data android:name>` read for the SDK key. */
            const val MANIFEST_SDK_KEY = "so.prelude.sdk_key"

            const val DEFAULT_TIMEOUT_MS = 5_000L
        }
    }

/** The explicit key when it is not blank, else the manifest key, else `null`. */
internal fun pickSignalsSdkKey(
    explicit: String?,
    manifest: () -> String?,
): String? =
    explicit?.trim()?.takeIf { it.isNotEmpty() }
        ?: manifest()?.trim()?.takeIf { it.isNotEmpty() }

private fun manifestSdkKey(context: Context): String? {
    val packageManager: PackageManager = context.packageManager ?: return null
    return try {
        packageManager
            .getApplicationInfo(context.packageName, PackageManager.GET_META_DATA)
            ?.metaData
            ?.getString(PreludeSignalsAdapter.MANIFEST_SDK_KEY)
    } catch (_: PackageManager.NameNotFoundException) {
        null
    }
}
