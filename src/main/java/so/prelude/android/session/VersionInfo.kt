package so.prelude.android.session

/**
 * Version is a namespace for session SDK–related version information.
 */
object VersionInfo {
    /**
     * The major version.
     */
    const val MAJOR = 0

    /**
     * The minor version.
     */
    const val MINOR = 2

    /**
     * The patch version.
     */
    const val PATCH = 0

    /**
     * The version string.
     */
    val versionString: String get() = "$MAJOR.$MINOR.$PATCH"
}
