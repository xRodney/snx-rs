package net.pankratov.snxrs

/** Static entry points into libsnxrs.so (apps/snxrs-android). */
object Native {
    init {
        System.loadLibrary("snxrs")
    }

    /** Login types the gateway offers, as JSON `[{id, name, factors}]` or `{"error": ...}`. Blocking. */
    @JvmStatic
    external fun loginTypes(config: String): String
}
