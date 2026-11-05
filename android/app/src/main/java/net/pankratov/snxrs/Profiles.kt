package net.pankratov.snxrs

import android.content.Context
import android.content.SharedPreferences
import android.util.Base64
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import java.io.File
import java.util.UUID

/**
 * Connection profiles. Each profile is an encrypted preferences file whose keys are snx-rs config-file
 * option names (`server-name`, `login-type`, …); [configText] renders it as `snx-rs.conf` text, which
 * the native side parses with the desktop's own parser. Keys starting with `_` are app-internal.
 */
object Profiles {
    data class Profile(val id: String, val name: String)

    private const val INDEX = "profiles"
    private val cache = mutableMapOf<String, SharedPreferences>()

    private fun index(ctx: Context) = ctx.getSharedPreferences(INDEX, Context.MODE_PRIVATE)

    private fun ids(ctx: Context): List<String> =
        index(ctx).getString("ids", "").orEmpty().split(',').filter { it.isNotBlank() }

    private fun saveIds(ctx: Context, ids: List<String>) {
        index(ctx).edit().putString("ids", ids.joinToString(",")).apply()
    }

    @Synchronized
    fun prefs(ctx: Context, id: String): SharedPreferences = cache.getOrPut(id) {
        val app = ctx.applicationContext
        EncryptedSharedPreferences.create(
            app,
            "profile_$id",
            MasterKey.Builder(app).setKeyScheme(MasterKey.KeyScheme.AES256_GCM).build(),
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
        )
    }

    fun list(ctx: Context): List<Profile> = ids(ctx).map { id ->
        Profile(id, prefs(ctx, id).getString("profile-name", null).orEmpty().ifBlank { ctx.getString(R.string.profile_unnamed) })
    }

    fun create(ctx: Context, name: String): String {
        val id = UUID.randomUUID().toString()
        prefs(ctx, id).edit().putString("profile-name", name).commit()
        saveIds(ctx, ids(ctx) + id)
        return id
    }

    @Synchronized
    fun delete(ctx: Context, id: String) {
        prefs(ctx, id).edit().clear().commit()
        cache.remove(id)
        ctx.deleteSharedPreferences("profile_$id")
        File(ctx.filesDir, "profiles/$id").deleteRecursively()
        val rest = ids(ctx) - id
        saveIds(ctx, rest)
        if (selected(ctx) == id) setSelected(ctx, rest.firstOrNull())
    }

    fun selected(ctx: Context): String? = index(ctx).getString("selected", null)?.takeIf { it in ids(ctx) }

    fun setSelected(ctx: Context, id: String?) {
        index(ctx).edit().putString("selected", id).apply()
    }

    /** Per-profile directory for files picked in settings (CA and client certificates). */
    fun filesDir(ctx: Context, id: String): File = File(ctx.filesDir, "profiles/$id").apply { mkdirs() }

    fun configText(ctx: Context, id: String): String = buildString {
        append("profile-id=").append(id).append('\n')
        for ((key, raw) in prefs(ctx, id).all.toSortedMap()) {
            if (key.startsWith("_") || key == "profile-id") continue
            var value = when (raw) {
                is Boolean -> raw.toString()
                is String -> if (key == "password" || key == "cert-password") raw else raw.trim()
                else -> continue
            }
            if (value.isEmpty() || value.contains('\n')) continue
            // snx-rs.conf keeps the password base64-encoded; the parser decodes it.
            if (key == "password") value = Base64.encodeToString(value.toByteArray(), Base64.NO_WRAP)
            append(key).append('=').append(value).append('\n')
        }
    }

    /** First run of the profile-based UI: turn the old single-form settings into a profile. */
    fun migrateLegacy(ctx: Context) {
        if (ids(ctx).isNotEmpty()) return
        val form = ctx.getSharedPreferences("form", Context.MODE_PRIVATE)
        val id = create(ctx, form.getString("server", null)?.takeIf { it.isNotBlank() } ?: ctx.getString(R.string.profile_default_name))
        prefs(ctx, id).edit().apply {
            form.getString("server", null)?.let { putString("server-name", it) }
            form.getString("login_type", null)?.let { putString("login-type", it) }
            form.getString("username", null)?.let { putString("user-name", it) }
            if (form.getBoolean("ignore_cert", false)) putBoolean("ignore-server-cert", true)
        }.commit()
        setSelected(ctx, id)
    }
}
