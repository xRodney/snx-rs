package net.pankratov.snxrs

import android.net.Uri
import android.os.Bundle
import android.provider.OpenableColumns
import android.text.InputType
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AlertDialog
import androidx.core.os.bundleOf
import androidx.preference.EditTextPreference
import androidx.preference.ListPreference
import androidx.preference.Preference
import androidx.preference.PreferenceDataStore
import androidx.preference.PreferenceFragmentCompat
import org.json.JSONArray
import java.io.File

/**
 * Settings for one profile. Preference keys are snx-rs config-file option names and are stored in the
 * profile's encrypted preferences through [ProfileDataStore].
 */
class ProfileSettingsFragment : PreferenceFragmentCompat() {

    companion object {
        private const val ARG_ID = "profile_id"
        private const val LOGIN_TYPES_CACHE = "_login_types"
        private val NUMERIC = listOf("mtu", "ike-lifetime", "ip-lease-time", "password-factor")
        private val SECRET = listOf("password", "cert-password")
        private val FILES = listOf("ca-cert", "cert-path")
        private val CREDENTIALS = listOf("user-name", "password")

        fun newInstance(profileId: String) = ProfileSettingsFragment().apply { arguments = bundleOf(ARG_ID to profileId) }
    }

    private class ProfileDataStore(private val prefs: android.content.SharedPreferences) : PreferenceDataStore() {
        override fun putString(key: String, value: String?) {
            prefs.edit().putString(key, value).apply()
        }

        override fun getString(key: String, defValue: String?): String? = prefs.getString(key, defValue)

        override fun putBoolean(key: String, value: Boolean) {
            prefs.edit().putBoolean(key, value).apply()
        }

        override fun getBoolean(key: String, defValue: Boolean): Boolean = prefs.getBoolean(key, defValue)
    }

    private lateinit var profileId: String
    private lateinit var store: ProfileDataStore
    private var loginFactors: Map<String, String> = emptyMap()
    private var pendingFileKey: String? = null

    private val pickFile = registerForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) onFilePicked(uri)
    }

    override fun onCreatePreferences(savedInstanceState: Bundle?, rootKey: String?) {
        profileId = requireArguments().getString(ARG_ID)!!
        store = ProfileDataStore(Profiles.prefs(requireContext(), profileId))
        preferenceManager.preferenceDataStore = store
        setPreferencesFromResource(R.xml.profile_preferences, rootKey)

        for (key in NUMERIC) {
            findPreference<EditTextPreference>(key)?.setOnBindEditTextListener { it.inputType = InputType.TYPE_CLASS_NUMBER }
        }
        for (key in SECRET) {
            findPreference<EditTextPreference>(key)?.apply {
                setOnBindEditTextListener {
                    it.inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
                }
                summaryProvider = Preference.SummaryProvider<EditTextPreference> { p ->
                    if (p.text.isNullOrEmpty()) getString(R.string.value_not_set) else "••••••••"
                }
            }
        }
        for (key in FILES) {
            findPreference<Preference>(key)?.apply {
                updateFileSummary(this)
                setOnPreferenceClickListener { onFileClick(it); true }
            }
        }
        findPreference<Preference>("_load_login_types")?.setOnPreferenceClickListener { loadLoginTypes(); true }
        findPreference<ListPreference>("login-type")?.setOnPreferenceChangeListener { _, value ->
            updateCredentialVisibility(value as String)
            true
        }
        applyLoginTypes(store.getString(LOGIN_TYPES_CACHE, null))
    }

    private fun loadLoginTypes() {
        if (store.getString("server-name", null).isNullOrBlank()) {
            toast(getString(R.string.status_enter_server))
            return
        }
        val ctx = requireContext().applicationContext
        val config = Profiles.configText(ctx, profileId)
        toast(getString(R.string.status_loading))
        Thread {
            val json = Native.loginTypes(config)
            activity?.runOnUiThread {
                if (json.trimStart().startsWith("{")) {
                    toast(runCatching { org.json.JSONObject(json).optString("error") }.getOrDefault(json))
                } else {
                    store.putString(LOGIN_TYPES_CACHE, json)
                    applyLoginTypes(json)
                    JSONArray(json).length().let { toast(resources.getQuantityString(R.plurals.status_loaded, it, it)) }
                }
            }
        }.start()
    }

    private fun applyLoginTypes(json: String?) {
        val pref = findPreference<ListPreference>("login-type") ?: return
        val arr = json?.let { runCatching { JSONArray(it) }.getOrNull() }
        if (arr == null || arr.length() == 0) {
            val current = pref.value?.takeIf { it.isNotBlank() }
            pref.entries = listOfNotNull(current).toTypedArray()
            pref.entryValues = listOfNotNull(current).toTypedArray()
            loginFactors = emptyMap()
        } else {
            val ids = mutableListOf<String>()
            val labels = mutableListOf<String>()
            val factors = mutableMapOf<String, String>()
            for (i in 0 until arr.length()) {
                val o = arr.getJSONObject(i)
                ids += o.getString("id")
                labels += "${o.getString("name")} (${o.getString("factors")})"
                factors[o.getString("id")] = o.getString("factors")
            }
            pref.entries = labels.toTypedArray()
            pref.entryValues = ids.toTypedArray()
            loginFactors = factors
        }
        updateCredentialVisibility(pref.value)
    }

    /** Username/password only matter for login types with a password factor; SSO types don't use them. */
    private fun updateCredentialVisibility(loginType: String?) {
        val factors = loginType?.let { loginFactors[it] }
        val visible = factors == null || "password" in factors
        for (key in CREDENTIALS) findPreference<Preference>(key)?.isVisible = visible
    }

    private fun onFileClick(pref: Preference) {
        val key = pref.key
        if (store.getString(key, null).isNullOrBlank()) {
            launchPicker(key)
            return
        }
        AlertDialog.Builder(requireContext())
            .setTitle(pref.title)
            .setItems(arrayOf(getString(R.string.file_choose), getString(R.string.file_remove))) { _, which ->
                if (which == 0) {
                    launchPicker(key)
                } else {
                    store.getString(key, null)?.let { File(it).delete() }
                    store.putString(key, "")
                    updateFileSummary(pref)
                }
            }
            .show()
    }

    private fun launchPicker(key: String) {
        pendingFileKey = key
        pickFile.launch(arrayOf("*/*"))
    }

    /** Copies the picked document into the profile's private directory; the native side reads it by path. */
    private fun onFilePicked(uri: Uri) {
        val key = pendingFileKey ?: return
        val ctx = requireContext()
        val name = ctx.contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)?.use {
            if (it.moveToFirst()) it.getString(0) else null
        } ?: key
        val dest = File(Profiles.filesDir(ctx, profileId), "$key-$name")
        try {
            ctx.contentResolver.openInputStream(uri)!!.use { input -> dest.outputStream().use { input.copyTo(it) } }
            store.getString(key, null)?.takeIf { it != dest.absolutePath }?.let { File(it).delete() }
            store.putString(key, dest.absolutePath)
        } catch (e: Exception) {
            toast(e.message ?: e.toString())
        }
        findPreference<Preference>(key)?.let { updateFileSummary(it) }
    }

    private fun updateFileSummary(pref: Preference) {
        val path = store.getString(pref.key, null)
        pref.summary = if (path.isNullOrBlank()) getString(R.string.value_not_set) else File(path).name.removePrefix("${pref.key}-")
    }

    private fun toast(text: String) = Toast.makeText(requireContext(), text, Toast.LENGTH_SHORT).show()
}
