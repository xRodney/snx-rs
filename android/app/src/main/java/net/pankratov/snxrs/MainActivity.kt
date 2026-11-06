package net.pankratov.snxrs

import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.view.View
import android.widget.AdapterView
import android.widget.ArrayAdapter
import android.widget.Button
import android.widget.EditText
import android.widget.Spinner
import android.widget.TextView
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity

/** Profile picker plus connect/disconnect. Profile options are edited in [SettingsActivity]. */
class MainActivity : AppCompatActivity() {

    private lateinit var profileSpinner: Spinner
    private lateinit var connectionState: TextView
    private var profiles: List<Profiles.Profile> = emptyList()
    private var pendingProfileId: String? = null

    private val prepareLauncher =
        registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
            val id = pendingProfileId
            if (result.resultCode == RESULT_OK && id != null) startVpn(id)
        }

    private val notifyLauncher =
        registerForActivityResult(ActivityResultContracts.RequestPermission()) { }

    private val stateListener: (String) -> Unit = { connectionState.text = it }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        profileSpinner = findViewById(R.id.profile)
        connectionState = findViewById(R.id.connection_state)

        profileSpinner.onItemSelectedListener = object : AdapterView.OnItemSelectedListener {
            override fun onItemSelected(parent: AdapterView<*>?, view: View?, position: Int, id: Long) {
                Profiles.setSelected(this@MainActivity, profiles.getOrNull(position)?.id)
            }

            override fun onNothingSelected(parent: AdapterView<*>?) {}
        }

        findViewById<Button>(R.id.edit_profile).setOnClickListener { selected()?.let { openSettings(it.id) } ?: toast(R.string.profile_none) }
        findViewById<Button>(R.id.new_profile).setOnClickListener { promptNewProfile() }
        findViewById<Button>(R.id.delete_profile).setOnClickListener { confirmDelete() }
        findViewById<Button>(R.id.connect).setOnClickListener { onConnect() }
        findViewById<Button>(R.id.disconnect).setOnClickListener { onDisconnect() }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            notifyLauncher.launch(android.Manifest.permission.POST_NOTIFICATIONS)
        }
    }

    override fun onStart() {
        super.onStart()
        ConnectionState.observe(stateListener)
    }

    override fun onResume() {
        super.onResume()
        refreshProfiles()
    }

    override fun onStop() {
        ConnectionState.remove(stateListener)
        super.onStop()
    }

    private fun refreshProfiles() {
        profiles = Profiles.list(this)
        profileSpinner.adapter = ArrayAdapter(this, android.R.layout.simple_spinner_dropdown_item, profiles.map { it.name })
        val selected = Profiles.selected(this)
        profiles.indexOfFirst { it.id == selected }.takeIf { it >= 0 }?.let { profileSpinner.setSelection(it) }
    }

    private fun selected(): Profiles.Profile? = profiles.getOrNull(profileSpinner.selectedItemPosition)

    private fun openSettings(id: String) {
        startActivity(Intent(this, SettingsActivity::class.java).putExtra(SettingsActivity.EXTRA_PROFILE_ID, id))
    }

    private fun promptNewProfile() {
        val input = EditText(this).apply { hint = getString(R.string.profile_name_hint) }
        AlertDialog.Builder(this)
            .setTitle(R.string.profile_new_title)
            .setView(input)
            .setPositiveButton(android.R.string.ok) { _, _ ->
                val name = input.text.toString().trim().ifEmpty { getString(R.string.profile_unnamed) }
                val id = Profiles.create(this, name)
                Profiles.setSelected(this, id)
                openSettings(id)
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    private fun confirmDelete() {
        val profile = selected() ?: return toast(R.string.profile_none)
        AlertDialog.Builder(this)
            .setMessage(getString(R.string.profile_delete_confirm, profile.name))
            .setPositiveButton(R.string.label_delete) { _, _ ->
                Profiles.delete(this, profile.id)
                refreshProfiles()
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    private fun onConnect() {
        val profile = selected() ?: return toast(R.string.profile_none)
        val prefs = Profiles.prefs(this, profile.id)
        if (prefs.getString("server-name", null).isNullOrBlank() || prefs.getString("login-type", null).isNullOrBlank()) {
            toast(R.string.profile_incomplete)
            openSettings(profile.id)
            return
        }
        pendingProfileId = profile.id
        val consent = VpnService.prepare(this)
        if (consent != null) prepareLauncher.launch(consent) else startVpn(profile.id)
    }

    private fun startVpn(profileId: String) {
        val intent = Intent(this, VpnClientService::class.java)
            .setAction(VpnClientService.ACTION_CONNECT)
            .putExtra(VpnClientService.EXTRA_CONFIG, Profiles.configText(this, profileId))
        startForegroundService(intent)
    }

    private fun onDisconnect() {
        startService(Intent(this, VpnClientService::class.java).setAction(VpnClientService.ACTION_DISCONNECT))
    }

    private fun toast(res: Int) = Toast.makeText(this, res, Toast.LENGTH_SHORT).show()
}
