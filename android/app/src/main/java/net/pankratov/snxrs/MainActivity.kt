package net.pankratov.snxrs

import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.view.View
import android.widget.AdapterView
import android.widget.ArrayAdapter
import android.widget.Button
import android.widget.CheckBox
import android.widget.EditText
import android.widget.Spinner
import android.widget.TextView
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import org.json.JSONArray
import org.json.JSONObject

/**
 * Minimal connect/disconnect UI. The login type is picked from the list the gateway reports, then the
 * VpnService consent flow runs and [VpnClientService] is started. A bring-up UI, not a finished one.
 */
class MainActivity : AppCompatActivity() {

    companion object {
        init {
            System.loadLibrary("snxrs")
        }
    }

    /** Implemented in apps/snxrs-android; JSON array of {id, name, factors} or {"error": ...}. Blocking. */
    private external fun nativeLoginTypes(server: String, ignoreCert: Boolean): String

    private lateinit var server: EditText
    private lateinit var loginType: Spinner
    private lateinit var username: EditText
    private lateinit var password: EditText
    private lateinit var ignoreCert: CheckBox
    private lateinit var status: TextView
    private lateinit var connectionState: TextView

    private var loginTypeIds: List<String> = emptyList()
    private var loginTypeFactors: List<String> = emptyList()

    private val stateListener: (String) -> Unit = { connectionState.text = it }

    override fun onStart() {
        super.onStart()
        ConnectionState.observe(stateListener)
    }

    override fun onStop() {
        ConnectionState.remove(stateListener)
        super.onStop()
    }

    private val prefs by lazy { getSharedPreferences("form", MODE_PRIVATE) }

    private val prepareLauncher =
        registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
            if (result.resultCode == RESULT_OK) startVpn()
        }

    private val notifyLauncher =
        registerForActivityResult(ActivityResultContracts.RequestPermission()) { }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        server = findViewById(R.id.server)
        loginType = findViewById(R.id.login_type)
        username = findViewById(R.id.username)
        password = findViewById(R.id.password)
        ignoreCert = findViewById(R.id.ignore_cert)
        status = findViewById(R.id.status)
        connectionState = findViewById(R.id.connection_state)

        prefs.getString("server", null)?.let { server.setText(it) }
        prefs.getString("username", null)?.let { username.setText(it) }
        ignoreCert.isChecked = prefs.getBoolean("ignore_cert", false)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            notifyLauncher.launch(android.Manifest.permission.POST_NOTIFICATIONS)
        }

        loginType.onItemSelectedListener = object : AdapterView.OnItemSelectedListener {
            override fun onItemSelected(parent: AdapterView<*>?, view: View?, position: Int, id: Long) =
                updateCredentialFields()

            override fun onNothingSelected(parent: AdapterView<*>?) = updateCredentialFields()
        }
        updateCredentialFields()

        findViewById<Button>(R.id.load_login_types).setOnClickListener { loadLoginTypes() }
        findViewById<Button>(R.id.connect).setOnClickListener { onConnect() }
        findViewById<Button>(R.id.disconnect).setOnClickListener { onDisconnect() }

        if (server.text.isNotBlank()) loadLoginTypes()
    }

    private fun loadLoginTypes() {
        val host = server.text.toString().trim()
        if (host.isEmpty()) {
            status.text = getString(R.string.status_enter_server)
            return
        }
        status.text = getString(R.string.status_loading)
        val ignore = ignoreCert.isChecked
        Thread {
            val json = nativeLoginTypes(host, ignore)
            runOnUiThread { showLoginTypes(json) }
        }.start()
    }

    private fun showLoginTypes(json: String) {
        if (json.trimStart().startsWith("{")) {
            status.text = JSONObject(json).optString("error", json)
            return
        }
        val arr = JSONArray(json)
        val ids = mutableListOf<String>()
        val factors = mutableListOf<String>()
        val labels = mutableListOf<String>()
        for (i in 0 until arr.length()) {
            val o = arr.getJSONObject(i)
            ids += o.getString("id")
            factors += o.getString("factors")
            labels += "${o.getString("name")} (${o.getString("factors")})"
        }
        loginTypeIds = ids
        loginTypeFactors = factors
        loginType.adapter = ArrayAdapter(this, android.R.layout.simple_spinner_dropdown_item, labels)
        val saved = prefs.getString("login_type", null)
        ids.indexOf(saved).takeIf { it >= 0 }?.let { loginType.setSelection(it) }
        status.text = getString(R.string.status_loaded, ids.size)
    }

    private fun selectedLoginType(): String? = loginTypeIds.getOrNull(loginType.selectedItemPosition)

    /** Username/password only matter for login types with a password factor; SSO types don't use them. */
    private fun updateCredentialFields() {
        val factors = loginTypeFactors.getOrNull(loginType.selectedItemPosition)
        val visibility = if (factors == null || "password" in factors) View.VISIBLE else View.GONE
        username.visibility = visibility
        password.visibility = visibility
    }

    private fun onConnect() {
        if (selectedLoginType() == null) {
            status.text = getString(R.string.status_pick_login_type)
            return
        }
        prefs.edit()
            .putString("server", server.text.toString().trim())
            .putString("login_type", selectedLoginType())
            .putString("username", username.text.toString().trim())
            .putBoolean("ignore_cert", ignoreCert.isChecked)
            .apply()

        val consent = VpnService.prepare(this)
        if (consent != null) prepareLauncher.launch(consent) else startVpn()
    }

    private fun startVpn() {
        val config = JSONObject()
            .put("server_name", server.text.toString().trim())
            .put("login_type", selectedLoginType())
            .put("user_name", username.text.toString().trim())
            .put("password", password.text.toString())
            .put("ignore_server_cert", ignoreCert.isChecked)
            .put("tunnel_type", "ipsec")
            .toString()

        val intent = Intent(this, VpnClientService::class.java)
            .setAction(VpnClientService.ACTION_CONNECT)
            .putExtra(VpnClientService.EXTRA_CONFIG_JSON, config)
        startForegroundService(intent)
    }

    private fun onDisconnect() {
        startService(Intent(this, VpnClientService::class.java).setAction(VpnClientService.ACTION_DISCONNECT))
    }
}
