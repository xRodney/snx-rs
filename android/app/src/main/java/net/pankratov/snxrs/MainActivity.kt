package net.pankratov.snxrs

import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.widget.Button
import android.widget.CheckBox
import android.widget.EditText
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import org.json.JSONObject

/**
 * Minimal connect/disconnect UI. Collects the gateway, login type and credentials, runs the
 * VpnService consent flow, then starts [VpnClientService]. This is a bring-up UI, not a finished one.
 */
class MainActivity : AppCompatActivity() {

    private lateinit var server: EditText
    private lateinit var loginType: EditText
    private lateinit var username: EditText
    private lateinit var password: EditText
    private lateinit var ignoreCert: CheckBox

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

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            notifyLauncher.launch(android.Manifest.permission.POST_NOTIFICATIONS)
        }

        findViewById<Button>(R.id.connect).setOnClickListener { onConnect() }
        findViewById<Button>(R.id.disconnect).setOnClickListener { onDisconnect() }
    }

    private fun onConnect() {
        val consent = VpnService.prepare(this)
        if (consent != null) prepareLauncher.launch(consent) else startVpn()
    }

    private fun startVpn() {
        val config = JSONObject()
            .put("server_name", server.text.toString().trim())
            .put("login_type", loginType.text.toString().trim())
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
