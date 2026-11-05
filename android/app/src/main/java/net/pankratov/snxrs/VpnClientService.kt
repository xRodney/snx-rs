package net.pankratov.snxrs

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.provider.Settings
import android.system.OsConstants
import android.util.Log
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import org.json.JSONObject

/**
 * Android VpnService hosting the snx-rs Rust core (libsnxrs.so, from the apps/snxrs-android cdylib).
 *
 * Java -> Rust: [nativeConnect] / [nativeDisconnect] start/stop the tokio runtime + tunnel. The
 * controller runs the IPsec userspace ESP path (snxcore's ipsec_native = false), so no root is used.
 *
 * Rust -> Java (via the Rust VpnServiceHandle): [establishTun] builds the tunnel and returns its fd,
 * [protectSocket] keeps gateway sockets off the tunnel, [androidId]/[keystore*] back machine-id and
 * password storage.
 */
class VpnClientService : VpnService() {

    companion object {
        private const val TAG = "snx-rs"
        private const val CHANNEL_ID = "snx-rs-vpn"
        private const val NOTIFICATION_ID = 1

        const val ACTION_CONNECT = "net.pankratov.snxrs.CONNECT"
        const val ACTION_DISCONNECT = "net.pankratov.snxrs.DISCONNECT"
        const val EXTRA_CONFIG_JSON = "config_json"

        init {
            System.loadLibrary("snxrs")
        }
    }

    private var tunInterface: ParcelFileDescriptor? = null
    private var worker: Thread? = null

    // Implemented in apps/snxrs-android (Java_net_pankratov_snxrs_VpnClientService_*).
    private external fun nativeConnect(configJson: String): Int
    private external fun nativeDisconnect()

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_CONNECT -> {
                if (worker?.isAlive == true) {
                    Log.w(TAG, "Connect ignored: a connection attempt is already running")
                    return START_STICKY
                }
                val configJson = intent.getStringExtra(EXTRA_CONFIG_JSON) ?: "{}"
                startForeground(NOTIFICATION_ID, buildNotification("Connecting…"))
                worker = Thread {
                    val rc = nativeConnect(configJson)
                    Log.i(TAG, "nativeConnect returned $rc")
                    cleanup()
                    stopSelf()
                }.also { it.start() }
            }
            ACTION_DISCONNECT -> {
                nativeDisconnect()
            }
        }
        return START_STICKY
    }

    /**
     * Called from Rust. `configJson` = {address, prefix, mtu, routes[], dns_servers[], search_domains[]}.
     * Builds the tunnel and returns the raw fd (ownership transferred via detachFd), or -1 on failure.
     */
    fun establishTun(configJson: String): Int {
        return try {
            val cfg = JSONObject(configJson)
            val builder = Builder().apply {
                setSession("snx-rs")
                // The tunnel carries IPv4 only; without this Android blackholes all IPv6 while connected.
                allowFamily(OsConstants.AF_INET6)
                setMtu(cfg.optInt("mtu", 1400))
                addAddress(cfg.getString("address"), cfg.getInt("prefix"))

                val routes = cfg.optJSONArray("routes")
                if (routes == null || routes.length() == 0) {
                    addRoute("0.0.0.0", 0)
                } else {
                    for (i in 0 until routes.length()) {
                        val (addr, prefix) = routes.getString(i).split("/")
                        addRoute(addr, prefix.toInt())
                    }
                }

                cfg.optJSONArray("dns_servers")?.let { for (i in 0 until it.length()) addDnsServer(it.getString(i)) }
                cfg.optJSONArray("search_domains")?.let { for (i in 0 until it.length()) addSearchDomain(it.getString(i)) }
            }
            val pfd = builder.establish() ?: return -1
            tunInterface = pfd
            updateNotification("Connected")
            pfd.detachFd()
        } catch (e: Exception) {
            Log.e(TAG, "establishTun failed", e)
            -1
        }
    }

    fun protectSocket(fd: Int): Boolean = protect(fd)

    /** Called from Rust for identity-provider (SSO) login: show the gateway's sign-in page in [SsoActivity]. */
    fun openUrl(url: String) {
        updateNotification("Waiting for browser sign-in…")
        startActivity(
            Intent(this, SsoActivity::class.java)
                .putExtra(SsoActivity.EXTRA_URL, url)
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
        )
    }

    fun androidId(): String =
        Settings.Secure.getString(contentResolver, Settings.Secure.ANDROID_ID) ?: "unknown"

    fun keystoreGet(key: String): String? = securePrefs().getString(key, null)
    fun keystoreSet(key: String, value: String) = securePrefs().edit().putString(key, value).apply()
    fun keystoreDelete(key: String) = securePrefs().edit().remove(key).apply()

    private fun securePrefs() = EncryptedSharedPreferences.create(
        this,
        "snx-rs-secure",
        MasterKey.Builder(this).setKeyScheme(MasterKey.KeyScheme.AES256_GCM).build(),
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
    )

    private fun buildNotification(text: String): Notification {
        val mgr = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            mgr.createNotificationChannel(
                NotificationChannel(CHANNEL_ID, "VPN", NotificationManager.IMPORTANCE_LOW),
            )
        }
        val pi = PendingIntent.getActivity(
            this, 0, Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE,
        )
        return Notification.Builder(this, CHANNEL_ID)
            .setContentTitle(getString(R.string.app_name))
            .setContentText(text)
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentIntent(pi)
            .setOngoing(true)
            .build()
    }

    private fun updateNotification(text: String) {
        val mgr = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        mgr.notify(NOTIFICATION_ID, buildNotification(text))
    }

    private fun cleanup() {
        tunInterface?.close()
        tunInterface = null
    }

    override fun onDestroy() {
        nativeDisconnect()
        cleanup()
        super.onDestroy()
    }
}
