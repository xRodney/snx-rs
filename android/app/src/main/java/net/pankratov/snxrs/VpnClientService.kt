package net.pankratov.snxrs

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.graphics.drawable.Icon
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.provider.Settings
import android.system.OsConstants
import android.util.Log
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import org.json.JSONObject

/** Runs the Rust core (libsnxrs.so); the public methods below are called from Rust over JNI. */
class VpnClientService : VpnService() {

    companion object {
        private const val TAG = "snx-rs"
        private const val CHANNEL_ID = "snx-rs-vpn"
        private const val NOTIFICATION_ID = 1

        const val ACTION_CONNECT = "net.pankratov.snxrs.CONNECT"
        const val ACTION_DISCONNECT = "net.pankratov.snxrs.DISCONNECT"
        const val EXTRA_CONFIG = "config"

        init {
            System.loadLibrary("snxrs")
        }
    }

    private var tunInterface: ParcelFileDescriptor? = null
    private var worker: Thread? = null
    private var networkMonitor: NetworkMonitor? = null

    /** Blocks until the user disconnects or the connection fails; returns "" or the error. */
    private external fun nativeConnect(config: String, filesDir: String): String
    private external fun nativeDisconnect()
    private external fun nativeSetOnline(online: Boolean)
    private external fun nativeNetworkChanged()

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_CONNECT -> {
                if (worker?.isAlive == true) {
                    Log.w(TAG, "Connect ignored: a connection attempt is already running")
                    return START_STICKY
                }
                val config = intent.getStringExtra(EXTRA_CONFIG) ?: ""
                ConnectionState.update(getString(R.string.state_connecting))
                startForeground(NOTIFICATION_ID, buildNotification(getString(R.string.state_connecting)))
                startNetworkMonitor()
                worker = Thread {
                    val error = nativeConnect(config, filesDir.absolutePath)
                    Log.i(TAG, "nativeConnect finished: ${error.ifEmpty { "ok" }}")
                    ConnectionState.update(
                        if (error.isEmpty()) getString(R.string.state_disconnected)
                        else getString(R.string.state_failed, error),
                    )
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

    /** `configJson`: {address, prefix, mtu, routes[], dns_servers[], search_domains[]}. Returns a detached fd or -1. */
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
            ConnectionState.update(getString(R.string.state_connected))
            updateNotification(getString(R.string.state_connected), connected = true)
            pfd.detachFd()
        } catch (e: Exception) {
            Log.e(TAG, "establishTun failed", e)
            -1
        }
    }

    fun protectSocket(fd: Int): Boolean = protect(fd)

    fun onReconnecting() {
        ConnectionState.update(getString(R.string.state_reconnecting))
        updateNotification(getString(R.string.state_reconnecting))
    }

    private fun startNetworkMonitor() {
        networkMonitor?.stop()
        networkMonitor = NetworkMonitor(this) { network, switched ->
            Log.i(TAG, "Underlying network: $network (switched: $switched)")
            setUnderlyingNetworks(network?.let { arrayOf(it) })
            nativeSetOnline(network != null)
            if (switched) nativeNetworkChanged()
        }.also { it.start() }
    }

    fun openUrl(url: String) {
        ConnectionState.update(getString(R.string.state_signin))
        updateNotification(getString(R.string.state_signin))
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

    private fun buildNotification(text: String, connected: Boolean = false): Notification {
        val mgr = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        mgr.createNotificationChannel(
            NotificationChannel(CHANNEL_ID, "VPN", NotificationManager.IMPORTANCE_LOW),
        )
        val pi = PendingIntent.getActivity(
            this, 0, Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE,
        )
        val disconnect = PendingIntent.getService(
            this, 1, Intent(this, VpnClientService::class.java).setAction(ACTION_DISCONNECT),
            PendingIntent.FLAG_IMMUTABLE,
        )
        return Notification.Builder(this, CHANNEL_ID)
            .setContentTitle(getString(R.string.app_name))
            .setContentText(text)
            .setSmallIcon(if (connected) R.drawable.ic_stat_connected else R.drawable.ic_stat_acquiring)
            .setContentIntent(pi)
            .setOngoing(true)
            .addAction(
                Notification.Action.Builder(
                    Icon.createWithResource(this, android.R.drawable.ic_menu_close_clear_cancel),
                    getString(R.string.label_disconnect),
                    disconnect,
                ).build(),
            )
            .build()
    }

    private fun updateNotification(text: String, connected: Boolean = false) {
        val mgr = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        mgr.notify(NOTIFICATION_ID, buildNotification(text, connected))
    }

    private fun cleanup() {
        networkMonitor?.stop()
        networkMonitor = null
        nativeSetOnline(true)
        tunInterface?.close()
        tunInterface = null
    }

    override fun onRevoke() {
        nativeDisconnect()
        super.onRevoke()
    }

    override fun onDestroy() {
        nativeDisconnect()
        cleanup()
        super.onDestroy()
    }
}
