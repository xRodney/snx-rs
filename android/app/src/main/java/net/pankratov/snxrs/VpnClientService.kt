package net.pankratov.snxrs

import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.util.Log

/**
 * Android VpnService that hosts the snx-rs Rust core (libsnxrs.so, built from the
 * apps/snxrs-android cdylib wrapper around snxcore + the `android-jni` feature).
 *
 * Java -> Rust: [nativeConnect] / [nativeDisconnect] start and stop the tokio runtime + connection
 * controller. The controller drives the IPsec tunnel over the **userspace ESP data path** (snxcore's
 * `ipsec_native = false` forces it), so no root/XFRM is involved.
 *
 * Rust -> Java (via the `VpnServiceHandle` in platform/android/jni_bridge.rs):
 *  - [establishTun]: build the interface with VpnService.Builder and return its fd. This is the
 *    inversion that makes the desktop core fit Android — address/routes/DNS/MTU are declared here,
 *    before establish(), instead of being applied to a device the core created.
 *  - [protectSocket]: VpnService.protect() so gateway sockets bypass the tunnel.
 *  - [androidId] / [keystore*]: machine id and password storage.
 */
class VpnClientService : VpnService() {

    companion object {
        private const val TAG = "snx-rs"

        init {
            System.loadLibrary("snxrs")
        }
    }

    private var tunInterface: ParcelFileDescriptor? = null

    // --- native methods implemented in platform/android/jni_bridge.rs (feature android-jni) ---
    private external fun nativeConnect(service: VpnClientService, configJson: String): Int
    private external fun nativeDisconnect()

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_CONNECT -> {
                val configJson = intent.getStringExtra(EXTRA_CONFIG_JSON) ?: "{}"
                startForegroundNotification()
                Thread { nativeConnect(this, configJson) }.start()
            }
            ACTION_DISCONNECT -> {
                nativeDisconnect()
                cleanup()
                stopSelf()
            }
        }
        return START_STICKY
    }

    /**
     * Called from Rust (`VpnServiceHandle::establish_tun`). Builds the tunnel interface from the
     * config the core negotiated (office-mode address, pushed routes, DNS) and returns the raw fd.
     * Returns -1 on failure.
     *
     * @param addressCidr   office-mode address as "a.b.c.d/prefix"
     * @param mtu           interface MTU
     * @param routes        destination routes "a.b.c.d/prefix"; empty => full tunnel ("0.0.0.0/0")
     * @param dnsServers    DNS server IPv4 addresses
     * @param searchDomains DNS search domains
     */
    fun establishTun(
        addressCidr: String,
        mtu: Int,
        routes: Array<String>,
        dnsServers: Array<String>,
        searchDomains: Array<String>,
    ): Int {
        return try {
            val builder = Builder().apply {
                setSession("snx-rs")
                setMtu(mtu)

                val (addr, prefix) = addressCidr.split("/").let { it[0] to it[1].toInt() }
                addAddress(addr, prefix)

                if (routes.isEmpty()) {
                    addRoute("0.0.0.0", 0)
                } else {
                    for (r in routes) {
                        val (rAddr, rPrefix) = r.split("/").let { it[0] to it[1].toInt() }
                        addRoute(rAddr, rPrefix)
                    }
                }

                for (dns in dnsServers) addDnsServer(dns)
                for (dom in searchDomains) addSearchDomain(dom)
            }

            val pfd = builder.establish() ?: return -1
            tunInterface = pfd
            // detachFd() transfers ownership to Rust, which closes it on teardown (close_fd_on_drop).
            pfd.detachFd()
        } catch (e: Exception) {
            Log.e(TAG, "establishTun failed", e)
            -1
        }
    }

    /** Called from Rust before each gateway socket connects. */
    fun protectSocket(fd: Int): Boolean = protect(fd)

    // --- machine id + keychain for platform/android/{machine_uuid,keychain}.rs ---
    fun androidId(): String =
        android.provider.Settings.Secure.getString(contentResolver, android.provider.Settings.Secure.ANDROID_ID)

    fun keystoreGet(key: String): String? = SecurePrefs.get(this, key)
    fun keystoreSet(key: String, value: String) = SecurePrefs.set(this, key, value)
    fun keystoreDelete(key: String) = SecurePrefs.delete(this, key)

    private fun startForegroundNotification() {
        // TODO: NotificationChannel + startForeground(...) — a VpnService must run in the foreground.
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

/** Placeholder for EncryptedSharedPreferences-backed storage (androidx.security.crypto). */
private object SecurePrefs {
    fun get(service: VpnService, key: String): String? = TODO("EncryptedSharedPreferences")
    fun set(service: VpnService, key: String, value: String): Unit = TODO("EncryptedSharedPreferences")
    fun delete(service: VpnService, key: String): Unit = TODO("EncryptedSharedPreferences")
}

const val ACTION_CONNECT = "net.pankratov.snxrs.CONNECT"
const val ACTION_DISCONNECT = "net.pankratov.snxrs.DISCONNECT"
const val EXTRA_CONFIG_JSON = "config_json"
