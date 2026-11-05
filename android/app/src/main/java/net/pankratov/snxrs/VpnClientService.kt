package net.pankratov.snxrs

import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.util.Log

/**
 * Android VpnService that hosts the snx-rs Rust core.
 *
 * The Rust core never touches the Android networking APIs directly. Instead:
 *
 *  - Java -> Rust: [nativeConnect] / [nativeDisconnect] start and stop the tokio runtime + tunnel
 *    controller inside libsnxrs.so.
 *  - Rust -> Java: the core calls back into [establishTun] (to build the interface and hand back an
 *    fd) and [protectSocket] (so gateway sockets bypass the tunnel). These are invoked from the Rust
 *    `VpnServiceHandle` over JNI.
 *
 * This is the inversion that makes the desktop core fit Android: addresses/routes/DNS/MTU are
 * declared on [VpnService.Builder] *before* establish() returns the fd, rather than applied after.
 */
class VpnClientService : VpnService() {

    companion object {
        private const val TAG = "snx-rs"

        init {
            System.loadLibrary("snxrs")
        }
    }

    private var tunInterface: ParcelFileDescriptor? = null

    // --- native methods implemented in platform/android/jni_bridge.rs ---
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
     * config the core negotiated and returns the raw fd. Returns -1 on failure.
     *
     * @param addressCidr office-mode address as "a.b.c.d/prefix"
     * @param mtu         interface MTU
     * @param routes      destination routes as "a.b.c.d/prefix"; empty => full tunnel ("0.0.0.0/0")
     * @param dnsServers  DNS server IPv4 addresses
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
                setMtu(mtu)
                setSession("snx-rs")

                val (addr, prefix) = addressCidr.split("/").let { it[0] to it[1].toInt() }
                addAddress(addr, prefix)

                if (routes.isEmpty()) {
                    addRoute("0.0.0.0", 0) // full tunnel
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
            // detachFd() transfers ownership to the Rust side, which closes it on teardown.
            pfd.detachFd()
        } catch (e: Exception) {
            Log.e(TAG, "establishTun failed", e)
            -1
        }
    }

    /**
     * Called from Rust before each gateway socket connects. Keeps the gateway-bound TLS/UDP socket
     * off the tunnel so traffic to the VPN server is not routed back into the VPN.
     */
    fun protectSocket(fd: Int): Boolean = protect(fd)

    // --- Android Keystore access for platform/android/keychain.rs (sketch) ---
    fun keystoreGet(key: String): String? = SecurePrefs.get(this, key)
    fun keystoreSet(key: String, value: String) = SecurePrefs.set(this, key, value)

    private fun startForegroundNotification() {
        // TODO: create a NotificationChannel and call startForeground(...) — a VpnService must run
        // in the foreground on modern Android.
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

/** Placeholder for EncryptedSharedPreferences-backed storage. */
private object SecurePrefs {
    fun get(service: VpnService, key: String): String? = TODO("EncryptedSharedPreferences")
    fun set(service: VpnService, key: String, value: String): Unit = TODO("EncryptedSharedPreferences")
}

const val ACTION_CONNECT = "net.pankratov.snxrs.CONNECT"
const val ACTION_DISCONNECT = "net.pankratov.snxrs.DISCONNECT"
const val EXTRA_CONFIG_JSON = "config_json"
