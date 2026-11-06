package net.pankratov.snxrs

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.os.Handler
import android.os.Looper

/**
 * Follows the network that protected sockets leave through. A VPN app's own default network is its
 * VPN, so this watches the non-VPN networks and picks the one Android would prefer: validated, then
 * not cellular. Changes are debounced because Wi-Fi joins before it validates.
 *
 * `switched` compares with the last network that was online, so a short offline gap still counts.
 */
class NetworkMonitor(
    context: Context,
    private val onChange: (network: Network?, switched: Boolean) -> Unit,
) {
    private val cm = context.getSystemService(ConnectivityManager::class.java)
    private val main = Handler(Looper.getMainLooper())
    private val networks = LinkedHashMap<Network, NetworkCapabilities>()
    private var current: Network? = null
    private var lastOnline: Network? = null
    private var pending: Runnable? = null

    private val callback = object : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(network: Network) {
            cm.getNetworkCapabilities(network)?.let { main.post { update(network, it) } }
        }

        override fun onCapabilitiesChanged(network: Network, caps: NetworkCapabilities) {
            main.post { update(network, caps) }
        }

        override fun onLost(network: Network) {
            main.post {
                networks.remove(network)
                reevaluate()
            }
        }
    }

    fun start() {
        val request = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
            .build()
        cm.registerNetworkCallback(request, callback)
    }

    fun stop() {
        runCatching { cm.unregisterNetworkCallback(callback) }
        main.post {
            pending?.let { main.removeCallbacks(it) }
            pending = null
            networks.clear()
            current = null
            lastOnline = null
        }
    }

    private fun update(network: Network, caps: NetworkCapabilities) {
        networks[network] = caps
        reevaluate()
    }

    private fun reevaluate() {
        val best = networks.entries.minByOrNull { (_, caps) ->
            val unvalidated = if (caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)) 0 else 2
            val cellular = if (caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)) 1 else 0
            unvalidated + cellular
        }?.key
        pending?.let { main.removeCallbacks(it) }
        pending = Runnable {
            pending = null
            if (best != current) {
                val switched = best != null && lastOnline != null && best != lastOnline
                current = best
                if (best != null) lastOnline = best
                onChange(best, switched)
            }
        }.also { main.postDelayed(it, if (best == null) 0 else 1500) }
    }
}
