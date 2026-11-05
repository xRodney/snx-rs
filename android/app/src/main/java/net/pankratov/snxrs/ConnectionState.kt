package net.pankratov.snxrs

import android.os.Handler
import android.os.Looper
import java.util.concurrent.CopyOnWriteArraySet

/** Connection status shared between [VpnClientService] (writer) and [MainActivity] (observer). */
object ConnectionState {
    @Volatile
    var text: String = ""
        private set

    private val listeners = CopyOnWriteArraySet<(String) -> Unit>()
    private val main = Handler(Looper.getMainLooper())

    fun update(value: String) {
        text = value
        main.post { listeners.forEach { it(value) } }
    }

    fun observe(listener: (String) -> Unit) {
        listeners += listener
        listener(text)
    }

    fun remove(listener: (String) -> Unit) {
        listeners -= listener
    }
}
