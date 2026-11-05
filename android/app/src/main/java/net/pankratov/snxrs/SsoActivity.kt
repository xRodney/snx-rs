package net.pankratov.snxrs

import android.annotation.SuppressLint
import android.net.Uri
import android.os.Bundle
import android.util.Log
import android.webkit.CookieManager
import android.webkit.WebResourceRequest
import android.webkit.WebResourceResponse
import android.webkit.WebView
import android.webkit.WebViewClient
import androidx.appcompat.app.AppCompatActivity
import java.io.ByteArrayInputStream
import java.net.HttpURLConnection
import java.net.URL

/**
 * Hosts the gateway's identity-provider sign-in page. At the end of the flow the page hands the OTP to
 * `http://127.0.0.1:7779/<otp>`, where snxcore's OtpListener waits. External browsers may block a
 * public site from reaching localhost (Brave, Chrome's local network access), so the request is
 * intercepted here and forwarded to the listener from the app itself.
 */
class SsoActivity : AppCompatActivity() {

    companion object {
        const val EXTRA_URL = "url"
        private const val TAG = "snx-rs"
        private const val OTP_HOST = "127.0.0.1"
        private const val OTP_PORT = 7779
    }

    @Volatile
    private var delivered = false

    @SuppressLint("SetJavaScriptEnabled")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val url = intent.getStringExtra(EXTRA_URL) ?: return finish()

        val web = WebView(this)
        setContentView(web)
        web.settings.javaScriptEnabled = true
        web.settings.domStorageEnabled = true
        CookieManager.getInstance().setAcceptThirdPartyCookies(web, true)

        web.webViewClient = object : WebViewClient() {
            override fun shouldInterceptRequest(view: WebView, request: WebResourceRequest): WebResourceResponse? {
                if (!isOtpUrl(request.url)) return null
                forwardOtp(request.url)
                return WebResourceResponse("text/plain", "utf-8", 200, "OK", corsHeaders(), ByteArrayInputStream(ByteArray(0)))
            }

            override fun shouldOverrideUrlLoading(view: WebView, request: WebResourceRequest): Boolean {
                if (!isOtpUrl(request.url)) return false
                Thread { forwardOtp(request.url) }.start()
                return true
            }
        }
        web.loadUrl(url)
    }

    private fun isOtpUrl(uri: Uri): Boolean =
        (uri.host == OTP_HOST || uri.host == "localhost") && uri.port == OTP_PORT

    private fun corsHeaders() = mapOf(
        "Access-Control-Allow-Origin" to "*",
        "Access-Control-Allow-Methods" to "GET, OPTIONS",
    )

    /** Runs off the UI thread (shouldInterceptRequest is called on a WebView worker thread). */
    private fun forwardOtp(uri: Uri) {
        val path = uri.path?.trimStart('/').orEmpty()
        if (path.isEmpty() || delivered) return
        try {
            val conn = URL("http://$OTP_HOST:$OTP_PORT/$path").openConnection() as HttpURLConnection
            conn.connectTimeout = 5000
            conn.readTimeout = 5000
            Log.i(TAG, "SSO: forwarding OTP to listener, HTTP ${conn.responseCode}")
            conn.disconnect()
            delivered = true
            runOnUiThread { finish() }
        } catch (e: Exception) {
            Log.e(TAG, "SSO: forwarding OTP failed", e)
        }
    }
}
