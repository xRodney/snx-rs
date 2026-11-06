package net.pankratov.snxrs

import android.annotation.SuppressLint
import android.net.Uri
import android.os.Bundle
import android.os.Message
import android.util.Log
import android.view.ViewGroup
import android.webkit.CookieManager
import android.webkit.WebChromeClient
import android.webkit.WebResourceRequest
import android.webkit.WebResourceResponse
import android.webkit.WebView
import android.webkit.WebViewClient
import android.widget.FrameLayout
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

    private lateinit var container: FrameLayout

    private val client: WebViewClient = object : WebViewClient() {
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

    // The sign-in page opens a second window (window.open) that completes the hand-off, so popups are
    // created as stacked WebViews sharing the same interception.
    private val chrome: WebChromeClient = object : WebChromeClient() {
        override fun onCreateWindow(view: WebView, isDialog: Boolean, isUserGesture: Boolean, resultMsg: Message): Boolean {
            Log.i(TAG, "SSO: page opened a popup window")
            val popup = newWebView()
            container.addView(popup)
            (resultMsg.obj as WebView.WebViewTransport).webView = popup
            resultMsg.sendToTarget()
            return true
        }

        override fun onCloseWindow(window: WebView) {
            Log.i(TAG, "SSO: popup window closed")
            container.removeView(window)
            window.destroy()
        }
    }

    @SuppressLint("SetJavaScriptEnabled")
    private fun newWebView(): WebView = WebView(this).apply {
        layoutParams = FrameLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT)
        settings.javaScriptEnabled = true
        settings.domStorageEnabled = true
        settings.setSupportMultipleWindows(true)
        settings.javaScriptCanOpenWindowsAutomatically = true
        CookieManager.getInstance().setAcceptThirdPartyCookies(this, true)
        webViewClient = client
        webChromeClient = chrome
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val url = intent.getStringExtra(EXTRA_URL) ?: return finish()

        container = FrameLayout(this)
        setContentView(container)
        val main = newWebView()
        container.addView(main)
        main.loadUrl(url)
    }

    @Deprecated("Back navigates within the sign-in pages before leaving")
    override fun onBackPressed() {
        val top = container.getChildAt(container.childCount - 1) as? WebView
        when {
            top != null && top.canGoBack() -> top.goBack()
            container.childCount > 1 && top != null -> { container.removeView(top); top.destroy() }
            else -> super.onBackPressed()
        }
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
