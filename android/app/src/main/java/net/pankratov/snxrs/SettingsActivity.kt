package net.pankratov.snxrs

import android.os.Bundle
import android.widget.FrameLayout
import androidx.appcompat.app.AppCompatActivity

/** Hosts [ProfileSettingsFragment] for one profile. */
class SettingsActivity : AppCompatActivity() {

    companion object {
        const val EXTRA_PROFILE_ID = "profile_id"
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val id = intent.getStringExtra(EXTRA_PROFILE_ID) ?: return finish()
        val container = FrameLayout(this).apply { this.id = R.id.settings_container }
        setContentView(container)
        if (savedInstanceState == null) {
            supportFragmentManager.beginTransaction()
                .replace(R.id.settings_container, ProfileSettingsFragment.newInstance(id))
                .commit()
        }
    }
}
