package dev.fzer0x.imsicatcherdetector2.ui

import android.app.Activity
import android.os.Build
import android.os.Bundle
import android.view.WindowManager
import android.widget.Button
import android.widget.TextView
import dev.fzer0x.imsicatcherdetector2.R

class AlertActivity : Activity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        
        // Make it show over lockscreen and keep screen on
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O_MR1) {
            setShowWhenLocked(true)
            setTurnScreenOn(true)
        } else {
            window.addFlags(
                WindowManager.LayoutParams.FLAG_SHOW_WHEN_LOCKED or
                        WindowManager.LayoutParams.FLAG_TURN_SCREEN_ON or
                        WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON or
                        WindowManager.LayoutParams.FLAG_DISMISS_KEYGUARD
            )
        }

        setContentView(R.layout.activity_alert)

        val title = intent.getStringExtra("title") ?: "SECURITY ALERT"
        val description = intent.getStringExtra("description") ?: "Threat Detected"
        val severity = intent.getIntExtra("severity", 10)

        findViewById<TextView>(R.id.alertTitle).text = title
        findViewById<TextView>(R.id.alertDescription).text = description
        findViewById<TextView>(R.id.alertSeverity).text = "SEVERITY: $severity/10"

        findViewById<Button>(R.id.dismissButton).setOnClickListener {
            finish()
        }
    }
}
