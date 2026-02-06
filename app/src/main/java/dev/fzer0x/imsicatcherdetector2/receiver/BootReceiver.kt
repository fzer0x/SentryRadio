package dev.fzer0x.imsicatcherdetector2.receiver

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.os.Build
import android.util.Log
import dev.fzer0x.imsicatcherdetector2.service.ForensicService

class BootReceiver : BroadcastReceiver() {
    private val TAG = "BootReceiver"

    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action == Intent.ACTION_BOOT_COMPLETED || intent.action == "android.intent.action.LOCKED_BOOT_COMPLETED") {
            Log.d(TAG, "Boot completed - starting ForensicService immediately")

            // Aktiviere Security Settings sofort
            val prefs = context.getSharedPreferences("sentry_settings", Context.MODE_PRIVATE)
            prefs.edit()
                .putBoolean("block_gsm", true)
                .putBoolean("reject_a50", true)
                .putBoolean("mark_fake_cells", true)
                .putBoolean("force_lte", true)
                .apply()

            // Starte Service
            val serviceIntent = Intent(context, ForensicService::class.java)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(serviceIntent)
            } else {
                context.startService(serviceIntent)
            }

            Log.d(TAG, "ForensicService started with security controls enabled")
        }
    }
}
