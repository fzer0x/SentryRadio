package dev.fzer0x.imsicatcherdetector2.security

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.util.Log
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

object UpdateManager {
    private val releaseService = GitHubReleaseService()
    private const val TAG = "UpdateManager"

    fun checkForUpdates(context: Context, currentVersion: String) {
        CoroutineScope(Dispatchers.IO).launch {
            try {
                val latest = releaseService.fetchLatestRelease() ?: return@launch
                
                if (VersionComparator.compare(currentVersion, latest.version) > 0) {
                    Log.i(TAG, "Update available: ${latest.version}")
                    withContext(Dispatchers.Main) {
                        // Da es ein Debug-Release ist, öffnen wir einfach den Browser zum Download
                        val browserIntent = Intent(Intent.ACTION_VIEW, Uri.parse(latest.downloadUrl))
                        browserIntent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                        context.startActivity(browserIntent)
                    }
                }
            } catch (e: Exception) {
                Log.e(TAG, "Error checking for updates: ${e.message}")
            }
        }
    }
}
