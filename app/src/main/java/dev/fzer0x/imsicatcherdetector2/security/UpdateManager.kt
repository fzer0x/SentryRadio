package dev.fzer0x.imsicatcherdetector2.security

import android.content.Context
import android.util.Log
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

object UpdateManager {
    private val releaseService = GitHubReleaseService()
    private const val TAG = "UpdateManager"
    
    // Callback interface für Update-Dialog
    interface UpdateCallback {
        fun onUpdateAvailable(currentVersion: String, latestVersion: String)
    }
    
    private var updateCallback: UpdateCallback? = null
    
    fun setUpdateCallback(callback: UpdateCallback) {
        updateCallback = callback
    }

    fun checkForUpdates(context: Context, currentVersion: String) {
        CoroutineScope(Dispatchers.IO).launch {
            try {
                val latest = releaseService.fetchLatestRelease() ?: return@launch
                
                if (VersionComparator.compare(currentVersion, latest.version) > 0) {
                    Log.i(TAG, "Update available: ${latest.version}")
                    withContext(Dispatchers.Main) {
                        updateCallback?.onUpdateAvailable(currentVersion, latest.version)
                    }
                } else {
                    Log.i(TAG, "No update available. Current: $currentVersion, Latest: ${latest.version}")
                }
            } catch (e: Exception) {
                Log.e(TAG, "Error checking for updates: ${e.message}")
            }
        }
    }
}
