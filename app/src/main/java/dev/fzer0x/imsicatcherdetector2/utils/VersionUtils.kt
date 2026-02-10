package dev.fzer0x.imsicatcherdetector2.utils

import android.content.Context
import android.content.pm.PackageManager

object VersionUtils {
    /**
     * Holt die aktuelle Version aus dem Build-Info im Format "versionCode-versionName"
     * Beispiel: "4-0.3.0"
     */
    fun getCurrentVersion(context: Context): String {
        return try {
            val packageInfo = if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.TIRAMISU) {
                context.packageManager.getPackageInfo(context.packageName, PackageManager.PackageInfoFlags.of(0))
            } else {
                @Suppress("DEPRECATION")
                context.packageManager.getPackageInfo(context.packageName, 0)
            }
            
            val versionCode = if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.P) {
                packageInfo.longVersionCode.toInt()
            } else {
                @Suppress("DEPRECATION")
                packageInfo.versionCode
            }
            
            val versionName = packageInfo.versionName ?: "unknown"
            "$versionCode-$versionName"
        } catch (e: Exception) {
            "0-0.0.0"
        }
    }
}
