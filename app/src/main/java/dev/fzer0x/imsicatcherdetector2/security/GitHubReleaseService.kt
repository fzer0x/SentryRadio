package dev.fzer0x.imsicatcherdetector2.security

import okhttp3.OkHttpClient
import okhttp3.Request
import org.json.JSONObject
import java.util.concurrent.TimeUnit

class GitHubReleaseService {
    private val client = OkHttpClient.Builder()
        .connectTimeout(15, TimeUnit.SECONDS)
        .readTimeout(15, TimeUnit.SECONDS)
        .build()

    data class ReleaseInfo(val version: String, val downloadUrl: String)

    suspend fun fetchLatestRelease(): ReleaseInfo? {
        val request = Request.Builder()
            .url("https://api.github.com/repos/fzer0x/SentryRadio/releases/latest")
            .header("User-Agent", "SentryRadio-UpdateManager")
            .build()

        return try {
            val response = client.newCall(request).execute()
            if (!response.isSuccessful) return null
            
            val json = JSONObject(response.body?.string() ?: "")
            val tagName = json.getString("tag_name")
            val assets = json.getJSONArray("assets")
            
            var downloadUrl = ""
            for (i in 0 until assets.length()) {
                val asset = assets.getJSONObject(i)
                if (asset.getString("name").endsWith(".apk")) {
                    downloadUrl = asset.getString("browser_download_url")
                    break
                }
            }

            if (tagName.isNotEmpty() && downloadUrl.isNotEmpty()) {
                ReleaseInfo(tagName, downloadUrl)
            } else null
        } catch (e: Exception) {
            null
        }
    }
}
