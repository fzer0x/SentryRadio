package dev.fzer0x.imsicatcherdetector2.security

import android.util.Log
import okhttp3.OkHttpClient
import okhttp3.Request
import org.json.JSONObject
import java.text.SimpleDateFormat
import java.util.Locale
import java.util.concurrent.TimeUnit

class NvdCveService(private val apiKey: String? = null) {
    private val client = OkHttpClient.Builder()
        .connectTimeout(30, TimeUnit.SECONDS)
        .readTimeout(30, TimeUnit.SECONDS)
        .build()

    private val nvdBaseUrl = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    private val TAG = "NvdCveService"

    private val searchKeywords = listOf(
        "qualcomm+modem", "mediatek+modem", "exynos+modem",
        "baseband+vulnerability", "telephony+stack", "rrc+protocol",
        "nas+protocol", "sim+toolkit", "radio+interface+layer"
    )

    suspend fun fetchCurrentVulnerabilities(): List<CveEntry> {
        val allFetched = mutableListOf<CveEntry>()
        
        for (keyword in searchKeywords) {
            val url = "$nvdBaseUrl?keywordSearch=$keyword"
            try {
                val request = Request.Builder()
                    .url(url)
                    .apply { 
                        if (!apiKey.isNullOrBlank()) {
                            addHeader("apiKey", apiKey)
                        }
                    }
                    .build()

                val results = client.newCall(request).execute().use { response ->
                    when {
                        response.code == 429 -> {
                            Log.w(TAG, "Rate limit hit (429) for keyword: $keyword")
                            null
                        }
                        response.isSuccessful -> {
                            response.body?.string()?.let { parseNvdResponse(it) }
                        }
                        else -> {
                            Log.e(TAG, "NVD API error ${response.code} for keyword: $keyword")
                            null
                        }
                    }
                }
                
                if (results != null) {
                    allFetched.addAll(results)
                } else {
                    // Stop on rate limit or critical error
                    break
                }
            } catch (e: Exception) {
                Log.e(TAG, "Error fetching NVD data for $keyword: ${e.message}")
            }
        }
        return allFetched.distinctBy { it.cveId }
    }

    private fun parseNvdResponse(jsonString: String): List<CveEntry> {
        val results = mutableListOf<CveEntry>()
        val root = JSONObject(jsonString)
        val vulnerabilities = root.optJSONArray("vulnerabilities") ?: return results

        val dateFormat = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss", Locale.US)

        for (i in 0 until vulnerabilities.length()) {
            val item = vulnerabilities.getJSONObject(i).getJSONObject("cve")
            val cveId = item.getString("id")
            
            val descriptions = item.optJSONArray("descriptions")
            val description = if (descriptions != null && descriptions.length() > 0) {
                descriptions.getJSONObject(0).getString("value")
            } else ""

            // Extract CVSS Score
            var severity = 0.0
            val metrics = item.optJSONObject("metrics")
            if (metrics != null) {
                val cvssV31 = metrics.optJSONArray("cvssMetricV31")
                val cvssV30 = metrics.optJSONArray("cvssMetricV30")
                
                if (cvssV31 != null && cvssV31.length() > 0) {
                    severity = cvssV31.getJSONObject(0).getJSONObject("cvssData").optDouble("baseScore", 0.0)
                } else if (cvssV30 != null && cvssV30.length() > 0) {
                    severity = cvssV30.getJSONObject(0).getJSONObject("cvssData").optDouble("baseScore", 0.0)
                }
            }

            val published = item.optString("published", "")
            val dateMillis = if (published.isNotEmpty()) {
                try { dateFormat.parse(published)?.time ?: 0L } catch (e: Exception) { 0L }
            } else 0L

            // Check relevance for IMSI Catchers / Radio Security
            val imsiKeywords = listOf("nas", "rrc", "protocol", "downgrade", "unencrypted", "cipher", "paging", "authentication")
            val isImsiRelevant = imsiKeywords.any { description.lowercase().contains(it) }

            results.add(CveEntry(cveId, description, severity, dateMillis, emptyList(), isImsiRelevant))
        }
        return results
    }
}
