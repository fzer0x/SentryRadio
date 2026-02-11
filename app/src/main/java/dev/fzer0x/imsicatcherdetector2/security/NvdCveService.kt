package dev.fzer0x.imsicatcherdetector2.security

import android.util.Log
import okhttp3.OkHttpClient
import okhttp3.Request
import org.json.JSONObject
import java.text.SimpleDateFormat
import java.util.Locale
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import java.util.concurrent.TimeUnit

class NvdCveService(private val apiKey: String? = null) {
    private val client = OkHttpClient.Builder()
        .connectTimeout(30, TimeUnit.SECONDS)
        .readTimeout(30, TimeUnit.SECONDS)
        .build()

    private val nvdBaseUrl = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    private val TAG = "NvdCveService"
    
    // Maximum total requests to prevent API abuse and crashes
    private val MAX_TOTAL_REQUESTS = 50
    private var requestCount = 0

    private val searchKeywords = listOf(
        "qualcomm", "mediatek", "exynos", "snapdragon",
        "baseband", "modem", "telephony", "cellular",
        "radio", "lte", "5g", "4g", "gsm", "umts",
        "rrc", "nas", "protocol", "firmware", "chipset",
        "smartphone", "mobile", "android", "processor"
    )

    suspend fun fetchCurrentVulnerabilities(): List<CveEntry> = withContext(Dispatchers.IO) {
        val allFetched = mutableListOf<CveEntry>()
        requestCount = 0 // Reset counter for this session
        
        Log.d(TAG, "Starting CVE fetch with ${searchKeywords.size} keywords")
        
        // Process keywords in smaller batches to avoid overwhelming the API
        val batchSize = 3
        val keywordBatches = searchKeywords.chunked(batchSize)
        
        for ((batchIndex, batch) in keywordBatches.withIndex()) {
            // Check if we've exceeded the maximum request limit
            if (requestCount >= MAX_TOTAL_REQUESTS) {
                Log.w(TAG, "Reached maximum request limit ($MAX_TOTAL_REQUESTS). Stopping fetch to prevent crashes.")
                break
            }
            
            Log.d(TAG, "Processing batch ${batchIndex + 1}/${keywordBatches.size} with ${batch.size} keywords")
            
            // Process batch in parallel but with controlled concurrency
            val batchResults = batch.map { keyword ->
                async {
                    var startIndex = 0
                    val resultsPerPage = 500 // Reduced from 2000 to be more conservative
                    var keywordTotal = 0
                    val keywordResults = mutableListOf<CveEntry>()
                    
                    do {
                        // Check request limit before making API call
                        if (requestCount >= MAX_TOTAL_REQUESTS) {
                            Log.w(TAG, "Request limit reached for keyword '$keyword'. Stopping.")
                            break
                        }
                        
                        val url = "$nvdBaseUrl?keywordSearch=$keyword&resultsPerPage=$resultsPerPage&startIndex=$startIndex"
                        Log.d(TAG, "Fetching: $url")
                        
                        try {
                            requestCount++ // Increment request counter
                            
                            val request = Request.Builder()
                                .url(url)
                                .apply { 
                                    if (!apiKey.isNullOrBlank()) {
                                        addHeader("apiKey", apiKey)
                                    }
                                }
                                .build()

                            val response = client.newCall(request).execute()
                            
                            when {
                                response.code == 429 -> {
                                    Log.w(TAG, "Rate limit hit (429) for keyword: $keyword - waiting before retry...")
                                    delay(2000) // Wait 2 seconds before retry
                                    break
                                }
                                response.isSuccessful -> {
                                    response.body?.string()?.let { responseBody ->
                                        val results = parseNvdResponse(responseBody)
                                        if (results.isEmpty()) break
                                        keywordResults.addAll(results)
                                        keywordTotal += results.size
                                        
                                        Log.d(TAG, "Fetched ${results.size} CVEs for '$keyword' (start: $startIndex)")
                                        
                                        // Check if there are more results
                                        val root = JSONObject(responseBody)
                                        val totalResults = root.optInt("totalResults", 0)
                                        startIndex += results.size
                                        
                                        if (startIndex >= totalResults || results.size < resultsPerPage) break
                                        
                                        // Add small delay between pages to avoid rate limiting
                                        delay(500)
                                    }
                                }
                                else -> {
                                    Log.e(TAG, "NVD API error ${response.code} for keyword: $keyword")
                                    break
                                }
                            }
                            response.close()
                        } catch (e: Exception) {
                            Log.e(TAG, "Error fetching NVD data for $keyword: ${e.message}")
                            break
                        }
                    } while (true && startIndex < 2000) // Limit total results per keyword to prevent excessive requests
                    
                    Log.d(TAG, "Total CVEs for '$keyword': $keywordTotal")
                    keywordResults
                }
            }.awaitAll()
            
            // Add batch results to total
            batchResults.forEach { allFetched.addAll(it) }
            
            // Add delay between batches to be respectful to the API
            if (batchIndex < keywordBatches.size - 1) {
                Log.d(TAG, "Batch completed, waiting before next batch...")
                delay(3000) // 3 second delay between batches
            }
        }
        
        val distinctResults = allFetched.distinctBy { it.cveId }
        Log.d(TAG, "Final result: ${distinctResults.size} distinct CVEs from ${allFetched.size} total fetched (${requestCount} API requests made)")
        
        distinctResults
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
