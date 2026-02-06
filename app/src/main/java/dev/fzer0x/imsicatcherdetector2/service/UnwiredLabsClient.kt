package dev.fzer0x.imsicatcherdetector2.service

import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import android.util.Log
import org.json.JSONArray
import dev.fzer0x.imsicatcherdetector2.security.HttpClientSecurityManager

data class UnwiredResult(
    val isFound: Boolean,
    val lat: Double? = null,
    val lon: Double? = null,
    val range: Double? = null,
    val error: String? = null
)

class UnwiredLabsClient(private val apiKey: String) {
    private val client = HttpClientSecurityManager.createSecureOkHttpClient()
    private val JSON = "application/json; charset=utf-8".toMediaType()

    suspend fun verifyTower(mcc: String, mnc: String, lacOrTac: Int, cellId: String, rat: String): UnwiredResult = withContext(Dispatchers.IO) {
        if (apiKey.isBlank()) return@withContext UnwiredResult(false, error = "No API Key")

        try {
            val radioType = when(rat.uppercase()) {
                "NR" -> "nr"
                "LTE" -> "lte"
                "WCDMA", "UMTS" -> "gsm"
                else -> "gsm"
            }

            val cellObj = JSONObject().apply {
                put("lac", lacOrTac)
                put("cid", cellId.toLongOrNull() ?: 0L)
            }

            val requestBody = JSONObject().apply {
                put("token", apiKey)
                put("radio", radioType)
                put("mcc", mcc.toIntOrNull() ?: 0)
                put("mnc", mnc.toIntOrNull() ?: 0)
                put("cells", JSONArray().put(cellObj))
                put("address", 0)
            }.toString().toRequestBody(JSON)

            val request = Request.Builder()
                .url("https://us1.unwiredlabs.com/v2/process.php")
                .post(requestBody)
                .build()

            client.newCall(request).execute().use { response ->
                val body = response.body?.string() ?: return@withContext UnwiredResult(false, error = "Empty response")
                Log.d("UnwiredLabs", "Response: $body")

                val json = JSONObject(body)
                val status = json.optString("status")
                
                if (status == "ok") {
                    val lat = json.optDouble("lat", Double.NaN)
                    val lon = json.optDouble("lon", Double.NaN)
                    val accuracy = json.optDouble("accuracy", Double.NaN)
                    
                    if (!lat.isNaN() && !lon.isNaN()) {
                        UnwiredResult(
                            isFound = true,
                            lat = lat,
                            lon = lon,
                            range = if (!accuracy.isNaN()) accuracy else null
                        )
                    } else {
                        UnwiredResult(false, error = "No coordinates")
                    }
                } else {
                    UnwiredResult(false, error = json.optString("message", "Error"))
                }
            }
        } catch (e: Exception) {
            Log.e("UnwiredLabs", "API Error: ${e.message}")
            UnwiredResult(false, error = e.message)
        }
    }
}
