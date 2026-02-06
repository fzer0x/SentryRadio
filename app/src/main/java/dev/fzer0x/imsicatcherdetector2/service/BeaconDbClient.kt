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

data class BeaconDbResult(
    val isFound: Boolean,
    val lat: Double? = null,
    val lon: Double? = null,
    val range: Double? = null,
    val samples: Int? = null,
    val changeable: Boolean? = null,
    val radio: String? = null,
    val error: String? = null
)

class BeaconDbClient(private val apiKey: String) {
    private val client = HttpClientSecurityManager.createSecureOkHttpClient()
    private val JSON = "application/json; charset=utf-8".toMediaType()

    suspend fun verifyTower(mcc: String, mnc: String, lacOrTac: Int, cellId: String): BeaconDbResult = withContext(Dispatchers.IO) {
        try {
            val cleanMnc = mnc.toIntOrNull() ?: 0
            val cleanMcc = mcc.toIntOrNull() ?: 0
            
            val url = "https://beacondb.net/v1/geolocate"
            
            val cellObj = JSONObject().apply {
                put("radioType", "lte") 
                put("mobileCountryCode", cleanMcc)
                put("mobileNetworkCode", cleanMnc)
                put("locationAreaCode", lacOrTac)
                put("cellId", cellId.toLongOrNull() ?: 0L)
            }

            val requestBody = JSONObject().apply {
                put("cellTowers", JSONArray().put(cellObj))
            }.toString().toRequestBody(JSON)

            val request = Request.Builder()
                .url(url)
                .post(requestBody)
                .apply {
                    if (apiKey.isNotBlank() && apiKey != "YOUR_API_KEY_HERE") {
                        // API Key im Header, nicht im Body (besser für logging)
                        addHeader("Authorization", "Bearer $apiKey")
                    }
                }
                .build()
            
            client.newCall(request).execute().use { response ->
                val body = response.body?.string() ?: return@withContext BeaconDbResult(false, error = "Empty response")
                Log.d("BeaconDB", "Response: $body")
                
                if (!response.isSuccessful) {
                    return@withContext BeaconDbResult(false, error = "HTTP ${response.code}: $body")
                }

                val json = JSONObject(body)
                val location = json.optJSONObject("location")
                
                if (location != null) {
                    val lat = location.optDouble("lat", Double.NaN)
                    val lon = location.optDouble("lng", Double.NaN)
                    val accuracy = json.optDouble("accuracy", Double.NaN)
                    
                    if (!lat.isNaN() && !lon.isNaN()) {
                        BeaconDbResult(
                            isFound = true, 
                            lat = lat, 
                            lon = lon,
                            range = if (!accuracy.isNaN()) accuracy else null
                        )
                    } else {
                        BeaconDbResult(false, error = "No coordinates found")
                    }
                } else {
                    BeaconDbResult(false, error = "Cell not found")
                }
            }
        } catch (e: Exception) {
            Log.e("BeaconDB", "API Error: ${e.message}")
            BeaconDbResult(false, error = e.message)
        }
    }

    suspend fun getTowersInArea(latMin: Double, lonMin: Double, latMax: Double, lonMax: Double): List<BeaconDbResult> {
        return emptyList()
    }
}
