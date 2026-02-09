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
    val error: String? = null
)

class BeaconDbClient(private val apiKey: String) {
    private val client = HttpClientSecurityManager.createSecureOkHttpClient()
    private val JSON = "application/json; charset=utf-8".toMediaType()

    suspend fun verifyTower(
        mcc: String, 
        mnc: String, 
        lacOrTac: Int, 
        cellId: String, 
        rat: String,
        pci: Int? = null,
        ta: Int? = null,
        signalStrength: Int? = null
    ): BeaconDbResult = withContext(Dispatchers.IO) {
        try {
            val cleanMnc = mnc.toIntOrNull() ?: 0
            val cleanMcc = mcc.toIntOrNull() ?: 0
            
            val radioType = when {
                rat.contains("NR", ignoreCase = true) || rat.contains("5G", ignoreCase = true) -> "nr"
                rat.contains("LTE", ignoreCase = true) || rat.contains("4G", ignoreCase = true) -> "lte"
                rat.contains("WCDMA", ignoreCase = true) || rat.contains("UMTS", ignoreCase = true) -> "wcdma"
                rat.contains("GSM", ignoreCase = true) -> "gsm"
                else -> "lte"
            }

            // MLS/GLS standard URL format
            val baseUrl = "https://beacondb.net/v1/geolocate"
            val url = if (apiKey.isNotBlank() && apiKey != "YOUR_API_KEY_HERE") "$baseUrl?key=$apiKey" else baseUrl
            
            val cellObj = JSONObject().apply {
                put("radioType", radioType)
                put("mobileCountryCode", cleanMcc)
                put("mobileNetworkCode", cleanMnc)
                put("locationAreaCode", lacOrTac)
                put("cellId", cellId.toLongOrNull() ?: 0L)
                // BeaconDB/GLS uses 'psc' for LTE PCI as well if applicable
                if (pci != null && pci != -1) put("psc", pci)
                if (ta != null && ta != -1) put("timingAdvance", ta)
                if (signalStrength != null && signalStrength != -120) put("signalStrength", signalStrength)
            }

            val requestBody = JSONObject().apply {
                put("cellTowers", JSONArray().put(cellObj))
                put("considerIp", false)
            }.toString().toRequestBody(JSON)

            val request = Request.Builder()
                .url(url)
                .post(requestBody)
                .header("User-Agent", "SentryRadio/1.0 (Android)")
                .build()
            
            client.newCall(request).execute().use { response ->
                val body = response.body?.string() ?: return@withContext BeaconDbResult(false, error = "Empty response")
                Log.d("BeaconDB", "Request Body: $requestBody")
                Log.d("BeaconDB", "Response: $body")

                if (!response.isSuccessful) {
                    if (response.code == 404) return@withContext BeaconDbResult(false, error = "Cell not found")
                    return@withContext BeaconDbResult(false, error = "HTTP ${response.code}")
                }

                val json = JSONObject(body)
                val location = json.optJSONObject("location")
                
                if (location != null) {
                    val lat = location.optDouble("lat", Double.NaN)
                    val lon = location.optDouble("lng", Double.NaN) // GLS uses "lng"
                    val accuracy = json.optDouble("accuracy", Double.NaN)

                    if (!lat.isNaN() && !lon.isNaN()) {
                        BeaconDbResult(true, lat, lon, if (!accuracy.isNaN()) accuracy else null)
                    } else {
                        BeaconDbResult(false, error = "Invalid coordinates")
                    }
                } else {
                    BeaconDbResult(false, error = "No location data")
                }
            }
        } catch (e: Exception) {
            Log.e("BeaconDB", "API Error: ${e.message}")
            BeaconDbResult(false, error = e.message)
        }
    }
}
