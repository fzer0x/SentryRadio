package dev.fzer0x.imsicatcherdetector2.service

import okhttp3.OkHttpClient
import okhttp3.Request
import org.json.JSONObject
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import android.util.Log
import dev.fzer0x.imsicatcherdetector2.security.HttpClientSecurityManager

data class OcidResult(
    val isFound: Boolean,
    val lat: Double? = null,
    val lon: Double? = null,
    val range: Double? = null,
    val samples: Int? = null,
    val changeable: Boolean? = null,
    val radio: String? = null,
    val error: String? = null
)

class OpenCellIdClient(private val apiKey: String) {
    private val client = HttpClientSecurityManager.createSecureOkHttpClient()

    suspend fun verifyTower(mcc: String, mnc: String, lacOrTac: Int, cellId: String): OcidResult = withContext(Dispatchers.IO) {
        if (apiKey.isBlank() || apiKey == "YOUR_API_KEY_HERE") {
            return@withContext OcidResult(false, error = "No API Key")
        }

        try {
            val cleanMnc = mnc.toIntOrNull()?.toString() ?: mnc
            if (mcc.toIntOrNull() !in 100..999) return@withContext OcidResult(false, error = "Invalid MCC: $mcc")
            
            // Use base URL without API key
            val url = "https://opencellid.org/cell/get?mcc=$mcc&mnc=$cleanMnc&lac=$lacOrTac&cellid=$cellId&format=json"
            Log.d("OpenCellID", "Querying: ${url.replace(Regex("key=[^&]*"), "key=***")}")

            val request = Request.Builder()
                .url(url)
                .addHeader("Authorization", "Bearer $apiKey")
                .build()

            client.newCall(request).execute().use { response ->
                val body = response.body?.string() ?: return@withContext OcidResult(false, error = "Empty response")
                Log.d("OpenCellID", "Response: $body")
                
                if (!response.isSuccessful) {
                    return@withContext OcidResult(false, error = "HTTP ${response.code}")
                }

                val json = JSONObject(body)
                val stat = json.optString("stat", "ok")
                
                if (stat == "fail") {
                    val errObj = json.optJSONObject("err")
                    val errMsg = errObj?.optString("info") ?: "Cell not found"
                    return@withContext OcidResult(false, error = errMsg)
                }

                val lat = json.optDouble("lat", Double.NaN)
                val lon = json.optDouble("lon", Double.NaN)
                
                if (!lat.isNaN() && !lon.isNaN() && lat != 0.0 && lon != 0.0) {
                    // Validate coordinates are within valid ranges
                    if (lat in -90.0..90.0 && lon in -180.0..180.0) {
                        OcidResult(
                            isFound = true,
                            lat = lat,
                            lon = lon,
                            range = if (json.has("range")) json.getDouble("range") else null,
                            samples = if (json.has("samples")) json.getInt("samples") else null,
                            changeable = when {
                                json.has("changeable") -> {
                                    val v = json.get("changeable")
                                    if (v is Boolean) v else json.optInt("changeable", 1) == 1
                                }
                                else -> null
                            },
                            radio = json.optString("radio")
                        )
                    } else {
                        OcidResult(isFound = false, error = "Coordinates out of valid range")
                    }
                } else {
                    OcidResult(isFound = false, error = "No valid coordinates in DB")
                }
            }
        } catch (e: Exception) {
            Log.e("OpenCellID", "API Error: ${e.message}")
            OcidResult(false, error = e.message)
        }
    }

    suspend fun getTowersInArea(latMin: Double, lonMin: Double, latMax: Double, lonMax: Double): List<OcidResult> = withContext(Dispatchers.IO) {
        if (apiKey.isBlank() || apiKey == "YOUR_API_KEY_HERE") return@withContext emptyList()
        
        try {
            val url = "https://opencellid.org/cell/getInArea?key=$apiKey&BBOX=$latMin,$lonMin,$latMax,$lonMax&format=json&limit=50"
            val request = Request.Builder().url(url).build()
            
            client.newCall(request).execute().use { response ->
                val body = response.body?.string() ?: return@withContext emptyList()
                val json = JSONObject(body)
                val cells = json.optJSONArray("cells") ?: return@withContext emptyList()
                
                val results = mutableListOf<OcidResult>()
                for (i in 0 until cells.length()) {
                    val c = cells.getJSONObject(i)
                    results.add(OcidResult(
                        isFound = true,
                        lat = c.getDouble("lat"),
                        lon = c.getDouble("lon"),
                        range = c.optDouble("range"),
                        samples = c.optInt("samples"),
                        changeable = when {
                            c.has("changeable") -> {
                                val v = c.get("changeable")
                                if (v is Boolean) v else c.optInt("changeable", 1) == 1
                            }
                            else -> true
                        },
                        radio = c.optString("radio")
                    ))
                }
                results
            }
        } catch (e: Exception) {
            Log.e("OpenCellID", "Area Scan Error: ${e.message}")
            emptyList()
        }
    }

    suspend fun addMeasurement(
        lat: Double,
        lon: Double,
        mcc: String,
        mnc: String,
        lac: Int?,
        tac: Int?,
        cellid: String,
        signal: Int?,
        act: String?,
        pci: Int? = null,
        ta: Int? = null,
        measuredAt: Long = System.currentTimeMillis()
    ): Boolean = withContext(Dispatchers.IO) {
        if (apiKey.isBlank() || apiKey == "YOUR_API_KEY_HERE") return@withContext false

        try {
            val cleanMnc = mnc.toIntOrNull()?.toString() ?: mnc
            val realLac = if (lac != null && lac != -1) lac else if (tac != null && tac != -1) tac else null
            if (realLac == null) return@withContext false

            val urlBuilder = StringBuilder("https://opencellid.org/measure/add")
            urlBuilder.append("?key=$apiKey")
            urlBuilder.append("&lat=$lat")
            urlBuilder.append("&lon=$lon")
            urlBuilder.append("&mcc=$mcc")
            urlBuilder.append("&mnc=$cleanMnc")
            urlBuilder.append("&lac=$realLac")
            urlBuilder.append("&cellid=$cellid")
            urlBuilder.append("&measured_at=$measuredAt")
            
            val actMapped = when(act?.uppercase()) {
                "WCDMA" -> "UMTS"
                "NR" -> "NR"
                "LTE" -> "LTE"
                "GSM" -> "GSM"
                else -> "GSM"
            }
            urlBuilder.append("&act=$actMapped")

            if (signal != null && signal != -120) urlBuilder.append("&signal=$signal")
            if (pci != null && pci != -1) urlBuilder.append("&pci=$pci")
            if (ta != null && ta != -1) urlBuilder.append("&ta=$ta")

            val request = Request.Builder().url(urlBuilder.toString()).build()
            client.newCall(request).execute().use { response ->
                val body = response.body?.string() ?: ""
                response.isSuccessful && body.contains("Your measurement has been inserted")
            }
        } catch (e: Exception) {
            Log.e("OpenCellID", "Upload Error: ${e.message}")
            false
        }
    }
}
