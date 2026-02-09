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
    val error: String? = null,
    val cellId: String? = null,
    val lac: Int? = null,
    val mcc: String? = null,
    val mnc: String? = null
)

class OpenCellIdClient(private val apiKey: String) {
    private val client = HttpClientSecurityManager.createSecureOkHttpClient()

    suspend fun verifyTower(mcc: String, mnc: String, lacOrTac: Int, cellId: String, radio: String = "LTE"): OcidResult = withContext(Dispatchers.IO) {
        if (apiKey.isBlank() || apiKey == "YOUR_API_KEY_HERE") {
            return@withContext OcidResult(false, error = "No API Key")
        }

        try {
            val cleanMnc = mnc.filter { it.isDigit() }
            val radioParam = mapRadio(radio)

            val url = "https://opencellid.org/cell/get?key=$apiKey&mcc=$mcc&mnc=$cleanMnc&lac=$lacOrTac&cellid=$cellId&radio=$radioParam&format=json"
            Log.d("OpenCellID", "Lookup URL: ${url.replace(apiKey, "***")}")

            val request = Request.Builder().url(url).build()

            client.newCall(request).execute().use { response ->
                val body = response.body?.string() ?: ""
                if (!response.isSuccessful) {
                    return@withContext OcidResult(false, error = "HTTP ${response.code}")
                }

                val json = JSONObject(body)
                if (json.optString("stat") == "fail") {
                    return@withContext OcidResult(false, error = json.optString("error"))
                }

                return@withContext OcidResult(
                    isFound = true,
                    lat = json.optDouble("lat"),
                    lon = json.optDouble("lon"),
                    range = json.optDouble("range"),
                    radio = json.optString("radio")
                )
            }
        } catch (e: Exception) {
            OcidResult(false, error = e.message)
        }
    }

    suspend fun getTowersInArea(latMin: Double, lonMin: Double, latMax: Double, lonMax: Double): List<OcidResult> = withContext(Dispatchers.IO) {
        if (apiKey.isBlank()) return@withContext emptyList()
        try {
            // FIX: OpenCellID API expects BBOX = lat_min,lon_min,lat_max,lon_max
            val url = "https://opencellid.org/cell/getInArea?key=$apiKey&BBOX=$latMin,$lonMin,$latMax,$lonMax&format=json"
            Log.d("OpenCellID", "Area Scan Final URL: ${url.replace(apiKey, "***")}")
            
            val request = Request.Builder().url(url).build()

            client.newCall(request).execute().use { response ->
                val body = response.body?.string() ?: ""
                if (!response.isSuccessful) {
                    Log.e("OpenCellID", "Area Scan Failed: ${response.code} - $body")
                    return@withContext emptyList()
                }

                val json = JSONObject(body)
                val cells = json.optJSONArray("cells") ?: return@withContext emptyList()
                val results = mutableListOf<OcidResult>()
                for (i in 0 until cells.length()) {
                    val c = cells.getJSONObject(i)
                    results.add(OcidResult(
                        isFound = true, 
                        lat = c.optDouble("lat"), 
                        lon = c.optDouble("lon"),
                        range = c.optDouble("range"),
                        radio = c.optString("radio"), 
                        cellId = c.optString("cellid"), 
                        lac = c.optInt("lac"),
                        mcc = c.optString("mcc"),
                        mnc = c.optString("mnc")
                    ))
                }
                results
            }
        } catch (e: Exception) { 
            Log.e("OpenCellID", "Exception: ${e.message}")
            emptyList() 
        }
    }

    private fun mapRadio(rat: String): String = when {
        rat.contains("NR", true) || rat.contains("5G", true) -> "NR"
        rat.contains("LTE", true) || rat.contains("4G", true) -> "LTE"
        rat.contains("WCDMA", true) || rat.contains("UMTS", true) || rat.contains("3G", true) -> "UMTS"
        else -> "GSM"
    }
}
