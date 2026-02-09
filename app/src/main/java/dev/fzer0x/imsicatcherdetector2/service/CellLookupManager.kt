package dev.fzer0x.imsicatcherdetector2.service

import android.util.Log
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

data class LookupResult(
    val isFound: Boolean,
    val lat: Double? = null,
    val lon: Double? = null,
    val range: Double? = null,
    val source: String? = null,
    val error: String? = null,
    val cellId: String? = null,
    val mcc: String? = null,
    val mnc: String? = null,
    val lac: Int? = null,
    val rat: String? = null,
    val samples: Int? = null,
    val changeable: Boolean? = null,
    val isSuspicious: Boolean = false
)

class CellLookupManager(
    private val beaconDbKey: String = "",
    private val openCellIdKey: String = "",
    private val useBeaconDb: Boolean = true,
    private val useOpenCellId: Boolean = true
) {
    private val beaconDbClient = BeaconDbClient(beaconDbKey)
    private val openCellIdClient = OpenCellIdClient(openCellIdKey)

    suspend fun lookup(
        mcc: String, 
        mnc: String, 
        lacOrTac: Int, 
        cellId: String, 
        rat: String = "LTE",
        pci: Int? = null,
        ta: Int? = null,
        dbm: Int? = null
    ): LookupResult = withContext(Dispatchers.IO) {
        val errors = mutableListOf<String>()
        val cleanMnc = mnc.filter { it.isDigit() }
        val cleanMcc = mcc.filter { it.isDigit() }

        if (useBeaconDb) {
            Log.d("CellLookup", "Trying BeaconDB for $cellId ($rat)")
            val bdb = beaconDbClient.verifyTower(cleanMcc, cleanMnc, lacOrTac, cellId, rat, pci, ta, dbm)
            if (bdb.isFound) {
                return@withContext LookupResult(
                    isFound = true,
                    lat = bdb.lat,
                    lon = bdb.lon,
                    range = bdb.range,
                    source = "BeaconDB"
                )
            } else {
                bdb.error?.let { errors.add("BeaconDB: $it") }
            }
        }

        if (useOpenCellId && openCellIdKey.isNotBlank()) {
            Log.d("CellLookup", "Trying OpenCellID for $cellId ($rat)")
            val ocid = openCellIdClient.verifyTower(cleanMcc, cleanMnc, lacOrTac, cellId, rat)
            if (ocid.isFound) {
                return@withContext LookupResult(
                    isFound = true,
                    lat = ocid.lat,
                    lon = ocid.lon,
                    range = ocid.range,
                    source = "OpenCellID",
                    samples = ocid.samples,
                    changeable = ocid.changeable
                )
            } else {
                ocid.error?.let { errors.add("OpenCellID: $it") }
            }
        }
        
        return@withContext LookupResult(false, error = if (errors.isEmpty()) "Not found" else errors.joinToString("; "))
    }

    suspend fun getTowersInArea(lat: Double, lon: Double): List<LookupResult> = withContext(Dispatchers.IO) {
        if (!useOpenCellId || openCellIdKey.isBlank() || openCellIdKey == "YOUR_API_KEY_HERE") return@withContext emptyList()
        
        val halfSize = 0.009
        val latMin = lat - halfSize
        val latMax = lat + halfSize
        val lonMin = lon - halfSize
        val lonMax = lon + halfSize
        
        try {
            val ocidList = openCellIdClient.getTowersInArea(latMin, lonMin, latMax, lonMax)
            ocidList.map { 
                LookupResult(
                    isFound = true, lat = it.lat, lon = it.lon, range = it.range, 
                    samples = it.samples, source = "OpenCellID Area",
                    rat = it.radio?.uppercase() ?: "LTE",
                    cellId = it.cellId,
                    lac = it.lac,
                    mcc = it.mcc,
                    mnc = it.mnc
                )
            }
        } catch (e: Exception) {
            emptyList()
        }
    }
}