package dev.fzer0x.imsicatcherdetector2.service

import android.util.Log
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

data class LookupResult(
    val isFound: Boolean,
    val lat: Double? = null,
    val lon: Double? = null,
    val range: Double? = null,
    val samples: Int? = null,
    val changeable: Boolean? = null,
    val source: String? = null,
    val error: String? = null
)

class CellLookupManager(
    private val openCellIdKey: String,
    private val unwiredLabsKey: String,
    private val useBeaconDb: Boolean = true,
    private val useOpenCellId: Boolean = true,
    private val useUnwiredLabs: Boolean = true
) {
    private val beaconDbClient = BeaconDbClient("") 
    private val openCellIdClient = OpenCellIdClient(openCellIdKey)
    private val unwiredLabsClient = UnwiredLabsClient(unwiredLabsKey)

    suspend fun lookup(mcc: String, mnc: String, lacOrTac: Int, cellId: String, rat: String = "LTE"): LookupResult = withContext(Dispatchers.IO) {
        if (useBeaconDb) {
            Log.d("CellLookup", "Trying BeaconDB for $cellId")
            val bdb = beaconDbClient.verifyTower(mcc, mnc, lacOrTac, cellId)
            if (bdb.isFound) {
                return@withContext LookupResult(
                    isFound = true,
                    lat = bdb.lat,
                    lon = bdb.lon,
                    range = bdb.range,
                    source = "BeaconDB"
                )
            }
        }

        if (useOpenCellId && openCellIdKey.isNotBlank()) {
            Log.d("CellLookup", "Trying OpenCellID for $cellId")
            val ocid = openCellIdClient.verifyTower(mcc, mnc, lacOrTac, cellId)
            if (ocid.isFound) {
                return@withContext LookupResult(
                    isFound = true,
                    lat = ocid.lat,
                    lon = ocid.lon,
                    range = ocid.range,
                    samples = ocid.samples,
                    changeable = ocid.changeable,
                    source = "OpenCellID"
                )
            }
        }

        if (useUnwiredLabs && unwiredLabsKey.isNotBlank()) {
            Log.d("CellLookup", "Trying UnwiredLabs for $cellId")
            val ul = unwiredLabsClient.verifyTower(mcc, mnc, lacOrTac, cellId, rat)
            if (ul.isFound) {
                return@withContext LookupResult(
                    isFound = true,
                    lat = ul.lat,
                    lon = ul.lon,
                    range = ul.range,
                    source = "UnwiredLabs"
                )
            }
        }

        return@withContext LookupResult(false, error = "Not found in enabled databases")
    }
}
