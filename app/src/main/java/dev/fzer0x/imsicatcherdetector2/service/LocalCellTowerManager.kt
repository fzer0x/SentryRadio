package dev.fzer0x.imsicatcherdetector2.service

import android.content.Context
import dev.fzer0x.imsicatcherdetector2.data.LocalCellTower
import dev.fzer0x.imsicatcherdetector2.data.LocalCellTowerDao
import dev.fzer0x.imsicatcherdetector2.data.TowerStatus
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import android.util.Log

class LocalCellTowerManager(
    private val dao: LocalCellTowerDao,
    private val context: Context,
    private val lookupManager: CellLookupManager? = null  
) {
    companion object {
        private const val TAG = "LocalCellTowerManager"
        const val API_TIMEOUT_MS = 5000  
        const val API_CACHE_VALIDITY_MS = 86400000  
    }

    suspend fun registerTower(
        cellId: String,
        mcc: String,
        mnc: String,
        lac: Int,
        tac: Int? = null,
        rat: String = "UNKNOWN",
        signalStrength: Int? = null,
        pci: Int? = null,
        earfcn: Int? = null,
        neighborCount: Int = 0
    ) = withContext(Dispatchers.IO) {
        val existing = dao.getTowerById(cellId)

        if (existing == null) {
            val newTower = LocalCellTower(
                cellId = cellId,
                mcc = mcc,
                mnc = mnc,
                lac = lac,
                tac = tac,
                rat = rat,
                pci = pci,
                earfcn = earfcn,
                neighborCount = neighborCount,
                avgSignalStrength = signalStrength,
                maxSignalStrength = signalStrength,
                minSignalStrength = signalStrength,
                status = TowerStatus.LOADING  
            )
            dao.upsertTower(newTower)
        } else {
            dao.updateLastSeen(cellId)
        }

        queryApisAsync(cellId, mcc, mnc, lac, tac, rat)
    }

    private suspend fun queryApisAsync(
        cellId: String,
        mcc: String,
        mnc: String,
        lac: Int,
        tac: Int?,
        rat: String
    ) = withContext(Dispatchers.IO) {
        try {
            val tower = dao.getTowerById(cellId) ?: return@withContext

            if (tower.apiLastChecked != null &&
                System.currentTimeMillis() - tower.apiLastChecked < API_CACHE_VALIDITY_MS) {
                Log.d(TAG, "Tower $cellId: API-Cache noch gültig")
                return@withContext
            }

            Log.d(TAG, "Tower $cellId: Starte API-Abfrage (PRIMARY)")

            lookupManager?.let { manager ->
                try {
                    val result = withContext(Dispatchers.IO) {
                        try {
                            manager.lookup(mcc, mnc, lac, cellId, rat)
                        } catch (e: Exception) {
                            Log.w(TAG, "API-Fehler für $cellId: ${e.message}")
                            null
                        }
                    }

                    if (result != null && result.isFound) {
                        Log.d(TAG, "Tower $cellId: API verifiziert ✓")
                        dao.updateTower(tower.copy(
                            latitude = result.lat,
                            longitude = result.lon,
                            accuracy = result.range?.toFloat(),
                            apiVerified = true,
                            apiSource = result.source,
                            apiLastChecked = System.currentTimeMillis(),
                            apiTrustLevel = 85,  
                            apiRange = result.range,
                            status = TowerStatus.API_VERIFIED,
                            trustLevel = 85,
                            verificationMethod = "API"
                        ))
                        return@withContext
                    }
                } catch (e: Exception) {
                    Log.w(TAG, "API-Fehler: ${e.message}")
                }
            }

            Log.d(TAG, "Tower $cellId: API nicht verfügbar, nutze Offline-Fallback")
            verifyOfflineAsSecondary(cellId)

        } catch (e: Exception) {
            Log.e(TAG, "Fehler bei Tower-Registrierung: ${e.message}", e)
        }
    }

    private suspend fun verifyOfflineAsSecondary(cellId: String) = withContext(Dispatchers.IO) {
        val tower = dao.getTowerById(cellId) ?: return@withContext

        Log.d(TAG, "Tower $cellId: Starte Offline-Fallback-Verifizierung")

        var isSuspicious = false
        var offlineTrust = 50  

        if (tower.timingAdvance == 0 && tower.avgSignalStrength != null && tower.avgSignalStrength > -60) {
            isSuspicious = true
            offlineTrust -= 20
        }

        if (tower.neighborCount == 0 && tower.detectionCount > 5) {
            isSuspicious = true
            offlineTrust -= 15
        }

        tower.avgSignalStrength?.let { signal ->
            if (signal > -30) {
                isSuspicious = true
                offlineTrust -= 20
            }
        }

        if (tower.detectionCount > 20) {
            offlineTrust += 15
        }

        if (tower.latitude != null && tower.longitude != null) {
            offlineTrust += 10
        }

        offlineTrust = offlineTrust.coerceIn(0, 100)

        dao.updateTower(tower.copy(
            offlineVerified = true,
            offlineTrustLevel = offlineTrust,
            isSuspicious = isSuspicious,
            status = when {
                isSuspicious -> TowerStatus.SUSPICIOUS
                offlineTrust >= 70 -> TowerStatus.NORMAL
                else -> TowerStatus.UNKNOWN
            },
            trustLevel = offlineTrust,
            verificationMethod = "Offline",  
            isUnderObservation = isSuspicious || !tower.apiVerified
        ))

        Log.d(TAG, "Tower $cellId: Offline-Fallback abgeschlossen (Trust: $offlineTrust)")
    }

    suspend fun addUserTower(
        cellId: String,
        mcc: String,
        mnc: String,
        lac: Int,
        latitude: Double? = null,
        longitude: Double? = null,
        name: String? = null,
        notes: String? = null
    ) = withContext(Dispatchers.IO) {
        Log.d(TAG, "User fügt Tower hinzu: $cellId")

        val tower = LocalCellTower(
            cellId = cellId,
            mcc = mcc,
            mnc = mnc,
            lac = lac,
            latitude = latitude,
            longitude = longitude,
            baseStationName = name,
            isUserAdded = true,
            isUnderObservation = true,
            observationNotes = notes,
            status = TowerStatus.OFFLINE_FALLBACK,  
            verificationMethod = "UserAdded"
        )
        dao.upsertTower(tower)
    }

    suspend fun updateLocation(
        cellId: String,
        latitude: Double,
        longitude: Double,
        accuracy: Float? = null
    ) = withContext(Dispatchers.IO) {
        val tower = dao.getTowerById(cellId) ?: return@withContext
        dao.updateTower(tower.copy(
            latitude = latitude,
            longitude = longitude,
            accuracy = accuracy
        ))
    }

    suspend fun blockTower(cellId: String) = withContext(Dispatchers.IO) {
        dao.updateStatus(cellId, TowerStatus.BLOCKED)
    }

    suspend fun stopObserving(cellId: String) = withContext(Dispatchers.IO) {
        dao.updateObservationStatus(cellId, false)
    }

    suspend fun getTrustLevel(cellId: String): Int = withContext(Dispatchers.IO) {
        dao.getTowerById(cellId)?.trustLevel ?: 0
    }

    suspend fun cleanupVerifiedTowers() = withContext(Dispatchers.IO) {
        dao.deleteVerifiedAndObserved()
    }
}
