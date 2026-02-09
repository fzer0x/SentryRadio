package dev.fzer0x.imsicatcherdetector2.data

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import dev.fzer0x.imsicatcherdetector2.security.CveEntity
import kotlinx.coroutines.flow.Flow

@Dao
interface ForensicDao {
    @Query("SELECT * FROM forensic_logs ORDER BY timestamp DESC")
    fun getAllLogs(): Flow<List<ForensicEvent>>

    @Insert
    suspend fun insertEvent(event: ForensicEvent)

    @Query("DELETE FROM forensic_logs")
    suspend fun clearLogs()

    // Cell Tower Inventory
    @Query("SELECT * FROM cell_towers")
    fun getAllTowers(): Flow<List<CellTower>>

    @Query("SELECT * FROM cell_towers WHERE cellId = :cellId LIMIT 1")
    suspend fun getTowerById(cellId: String): CellTower?

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsertTower(tower: CellTower)

    @Query("DELETE FROM cell_towers")
    suspend fun deleteAllTowers()

    @Query("UPDATE cell_towers SET isBlocked = :blocked WHERE cellId = :cellId")
    suspend fun updateBlockStatus(cellId: String, blocked: Boolean)

    @Query("SELECT cellId FROM cell_towers WHERE isBlocked = 1")
    fun getBlockedCellIds(): Flow<List<String>>

    @Query("UPDATE cell_towers SET isBlocked = 0")
    suspend fun unblockAllTowers()

    @Query("DELETE FROM forensic_logs WHERE cellId IN (SELECT cellId FROM cell_towers WHERE isBlocked = 1)")
    suspend fun deleteBlockedLogs()

    @Query("DELETE FROM forensic_logs WHERE type = 'RADIO_METRICS_UPDATE' AND timestamp < :timestamp")
    suspend fun pruneOldRadioMetrics(timestamp: Long)

    // CVE Cache
    @Query("SELECT * FROM cve_cache")
    suspend fun getAllCves(): List<CveEntity>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertCves(cves: List<CveEntity>)

    @Query("DELETE FROM cve_cache WHERE lastUpdated < :threshold")
    suspend fun pruneOldCveCache(threshold: Long)
}
