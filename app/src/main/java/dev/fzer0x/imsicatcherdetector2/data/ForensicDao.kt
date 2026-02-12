package dev.fzer0x.imsicatcherdetector2.data

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import androidx.room.Update
import dev.fzer0x.imsicatcherdetector2.security.CveEntity
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.asSharedFlow

@Dao
interface ForensicDao {
    @Query("SELECT * FROM forensic_logs ORDER BY timestamp DESC LIMIT :limit")
    fun getRecentLogs(limit: Int = 1000): Flow<List<ForensicEvent>>

    @Query("SELECT * FROM forensic_logs WHERE timestamp >= :since ORDER BY timestamp DESC")
    fun getLogsSince(since: Long): Flow<List<ForensicEvent>>

    @Query("SELECT * FROM forensic_logs WHERE severity >= :severity AND timestamp >= :since ORDER BY timestamp DESC")
    fun getCriticalLogs(severity: Int, since: Long): Flow<List<ForensicEvent>>

    @Query("SELECT * FROM forensic_logs WHERE simSlot = :slot ORDER BY timestamp DESC LIMIT :limit")
    fun getLogsBySlot(slot: Int, limit: Int = 500): Flow<List<ForensicEvent>>

    @Query("SELECT COUNT(*) FROM forensic_logs")
    suspend fun getLogCount(): Int

    @Query("DELETE FROM forensic_logs WHERE timestamp < :timestamp")
    suspend fun deleteLogsBefore(timestamp: Long)

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertEvents(events: List<ForensicEvent>)

    @Insert
    suspend fun insertEvent(event: ForensicEvent)

    @Query("DELETE FROM forensic_logs")
    suspend fun clearLogs()

    // Cell Tower Inventory
    @Query("SELECT * FROM cell_towers WHERE isBlocked = 1")
    fun getBlockedTowers(): Flow<List<CellTower>>

    @Query("SELECT * FROM cell_towers WHERE latitude BETWEEN :minLat AND :maxLat AND longitude BETWEEN :minLon AND :maxLon")
    suspend fun getTowersInArea(minLat: Double, maxLat: Double, minLon: Double, maxLon: Double): List<CellTower>

    @Query("SELECT * FROM cell_towers WHERE lastSeen < :threshold")
    suspend fun getOldTowers(threshold: Long): List<CellTower>

    @Query("DELETE FROM cell_towers WHERE lastSeen < :threshold")
    suspend fun deleteOldTowers(threshold: Long)

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsertTowers(towers: List<CellTower>)

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

    @Query("SELECT cveId FROM cve_cache")
    suspend fun getAllCveIds(): List<String>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertCves(cves: List<CveEntity>)

    @Query("DELETE FROM cve_cache")
    suspend fun clearCves()

    @Query("SELECT * FROM cve_cache WHERE lastUpdated >= :threshold")
    suspend fun getRecentCves(threshold: Long): List<CveEntity>

    @Query("SELECT COUNT(*) FROM cve_cache")
    suspend fun getCveCount(): Int

    @Query("DELETE FROM cve_cache WHERE lastUpdated < :threshold")
    suspend fun pruneOldCveCache(threshold: Long)
}
