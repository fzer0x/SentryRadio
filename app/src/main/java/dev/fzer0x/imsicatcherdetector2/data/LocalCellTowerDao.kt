package dev.fzer0x.imsicatcherdetector2.data

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import androidx.room.Update
import kotlinx.coroutines.flow.Flow

@Dao
interface LocalCellTowerDao {

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsertTower(tower: LocalCellTower)

    @Update
    suspend fun updateTower(tower: LocalCellTower)

    @Insert
    suspend fun insertTower(tower: LocalCellTower)

    @Query("SELECT * FROM local_cell_towers ORDER BY lastSeen DESC")
    fun getAllTowers(): Flow<List<LocalCellTower>>

    @Query("SELECT * FROM local_cell_towers WHERE cellId = :cellId")
    suspend fun getTowerById(cellId: String): LocalCellTower?

    @Query("SELECT * FROM local_cell_towers WHERE isUnderObservation = 1 ORDER BY lastSeen DESC")
    fun getObservedTowers(): Flow<List<LocalCellTower>>

    @Query("SELECT * FROM local_cell_towers WHERE isSuspicious = 1 ORDER BY lastSeen DESC")
    fun getSuspiciousTowers(): Flow<List<LocalCellTower>>

    @Query("SELECT * FROM local_cell_towers WHERE apiVerified = 1 ORDER BY lastSeen DESC")
    fun getVerifiedTowers(): Flow<List<LocalCellTower>>

    @Query("SELECT * FROM local_cell_towers WHERE isUserAdded = 1 ORDER BY firstDetected DESC")
    fun getUserAddedTowers(): Flow<List<LocalCellTower>>

    @Query("SELECT * FROM local_cell_towers WHERE status = :status ORDER BY lastSeen DESC")
    fun getTowersByStatus(status: TowerStatus): Flow<List<LocalCellTower>>

    @Query("""
        SELECT * FROM local_cell_towers 
        WHERE latitude IS NOT NULL AND longitude IS NOT NULL
        AND latitude BETWEEN :minLat AND :maxLat
        AND longitude BETWEEN :minLon AND :maxLon
        ORDER BY lastSeen DESC
    """)
    fun getTowersInArea(minLat: Double, maxLat: Double, minLon: Double, maxLon: Double): Flow<List<LocalCellTower>>

    @Query("""
        SELECT * FROM local_cell_towers 
        WHERE latitude IS NOT NULL AND longitude IS NOT NULL
        ORDER BY lastSeen DESC
        LIMIT :limit
    """)
    fun getRecentTowersWithLocation(limit: Int = 100): Flow<List<LocalCellTower>>

    @Query("SELECT COUNT(*) FROM local_cell_towers")
    suspend fun getTowerCount(): Int

    @Query("SELECT COUNT(*) FROM local_cell_towers WHERE isSuspicious = 1")
    suspend fun getSuspiciousTowerCount(): Int

    @Query("SELECT COUNT(*) FROM local_cell_towers WHERE apiVerified = 1")
    suspend fun getVerifiedTowerCount(): Int

    @Query("SELECT COUNT(*) FROM local_cell_towers WHERE isUnderObservation = 1")
    suspend fun getObservedTowerCount(): Int

    @Query("SELECT COUNT(*) FROM local_cell_towers WHERE latitude IS NOT NULL AND longitude IS NOT NULL")
    suspend fun getTowersWithLocationCount(): Int

    @Query("""
        SELECT * FROM local_cell_towers 
        WHERE cellId LIKE :searchQuery 
        OR baseStationName LIKE :searchQuery
        ORDER BY lastSeen DESC
    """)
    fun searchTowers(searchQuery: String): Flow<List<LocalCellTower>>

    @Query("UPDATE local_cell_towers SET isSuspicious = :suspicious WHERE cellId = :cellId")
    suspend fun updateSuspiciousStatus(cellId: String, suspicious: Boolean)

    @Query("UPDATE local_cell_towers SET apiVerified = :verified, apiSource = :source WHERE cellId = :cellId")
    suspend fun updateVerificationStatus(cellId: String, verified: Boolean, source: String)

    @Query("UPDATE local_cell_towers SET status = :status WHERE cellId = :cellId")
    suspend fun updateStatus(cellId: String, status: TowerStatus)

    @Query("UPDATE local_cell_towers SET isUnderObservation = :observed WHERE cellId = :cellId")
    suspend fun updateObservationStatus(cellId: String, observed: Boolean)

    @Query("UPDATE local_cell_towers SET trustLevel = :level WHERE cellId = :cellId")
    suspend fun updateTrustLevel(cellId: String, level: Int)

    @Query("UPDATE local_cell_towers SET lastSeen = :timestamp, detectionCount = detectionCount + 1 WHERE cellId = :cellId")
    suspend fun updateLastSeen(cellId: String, timestamp: Long = System.currentTimeMillis())

    @Query("DELETE FROM local_cell_towers WHERE cellId = :cellId")
    suspend fun deleteTower(cellId: String)

    @Query("DELETE FROM local_cell_towers WHERE isUnderObservation = 0 AND apiVerified = 1")
    suspend fun deleteVerifiedAndObserved()

    @Query("DELETE FROM local_cell_towers")
    suspend fun deleteAllTowers()

    @Query("UPDATE local_cell_towers SET isUnderObservation = 1 WHERE isUnderObservation = 0")
    suspend fun resumeAllObservations()

    @Query("UPDATE local_cell_towers SET isUnderObservation = 0")
    suspend fun pauseAllObservations()

    @Query("""
        UPDATE local_cell_towers 
        SET lastSeen = :timestamp 
        WHERE cellId IN (SELECT cellId FROM local_cell_towers WHERE isUnderObservation = 1 LIMIT :count)
    """)
    suspend fun updateMultipleTowersLastSeen(timestamp: Long, count: Int)
}
