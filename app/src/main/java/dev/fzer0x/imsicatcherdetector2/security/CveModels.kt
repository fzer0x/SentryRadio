package dev.fzer0x.imsicatcherdetector2.security

import androidx.room.Entity
import androidx.room.PrimaryKey

data class CveEntry(
    val cveId: String,
    val description: String,
    val severity: Double,
    val publishedDate: Long,
    val affectedProducts: List<String> = emptyList(),
    val isRelevantForImsiCatcher: Boolean = false
)

@Entity(tableName = "cve_cache")
data class CveEntity(
    @PrimaryKey val cveId: String,
    val description: String,
    val severity: Double,
    val publishedDate: Long,
    val productsSerialized: String,
    val lastUpdated: Long = System.currentTimeMillis()
)
