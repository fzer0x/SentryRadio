package dev.fzer0x.imsicatcherdetector2.data

import androidx.room.Entity
import androidx.room.PrimaryKey

@Entity(tableName = "cell_towers")
data class CellTower(
    @PrimaryKey val cellId: String,
    val firstSeen: Long = System.currentTimeMillis(),
    val lastSeen: Long = System.currentTimeMillis(),
    val mcc: String,
    val mnc: String,
    val lac: Int,
    val rat: String,
    val pci: Int? = null,
    val ta: Int? = null,
    val dbm: Int? = null,
    val latitude: Double? = null,
    val longitude: Double? = null,
    val isVerified: Boolean = false,
    val isMissingInDb: Boolean = false,
    val range: Double? = null,
    val samples: Int? = null,
    val changeable: Boolean? = null,
    val neighborList: String? = null,
    val isBlocked: Boolean = false,
    val source: String? = null
)
