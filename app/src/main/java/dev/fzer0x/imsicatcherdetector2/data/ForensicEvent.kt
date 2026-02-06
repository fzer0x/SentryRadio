package dev.fzer0x.imsicatcherdetector2.data

import androidx.room.Entity
import androidx.room.PrimaryKey

enum class EventType {
    IMSI_CATCHER_ALERT,
    SILENT_SMS,
    CELL_DOWNGRADE,
    CIPHERING_OFF,
    LOCATION_ANOMALY,
    RRC_STATE_CHANGE,
    RADIO_METRICS_UPDATE,
    BASEBAND_FINGERPRINT,
    TIMING_ADVANCE_ANOMALY
}

@Entity(tableName = "forensic_logs")
data class ForensicEvent(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    val timestamp: Long = System.currentTimeMillis(),
    val type: EventType,
    val severity: Int,
    val description: String,
    val cellId: String?,
    val lac: Int?,
    val tac: Int? = null,
    val pci: Int? = null,
    val earfcn: Int? = null,
    val mnc: String?,
    val mcc: String?,
    val networkType: String? = null,
    val signalStrength: Int?,
    val neighborCount: Int? = null,
    val timingAdvance: Int? = null,
    val basebandVersion: String? = null,
    val rawData: String? = null,
    val simSlot: Int = 0,
    val isExported: Boolean = false
)
