package dev.fzer0x.imsicatcherdetector2.data

import androidx.room.TypeConverter

class Converters {
    @TypeConverter
    fun fromEventType(value: EventType): String {
        return value.name
    }

    @TypeConverter
    fun toEventType(value: String): EventType {
        return try {
            EventType.valueOf(value)
        } catch (e: Exception) {
            EventType.RADIO_METRICS_UPDATE
        }
    }

    @TypeConverter
    fun fromTowerStatus(value: TowerStatus): String {
        return value.name
    }

    @TypeConverter
    fun toTowerStatus(value: String): TowerStatus {
        return try {
            TowerStatus.valueOf(value)
        } catch (e: Exception) {
            TowerStatus.UNKNOWN
        }
    }
}
