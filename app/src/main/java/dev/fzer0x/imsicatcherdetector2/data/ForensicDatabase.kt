package dev.fzer0x.imsicatcherdetector2.data

import android.content.Context
import androidx.room.Database
import androidx.room.Room
import androidx.room.RoomDatabase
import androidx.room.TypeConverters
import dev.fzer0x.imsicatcherdetector2.security.CveEntity

@Database(
    entities = [ForensicEvent::class, CellTower::class, LocalCellTower::class, CveEntity::class],
    version = 18,
    exportSchema = false
)
@TypeConverters(Converters::class)
abstract class ForensicDatabase : RoomDatabase() {
    abstract fun forensicDao(): ForensicDao
    abstract fun localCellTowerDao(): LocalCellTowerDao

    companion object {
        @Volatile
        private var INSTANCE: ForensicDatabase? = null

        fun getDatabase(context: Context): ForensicDatabase {
            return INSTANCE ?: synchronized(this) {
                val instance = Room.databaseBuilder(
                    context.applicationContext,
                    ForensicDatabase::class.java,
                    "forensic_database"
                )
                .fallbackToDestructiveMigration()
                .build()
                INSTANCE = instance
                instance
            }
        }
    }
}
