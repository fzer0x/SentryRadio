package dev.fzer0x.imsicatcherdetector2.data

import android.content.Context
import androidx.room.Database
import androidx.room.Room
import androidx.room.RoomDatabase

@Database(
    entities = [ForensicEvent::class, CellTower::class, LocalCellTower::class],
    version = 14,
    exportSchema = false
)
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
