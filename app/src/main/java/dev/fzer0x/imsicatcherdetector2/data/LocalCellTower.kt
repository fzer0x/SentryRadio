package dev.fzer0x.imsicatcherdetector2.data

import androidx.room.Entity
import androidx.room.PrimaryKey

@Entity(tableName = "local_cell_towers")
data class LocalCellTower(
    @PrimaryKey val cellId: String,

    val mcc: String,
    val mnc: String,
    val lac: Int,
    val tac: Int? = null,
    val rat: String = "UNKNOWN",

    val latitude: Double? = null,
    val longitude: Double? = null,
    val accuracy: Float? = null,  

    val firstDetected: Long = System.currentTimeMillis(),
    val lastSeen: Long = System.currentTimeMillis(),
    val detectionCount: Int = 1,  

    val avgSignalStrength: Int? = null,
    val maxSignalStrength: Int? = null,
    val minSignalStrength: Int? = null,

    val neighborCount: Int = 0,
    val timingAdvance: Int? = null,
    val pci: Int? = null,
    val earfcn: Int? = null,

    val apiVerified: Boolean = false,           
    val apiSource: String? = null,              
    val apiLastChecked: Long? = null,           
    val apiTrustLevel: Int? = null,             
    val apiRange: Double? = null,               
    val apiSamples: Int? = null,                
    val apiResponse: String? = null,            

    val isUserAdded: Boolean = false,           
    val isSuspicious: Boolean = false,          
    val isUnderObservation: Boolean = true,     
    val offlineVerified: Boolean = false,       
    val offlineTrustLevel: Int = 0,             
    val observationNotes: String? = null,       

    val status: TowerStatus = TowerStatus.UNKNOWN,  
    val trustLevel: Int = 0,                        
    val verificationMethod: String? = null,         

    val baseStationName: String? = null,        
    val rawData: String? = null                 
)

enum class TowerStatus {
    UNKNOWN,            
    LOADING,            
    API_VERIFIED,       
    NORMAL,             
    SUSPICIOUS,         
    POTENTIALLY_ROGUE,  
    VERIFIED,           
    BLOCKED,            
    OFFLINE_FALLBACK    
}
