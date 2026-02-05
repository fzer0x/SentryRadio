package dev.fzer0x.imsicatcherdetector2.ui.viewmodel

import android.app.Application
import android.content.Context
import android.content.Intent
import android.util.Log
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import dev.fzer0x.imsicatcherdetector2.data.CellTower
import dev.fzer0x.imsicatcherdetector2.data.EventType
import dev.fzer0x.imsicatcherdetector2.data.ForensicDatabase
import dev.fzer0x.imsicatcherdetector2.data.ForensicEvent
import dev.fzer0x.imsicatcherdetector2.service.CellLookupManager
import kotlinx.coroutines.flow.*
import kotlinx.coroutines.launch

data class UserSettings(
    val updateRate: Int = 15,
    val sensitivity: Int = 1,
    val logRootFeed: Boolean = false,
    val logRadioMetrics: Boolean = false,
    val logSuspiciousEvents: Boolean = true,
    val autoPcap: Boolean = true,
    val alarmSound: Boolean = true,
    val alarmVibe: Boolean = true,
    val openCellIdKey: String = "",
    val unwiredLabsKey: String = "",
    val useBeaconDb: Boolean = true,
    val useOpenCellId: Boolean = false,
    val useUnwiredLabs: Boolean = false,
    val showBlockedEvents: Boolean = false
)

data class SimState(
    val currentCellId: String = "N/A",
    val mcc: String = "---",
    val mnc: String = "---",
    val lac: String = "---",
    val tac: String = "---",
    val pci: String = "---",
    val earfcn: String = "---",
    val signalStrength: Int = -120,
    val networkType: String = "Scanning...",
    val isCipheringActive: Boolean = true,
    val neighborCount: Int = 0,
    val rssiHistory: List<Int> = emptyList()
)

data class DashboardState(
    val sim0: SimState = SimState(),
    val sim1: SimState = SimState(),
    val threatLevel: Int = 0,
    val securityStatus: String = "Initializing...",
    val activeThreats: List<String> = emptyList(),
    val hasRoot: Boolean = false,
    val isXposedActive: Boolean = false,
    val activeSimSlot: Int = 0
)

class ForensicViewModel(application: Application) : AndroidViewModel(application) {

    private val forensicDao = ForensicDatabase.getDatabase(application).forensicDao()
    private val prefs = application.getSharedPreferences("sentry_settings", Context.MODE_PRIVATE)

    private val _settings = MutableStateFlow(loadSettings())
    val settings: StateFlow<UserSettings> = _settings.asStateFlow()

    private val _blockedCellIds = forensicDao.getBlockedCellIds()
        .stateIn(viewModelScope, SharingStarted.Eagerly, emptyList())
    val blockedCellIds: StateFlow<List<String>> = _blockedCellIds

    val allLogs: StateFlow<List<ForensicEvent>> = combine(
        forensicDao.getAllLogs(),
        settings,
        _blockedCellIds
    ) { logs, currentSettings, blockedIds ->
        var filtered = logs
        
        if (!currentSettings.showBlockedEvents) {
            filtered = filtered.filter { it.cellId == null || !blockedIds.contains(it.cellId) }
        }

        if (!currentSettings.logRadioMetrics) {
            filtered = filtered.filter { it.type != EventType.RADIO_METRICS_UPDATE }
        }

        if (!currentSettings.logSuspiciousEvents) {
            filtered = filtered.filter { it.severity < 5 || it.severity > 7 }
        }

        if (!currentSettings.logRootFeed) {
            filtered = filtered.filter { 
                !it.description.contains("Live Signal Feed") && 
                !it.description.contains("Real-time Signal Update")
            }
        }
        
        filtered.sortedByDescending { it.timestamp }
    }.stateIn(viewModelScope, SharingStarted.Eagerly, emptyList())

    val allTowers: StateFlow<List<CellTower>> = forensicDao.getAllTowers()
        .stateIn(viewModelScope, SharingStarted.Eagerly, emptyList())

    private val _dashboardState = MutableStateFlow(DashboardState())
    val dashboardState: StateFlow<DashboardState> = _dashboardState.asStateFlow()

    private val _syncStatus = MutableSharedFlow<String>()
    val syncStatus = _syncStatus.asSharedFlow()

    init {
        checkSystemStatus()
        
        forensicDao.getAllLogs().onEach { logs ->
            if (logs.isEmpty()) {
                _dashboardState.update { it.copy(securityStatus = "No Data Logs") }
                return@onEach
            }

            val threshold = when(_settings.value.sensitivity) { 0 -> 9 else -> 7 }
            val criticals = logs.filter { it.severity >= threshold && (System.currentTimeMillis() - it.timestamp < 3600000) }
            val threats = criticals.map { it.description }.distinct()
            val hasAlert = logs.any { (it.type == EventType.IMSI_CATCHER_ALERT || it.type == EventType.CIPHERING_OFF) && (System.currentTimeMillis() - it.timestamp < 600000) }
            val score = if (hasAlert) 100 else (criticals.size * 20).coerceIn(0, 100)
            
            val status = when {
                score >= 90 -> "CRITICAL: THREAT DETECTED"
                score > 50 -> "WARNING: ANOMALIES"
                else -> "SYSTEM SECURE"
            }

            _dashboardState.update { state ->
                state.copy(
                    sim0 = updateSimState(logs, 0, state.sim0),
                    sim1 = updateSimState(logs, 1, state.sim1),
                    threatLevel = score,
                    securityStatus = status,
                    activeThreats = threats,
                    isXposedActive = isXposedModuleActive() || logs.any { it.description.contains("Xposed") || it.description.contains("ENGINE ACTIVE") }
                )
            }
        }.launchIn(viewModelScope)
    }

    private fun updateSimState(logs: List<ForensicEvent>, slot: Int, current: SimState): SimState {
        val simLogs = logs.filter { it.simSlot == slot }
        if (simLogs.isEmpty()) return current

        val latestCell = simLogs.firstOrNull { it.cellId != null }
        val latestPci = simLogs.firstOrNull { it.pci != null && it.pci != -1 }
        val latestEarfcn = simLogs.firstOrNull { it.earfcn != null && it.earfcn != -1 }
        val latestSignal = simLogs.firstOrNull { it.signalStrength != null }
        val signalHistory = simLogs.filter { it.signalStrength != null }.take(20).map { it.signalStrength!! }.reversed()

        return current.copy(
            currentCellId = latestCell?.cellId ?: current.currentCellId,
            mcc = latestCell?.mcc ?: current.mcc,
            mnc = latestCell?.mnc ?: current.mnc,
            lac = latestCell?.lac?.toString() ?: current.lac,
            tac = latestCell?.tac?.toString() ?: current.tac,
            pci = latestPci?.pci?.toString() ?: current.pci,
            earfcn = latestEarfcn?.earfcn?.toString() ?: current.earfcn,
            networkType = latestCell?.networkType ?: current.networkType,
            neighborCount = latestCell?.neighborCount ?: current.neighborCount,
            signalStrength = latestSignal?.signalStrength ?: current.signalStrength,
            isCipheringActive = !simLogs.any { it.type == EventType.CIPHERING_OFF && (System.currentTimeMillis() - it.timestamp < 600000) },
            rssiHistory = signalHistory
        )
    }

    fun setActiveSimSlot(slot: Int) {
        _dashboardState.update { it.copy(activeSimSlot = slot) }
    }

    private fun isXposedModuleActive(): Boolean {
        return false 
    }

    fun toggleBlockCell(cellId: String) {
        viewModelScope.launch {
            val tower = forensicDao.getTowerById(cellId)
            if (tower != null) {
                forensicDao.updateBlockStatus(cellId, !tower.isBlocked)
            } else {
                forensicDao.upsertTower(CellTower(cellId = cellId, mcc = "0", mnc = "0", lac = 0, rat = "UNKNOWN", isBlocked = true))
            }
        }
    }
    
    fun isCellBlocked(cellId: String?): Boolean {
        if (cellId == null) return false
        return _blockedCellIds.value.contains(cellId)
    }

    fun unblockAllCells() {
        viewModelScope.launch {
            forensicDao.unblockAllTowers()
            _syncStatus.emit("All cells unblocked")
        }
    }

    fun deleteBlockedLogs() {
        viewModelScope.launch {
            forensicDao.deleteBlockedLogs()
            _syncStatus.emit("Deleted logs from blocked cells")
        }
    }

    fun refreshTowerLocations() {
        val s = _settings.value
        viewModelScope.launch {
            val towersToRefresh = allTowers.value.filter { !it.isVerified }
            if (towersToRefresh.isEmpty()) {
                _syncStatus.emit("No new towers to verify")
                return@launch
            }

            val lookupManager = CellLookupManager(
                openCellIdKey = s.openCellIdKey,
                unwiredLabsKey = s.unwiredLabsKey,
                useBeaconDb = s.useBeaconDb,
                useOpenCellId = s.useOpenCellId,
                useUnwiredLabs = s.useUnwiredLabs
            )
            var foundCount = 0
            var missingCount = 0

            towersToRefresh.forEach { tower ->
                val result = lookupManager.lookup(tower.mcc, tower.mnc, tower.lac, tower.cellId)
                if (result.isFound && result.lat != null) {
                    foundCount++
                    forensicDao.upsertTower(tower.copy(
                        latitude = result.lat, 
                        longitude = result.lon, 
                        isVerified = true,
                        isMissingInDb = false,
                        range = result.range,
                        samples = result.samples,
                        changeable = result.changeable,
                        lastSeen = System.currentTimeMillis()
                    ))
                } else {
                    missingCount++
                    forensicDao.upsertTower(tower.copy(isMissingInDb = true, isVerified = false))
                }
            }
            
            if (foundCount > 0) {
                _syncStatus.emit("Success: Verified $foundCount towers")
            } else if (missingCount > 0) {
                _syncStatus.emit("Alert: $missingCount towers not found in DBs!")
            }
        }
    }

    private fun checkSystemStatus() {
        viewModelScope.launch {
            val hasSu = try { Runtime.getRuntime().exec("su -c id").waitFor() == 0 } catch (e: Exception) { false }
            _dashboardState.update { it.copy(hasRoot = hasSu) }
        }
    }

    private fun loadSettings() = UserSettings(
        updateRate = prefs.getInt("update_rate", 15),
        sensitivity = prefs.getInt("sensitivity", 1),
        logRootFeed = prefs.getBoolean("log_root_feed", false),
        logRadioMetrics = prefs.getBoolean("log_radio_metrics", false),
        logSuspiciousEvents = prefs.getBoolean("log_suspicious_events", true),
        autoPcap = prefs.getBoolean("auto_pcap", true),
        alarmSound = prefs.getBoolean("alarm_sound", true),
        alarmVibe = prefs.getBoolean("alarm_vibe", true),
        openCellIdKey = prefs.getString("opencellid_key", "") ?: "",
        unwiredLabsKey = prefs.getString("unwiredlabs_key", "") ?: "",
        useBeaconDb = prefs.getBoolean("use_beacondb", true),
        useOpenCellId = prefs.getBoolean("use_opencellid", false),
        useUnwiredLabs = prefs.getBoolean("use_unwiredlabs", false),
        showBlockedEvents = prefs.getBoolean("show_blocked_events", false)
    )

    fun updateOpenCellIdKey(key: String) {
        _settings.update { it.copy(openCellIdKey = key) }
        prefs.edit().putString("opencellid_key", key).apply()
    }

    fun updateUnwiredLabsKey(key: String) {
        _settings.update { it.copy(unwiredLabsKey = key) }
        prefs.edit().putString("unwiredlabs_key", key).apply()
    }

    fun updateUseBeaconDb(value: Boolean) {
        _settings.update { it.copy(useBeaconDb = value) }
        prefs.edit().putBoolean("use_beacondb", value).apply()
    }

    fun updateUseOpenCellId(value: Boolean) {
        _settings.update { it.copy(useOpenCellId = value) }
        prefs.edit().putBoolean("use_opencellid", value).apply()
    }

    fun updateUseUnwiredLabs(value: Boolean) {
        _settings.update { it.copy(useUnwiredLabs = value) }
        prefs.edit().putBoolean("use_unwiredlabs", value).apply()
    }

    fun updateSensitivity(value: Int) { 
        _settings.update { it.copy(sensitivity = value) }
        prefs.edit().putInt("sensitivity", value).apply() 
    }
    
    fun updateRate(value: Int) { 
        _settings.update { it.copy(updateRate = value) }
        prefs.edit().putInt("update_rate", value).apply() 
    }
    
    fun updateLogRootFeed(value: Boolean) { 
        _settings.update { it.copy(logRootFeed = value) }
        prefs.edit().putBoolean("log_root_feed", value).apply() 
    }

    fun updateLogRadioMetrics(value: Boolean) {
        _settings.update { it.copy(logRadioMetrics = value) }
        prefs.edit().putBoolean("log_radio_metrics", value).apply()
    }

    fun updateLogSuspiciousEvents(value: Boolean) {
        _settings.update { it.copy(logSuspiciousEvents = value) }
        prefs.edit().putBoolean("log_suspicious_events", value).apply()
    }
    
    fun updateAutoPcap(value: Boolean) { 
        _settings.update { it.copy(autoPcap = value) }
        prefs.edit().putBoolean("auto_pcap", value).apply() 
    }
    
    fun updateAlarmSound(value: Boolean) { 
        _settings.update { it.copy(alarmSound = value) }
        prefs.edit().putBoolean("alarm_sound", value).apply() 
    }
    
    fun updateAlarmVibe(value: Boolean) { 
        _settings.update { it.copy(alarmVibe = value) }
        prefs.edit().putBoolean("alarm_vibe", value).apply() 
    }
    
    fun updateShowBlockedEvents(value: Boolean) {
        _settings.update { it.copy(showBlockedEvents = value) }
        prefs.edit().putBoolean("show_blocked_events", value).apply()
    }

    fun clearLogs() { viewModelScope.launch { forensicDao.clearLogs() } }

    fun exportLogsToPcap(context: Context) { }
    fun exportLogsToJson(context: Context) { }
}
