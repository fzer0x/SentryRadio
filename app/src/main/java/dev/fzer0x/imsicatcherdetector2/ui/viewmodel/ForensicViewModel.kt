package dev.fzer0x.imsicatcherdetector2.ui.viewmodel

import android.Manifest
import android.app.Application
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.location.Location
import android.location.LocationManager
import android.os.Build
import android.util.Log
import androidx.core.content.ContextCompat
import androidx.core.content.edit
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import dev.fzer0x.imsicatcherdetector2.data.CellTower
import dev.fzer0x.imsicatcherdetector2.data.EventType
import dev.fzer0x.imsicatcherdetector2.data.ForensicDatabase
import dev.fzer0x.imsicatcherdetector2.data.ForensicEvent
import dev.fzer0x.imsicatcherdetector2.service.BlockingEvent
import dev.fzer0x.imsicatcherdetector2.service.CellLookupManager
import dev.fzer0x.imsicatcherdetector2.service.ForensicService
import dev.fzer0x.imsicatcherdetector2.security.RootRepository
import dev.fzer0x.imsicatcherdetector2.security.VulnerabilityManager
import dev.fzer0x.imsicatcherdetector2.security.CveEntry
import dev.fzer0x.imsicatcherdetector2.utils.MemoryManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.*
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

data class UserSettings(
    val updateRate: Int = 15,
    val sensitivity: Int = 1,
    val logRootFeed: Boolean = false,
    val logRadioMetrics: Boolean = false,
    val logSuspiciousEvents: Boolean = false,
    val autoPcap: Boolean = true,
    val alarmSound: Boolean = true,
    val alarmVibe: Boolean = true,
    val beaconDbKey: String = "",
    val openCellIdKey: String = "",
    val useBeaconDb: Boolean = true,
    val useOpenCellId: Boolean = false,
    val showBlockedEvents: Boolean = false,
    val blockGsm: Boolean = false,
    val rejectA50: Boolean = false,
    val markFakeCells: Boolean = true,
    val forceLte: Boolean = false,
    val autoMitigation: Boolean = false,
    val zeroDayProtection: Boolean = false,
    val geoFencingProtection: Boolean = false,
    val advancedTelemetry: Boolean = false,
    val extendedPanicMode: Boolean = false,
    val realTimeModemMonitoring: Boolean = false,
    // 5G/SA Settings
    val force5gSa: Boolean = false,
    val force5gNsa: Boolean = false,
    val enable5gMonitoring: Boolean = true
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
    val rssiHistory: List<Int> = emptyList(),
    val cipherAlgo: String = "Scanning...",
    val rrcStatus: String = "N/A",
    val modemSnr: String = "N/A",
    val modemTemp: String = "N/A",
    val timingAdvance: Int? = null,
    // 5G/SA specific fields
    val is5gSa: Boolean = false,
    val is5gNsa: Boolean = false,
    val nrArfcn: String = "---",
    val nrBand: String = "---",
    val nrState: String = "---",
    val nrDuplexMode: String = "---",
    val nrMmWaveBand: Boolean = false,
    val nrScs: String = "---",
    val nrRsrp: String = "---",
    val nrRsrq: String = "---",
    val nrSinr: String = "---",
    val nrCsiRsrp: String = "---",
    val nrCsiRsrq: String = "---",
    val nrCsiSinr: String = "---",
    val nrSsbRsrp: String = "---",
    val nrSsbRsrq: String = "---",
    val nrSsbSinr: String = "---"
)

data class DashboardState(
    val sim0: SimState = SimState(),
    val sim1: SimState = SimState(),
    val threatLevel: Int = 0,
    val securityStatus: String = "Initializing...",
    val activeThreats: List<String> = emptyList(),
    val hasRoot: Boolean = false,
    val isXposedActive: Boolean = false,
    val isHardeningModuleActive: Boolean = false,
    val activeSimSlot: Int = 0,
    val vulnerabilities: List<CveEntry> = emptyList(),
    val detectedChipset: String = "Unknown",
    val detectedBaseband: String = "Unknown",
    val lastCveUpdate: String = "Never",
    val securityPatch: String = "Unknown",
    val moduleUpdateAvailable: Boolean = false,
    val currentModuleVersion: String = "Not installed",
    val availableModuleVersion: String = "",
    val totalCveCount: Int = 0,
    val chipsetCveCount: Int = 0,
    val isLoadingCve: Boolean = false
)

class ForensicViewModel(application: Application) : AndroidViewModel(application) {

    private val forensicDao = ForensicDatabase.getDatabase(application).forensicDao()
    private val vulnerabilityManager = VulnerabilityManager(application)
    
    private val masterKey = MasterKey.Builder(application)
        .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
        .build()

    private val encryptedPrefs = EncryptedSharedPreferences.create(
        application,
        "sentry_secure_settings",
        masterKey,
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
    )

    private val prefs = application.getSharedPreferences("sentry_settings", Context.MODE_PRIVATE)

    private val _settings = MutableStateFlow(loadSettings())
    val settings: StateFlow<UserSettings> = _settings.asStateFlow()

    private val _blockedCellIds = forensicDao.getBlockedCellIds()
        .stateIn(viewModelScope, SharingStarted.Eagerly, emptyList())
    val blockedCellIds: StateFlow<List<String>> = _blockedCellIds

    val allLogs: StateFlow<List<ForensicEvent>> = combine(
        forensicDao.getRecentLogs(1000),
        settings,
        _blockedCellIds
    ) { logs, currentSettings, blockedIds ->
        var filtered = logs
        if (!currentSettings.showBlockedEvents) filtered = filtered.filter { event -> event.cellId == null || !blockedIds.contains(event.cellId) }
        if (!currentSettings.logRadioMetrics) filtered = filtered.filter { event -> event.type != EventType.RADIO_METRICS_UPDATE }
        if (!currentSettings.logSuspiciousEvents) filtered = filtered.filter { event -> event.severity !in 5..7 }
        if (!currentSettings.logRootFeed) filtered = filtered.filter { event -> !event.description.contains("Signal Feed") }
        filtered.sortedByDescending { event -> event.timestamp }
    }.stateIn(viewModelScope, SharingStarted.Eagerly, emptyList())

    val allTowers: StateFlow<List<CellTower>> = flow {
        emit(forensicDao.getTowersInArea(-90.0, 90.0, -180.0, 180.0))
    }.stateIn(viewModelScope, SharingStarted.Eagerly, emptyList())

    private val _dashboardState = MutableStateFlow(DashboardState())
    val dashboardState: StateFlow<DashboardState> = _dashboardState.asStateFlow()

    private val _syncStatus = MutableSharedFlow<String>()
    val syncStatus = _syncStatus.asSharedFlow()

    private val _blockingEvents = MutableStateFlow<List<BlockingEvent>>(emptyList())
    val blockingEvents: StateFlow<List<BlockingEvent>> = _blockingEvents.asStateFlow()

    init {
        // Initialize memory management
        MemoryManager.initialize(getApplication())
        
        checkSystemStatus()
        observeBlockingEvents()
        startModemTelemetryPoller()
        startDataPruningJob()

        viewModelScope.launch {
            forensicDao.getRecentLogs(1000).collect { logs ->
                if (logs.isEmpty()) {
                    _dashboardState.update { it.copy(securityStatus = "No Data Logs") }
                    return@collect
                }
                val threshold = if(_settings.value.sensitivity == 0) 9 else 7
                val criticals = logs.filter { event -> event.severity >= threshold && (System.currentTimeMillis() - event.timestamp < 3600000) }
                val hasAlert = logs.any { event -> (event.type == EventType.IMSI_CATCHER_ALERT || event.type == EventType.CIPHERING_OFF) && (System.currentTimeMillis() - event.timestamp < 600000) }
                val score = if (hasAlert) 100 else (criticals.size * 20).coerceIn(0, 100)
                val status = when { score >= 90 -> "CRITICAL: THREAT DETECTED"; score > 50 -> "WARNING: ANOMALIES"; else -> "SYSTEM SECURE" }

                _dashboardState.update { state ->
                    state.copy(
                        sim0 = updateSimState(logs, 0, state.sim0),
                        sim1 = updateSimState(logs, 1, state.sim1),
                        threatLevel = score, securityStatus = status, activeThreats = criticals.map { event -> event.description }.distinct()
                    )
                }
            }
        }
    }

    fun isXposedModuleActive(): Boolean {
        // This method is hooked by our Xposed module to return true
        // If the hook is active, it will override this return value
        return false
    }

    private fun updateSimState(logs: List<ForensicEvent>, slot: Int, current: SimState): SimState {
        val simLogs = logs.filter { it.simSlot == slot }
        if (simLogs.isEmpty()) return current
        val latestCell = simLogs.firstOrNull { it.cellId != null }
        val signalHistory = simLogs.filter { it.signalStrength != null }.map { it.signalStrength!! }.take(20).reversed()
        
        // Enhanced 5G/SA detection
        val networkType = latestCell?.networkType ?: current.networkType
        val is5gSa = detect5gStandalone(simLogs, networkType)
        val is5gNsa = detect5gNonStandalone(simLogs, networkType)
        
        return current.copy(
            currentCellId = latestCell?.cellId ?: current.currentCellId, 
            mcc = latestCell?.mcc ?: current.mcc, 
            mnc = latestCell?.mnc ?: current.mnc,
            lac = latestCell?.lac?.toString() ?: current.lac, 
            tac = latestCell?.tac?.toString() ?: current.tac,
            pci = simLogs.firstOrNull { it.pci != null && it.pci != -1 }?.pci?.toString() ?: current.pci,
            earfcn = simLogs.firstOrNull { it.earfcn != null && it.earfcn != -1 }?.earfcn?.toString() ?: current.earfcn,
            networkType = enhanceNetworkType(networkType, is5gSa, is5gNsa), 
            neighborCount = latestCell?.neighborCount ?: current.neighborCount,
            signalStrength = simLogs.firstOrNull { it.signalStrength != null }?.signalStrength ?: current.signalStrength,
            isCipheringActive = !simLogs.any { it.type == EventType.CIPHERING_OFF && (System.currentTimeMillis() - it.timestamp < 600000) },
            rssiHistory = signalHistory,
            timingAdvance = simLogs.firstOrNull { it.timingAdvance != null && it.timingAdvance != -1 }?.timingAdvance,
            // 5G/SA specific updates
            is5gSa = is5gSa,
            is5gNsa = is5gNsa,
            nrArfcn = extractNrArfcn(simLogs) ?: current.nrArfcn,
            nrBand = extractNrBand(simLogs) ?: current.nrBand,
            nrState = extractNrState(simLogs) ?: current.nrState,
            nrDuplexMode = extractNrDuplexMode(simLogs) ?: current.nrDuplexMode,
            nrMmWaveBand = detectMmWaveBand(simLogs) ?: current.nrMmWaveBand,
            nrScs = extractNrScs(simLogs) ?: current.nrScs,
            nrRsrp = extractNrMetric(simLogs, "rsrp") ?: current.nrRsrp,
            nrRsrq = extractNrMetric(simLogs, "rsrq") ?: current.nrRsrq,
            nrSinr = extractNrMetric(simLogs, "sinr") ?: current.nrSinr,
            nrCsiRsrp = extractNrMetric(simLogs, "csi_rsrp") ?: current.nrCsiRsrp,
            nrCsiRsrq = extractNrMetric(simLogs, "csi_rsrq") ?: current.nrCsiRsrq,
            nrCsiSinr = extractNrMetric(simLogs, "csi_sinr") ?: current.nrCsiSinr,
            nrSsbRsrp = extractNrMetric(simLogs, "ssb_rsrp") ?: current.nrSsbRsrp,
            nrSsbRsrq = extractNrMetric(simLogs, "ssb_rsrq") ?: current.nrSsbRsrq,
            nrSsbSinr = extractNrMetric(simLogs, "ssb_sinr") ?: current.nrSsbSinr
        )
    }

    // 5G/SA Detection Helper Functions
    
    private fun detect5gStandalone(logs: List<ForensicEvent>, networkType: String?): Boolean {
        if (networkType != "NR") return false
        
        // Check for standalone indicators in logs
        val saIndicators = logs.any { log ->
            log.description.contains("5G SA", true) ||
            log.description.contains("Standalone", true) ||
            log.description.contains("NR_SA", true) ||
            log.rawData?.contains("ENDC_SUPPORT:false") == true ||
            log.rawData?.contains("NR_STANDALONE") == true
        }
        
        if (saIndicators) return true
        
        // Check telemetry for SA indicators
        val saTelemetry = _dashboardState.value.let { state ->
            state.sim0.rrcStatus.contains("CONNECTED", true) && 
            networkType == "NR" &&
            !state.sim0.rrcStatus.contains("LTE", true)
        }
        
        return saTelemetry
    }
    
    private fun detect5gNonStandalone(logs: List<ForensicEvent>, networkType: String?): Boolean {
        if (networkType != "NR") return false
        
        // Check for NSA indicators
        val nsaIndicators = logs.any { log ->
            log.description.contains("5G NSA", true) ||
            log.description.contains("Non-Standalone", true) ||
            log.description.contains("NR_NSA", true) ||
            log.description.contains("EN-DC", true) ||
            log.rawData?.contains("ENDC_SUPPORT:true") == true ||
            log.rawData?.contains("NR_NON_STANDALONE") == true
        }
        
        return nsaIndicators
    }
    
    private fun enhanceNetworkType(networkType: String?, is5gSa: Boolean, is5gNsa: Boolean): String {
        return when {
            is5gSa -> "5G SA (Standalone)"
            is5gNsa -> "5G NSA (EN-DC)"
            networkType == "NR" -> "5G NR"
            else -> networkType ?: "Unknown"
        }
    }
    
    private fun extractNrArfcn(logs: List<ForensicEvent>): String? {
        return logs.firstNotNullOfOrNull { log ->
            when {
                log.rawData?.contains("nrArfcn") == true -> {
                    Regex("nrArfcn[=:]\\s*(\\d+)").find(log.rawData)?.groupValues?.get(1)
                }
                log.rawData?.contains("nrArfcn") == true -> {
                    Regex("nrArfcn[=:]\\s*(\\d+)").find(log.rawData)?.groupValues?.get(1)
                }
                else -> null
            }
        }
    }
    
    private fun extractNrBand(logs: List<ForensicEvent>): String? {
        return logs.firstNotNullOfOrNull { log ->
            when {
                log.rawData?.contains("nrBand") == true -> {
                    Regex("nrBand[=:]\\s*(\\d+)").find(log.rawData)?.groupValues?.get(1)
                }
                log.rawData?.contains("band") == true -> {
                    Regex("band[=:]\\s*(n\\d+)").find(log.rawData)?.groupValues?.get(1)
                }
                else -> null
            }
        }
    }
    
    private fun extractNrState(logs: List<ForensicEvent>): String? {
        return logs.firstNotNullOfOrNull { log ->
            when {
                log.rawData?.contains("nrState") == true -> {
                    Regex("nrState[=:]\\s*(\\w+)").find(log.rawData)?.groupValues?.get(1)
                }
                log.description.contains("CONNECTED", true) -> "CONNECTED"
                log.description.contains("IDLE", true) -> "IDLE"
                else -> null
            }
        }
    }
    
    private fun extractNrDuplexMode(logs: List<ForensicEvent>): String? {
        return logs.firstNotNullOfOrNull { log ->
            when {
                log.rawData?.contains("TDD") == true -> "TDD"
                log.rawData?.contains("FDD") == true -> "FDD"
                log.description.contains("TDD", true) -> "TDD"
                log.description.contains("FDD", true) -> "FDD"
                else -> null
            }
        }
    }
    
    private fun detectMmWaveBand(logs: List<ForensicEvent>): Boolean? {
        val mmWaveBands = listOf("n257", "n258", "n260", "n261", "n262", "n263")
        return logs.any { log ->
            mmWaveBands.any { band ->
                log.rawData?.contains(band, true) == true ||
                log.description.contains(band, true)
            }
        }
    }
    
    private fun extractNrScs(logs: List<ForensicEvent>): String? {
        return logs.firstNotNullOfOrNull { log ->
            when {
                log.rawData?.contains("scs") == true -> {
                    Regex("scs[=:]\\s*(\\d+)").find(log.rawData)?.groupValues?.get(1)
                }
                log.rawData?.contains("subCarrierSpacing") == true -> {
                    Regex("subCarrierSpacing[=:]\\s*(\\d+)").find(log.rawData)?.groupValues?.get(1)
                }
                else -> null
            }
        }
    }
    
    private fun extractNrMetric(logs: List<ForensicEvent>, metric: String): String? {
        val metricPatterns = mapOf(
            "rsrp" to listOf("rsrp", "nrRsrp"),
            "rsrq" to listOf("rsrq", "nrRsrq"),
            "sinr" to listOf("sinr", "nrSinr"),
            "csi_rsrp" to listOf("csiRsrp", "csi_rsrp"),
            "csi_rsrq" to listOf("csiRsrq", "csi_rsrq"),
            "csi_sinr" to listOf("csiSinr", "csi_sinr"),
            "ssb_rsrp" to listOf("ssbRsrp", "ssb_rsrp"),
            "ssb_rsrq" to listOf("ssbRsrq", "ssb_rsrq"),
            "ssb_sinr" to listOf("ssbSinr", "ssb_sinr")
        )
        
        val patterns = metricPatterns[metric] ?: return null
        
        return logs.firstNotNullOfOrNull { log ->
            patterns.firstNotNullOfOrNull { pattern ->
                val regex = Regex("$pattern[=:]\\s*(-?\\d+)")
                regex.find(log.rawData ?: "")?.groupValues?.get(1)
            }
        }
    }

    private fun observeBlockingEvents() {
        viewModelScope.launch {
            _blockingEvents.value = ForensicService.getBlockingEvents().sortedByDescending { it.timestamp }
            ForensicService.blockingEventsFlow.collect { event ->
                _blockingEvents.update { (listOf(event) + it).take(ForensicService.MAX_BLOCKING_EVENTS) }
            }
        }
    }
    private fun startModemTelemetryPoller() {
        viewModelScope.launch {
            while (isActive) {
                if (_dashboardState.value.hasRoot) {
                    var algo = "A5/3 (Likely)"
                    var rrc = "N/A"
                    var snr = "N/A"
                    var temp = "N/A"

                    if (_dashboardState.value.isHardeningModuleActive) {
                        val result = RootRepository.execute("sentry-ctl --telemetry")
                        if (result.success) {
                            val output = result.output
                            algo = output.lines().find { it.contains("Algorithm", true) }?.split(":")?.getOrNull(1)?.trim() ?: algo
                            rrc = output.lines().find { it.contains("RRC State", true) }?.split(":")?.getOrNull(1)?.trim() ?: rrc
                            snr = output.lines().find { it.contains("Signal-SNR", true) }?.split(":")?.getOrNull(1)?.trim() ?: snr
                            temp = output.lines().find { it.contains("Baseband-Temp", true) }?.split(":")?.getOrNull(1)?.trim() ?: temp
                        }
                    } else {
                        val propsToCheck = listOf("vendor.radio.cipher_algo", "persist.vendor.radio.cipher_algo", "gsm.radio.cipher", "vendor.radio.encryption")
                        for (prop in propsToCheck) {
                            val res = RootRepository.execute("getprop $prop").output.trim()
                            if (res.isNotEmpty()) { algo = res; break }
                        }
                        val dumpsysOutput = RootRepository.execute("dumpsys telephony.registry").output
                        val rrcLines = dumpsysOutput.lines().filter { it.contains("mRrcState", true) }
                        rrc = if (rrcLines.isNotEmpty()) {
                            val activeSlot = _dashboardState.value.activeSimSlot
                            val line = if (activeSlot < rrcLines.size) rrcLines[activeSlot] else rrcLines.first()
                            if (line.contains("=")) line.split("=").last().trim() else "IDLE"
                        } else "IDLE"
                        snr = RootRepository.execute("getprop vendor.radio.snr").output.trim().ifEmpty { RootRepository.execute("getprop vendor.radio.rsrq").output.trim().ifEmpty { "N/A" } }
                        temp = RootRepository.execute("getprop vendor.modem.temp").output.trim().ifEmpty { RootRepository.execute("getprop vendor.modem.temperature").output.trim().ifEmpty { "N/A" } }
                    }
                    _dashboardState.update { it.copy(sim0 = it.sim0.copy(cipherAlgo = algo, rrcStatus = rrc, modemSnr = snr, modemTemp = temp), sim1 = it.sim1.copy(cipherAlgo = algo, rrcStatus = rrc, modemSnr = snr, modemTemp = temp)) }
                }
                delay(5000)
            }
        }
    }

    private fun startDataPruningJob() {
        viewModelScope.launch {
            while (isActive) {
                val fortyEightHoursAgo = System.currentTimeMillis() - (48 * 60 * 60 * 1000)
                withContext(Dispatchers.IO) { forensicDao.pruneOldRadioMetrics(fortyEightHoursAgo) }
                delay(12 * 60 * 60 * 1000)
            }
        }
    }

    fun setActiveSimSlot(slot: Int) { _dashboardState.update { it.copy(activeSimSlot = slot) } }

    fun toggleBlockCell(cellId: String) {
        viewModelScope.launch {
            val tower = forensicDao.getTowerById(cellId)
            if (tower != null) forensicDao.updateBlockStatus(cellId, !tower.isBlocked)
            else forensicDao.upsertTower(CellTower(cellId = cellId, mcc = "0", mnc = "0", lac = 0, rat = "UNKNOWN", isBlocked = true))
        }
    }

    fun unblockAllCells() { viewModelScope.launch { forensicDao.unblockAllTowers(); _syncStatus.emit("All cells unblocked") } }
    fun deleteBlockedLogs() { viewModelScope.launch { forensicDao.deleteBlockedLogs(); _syncStatus.emit("Deleted logs from blocked cells") } }

    /**
     * DEEP LOCATION SEARCH: Checks service cache first, then all providers.
     */
    fun getFreshLocation(): Location? {
        // 1. Try Service Cache first (Most reliable as it has an active listener)
        ForensicService.lastServiceLocation?.let { return it }

        val lm = getApplication<Application>().getSystemService(Context.LOCATION_SERVICE) as LocationManager
        if (ContextCompat.checkSelfPermission(getApplication(), Manifest.permission.ACCESS_COARSE_LOCATION) != PackageManager.PERMISSION_GRANTED) return null
        
        val providers = lm.getProviders(true)
        var bestLocation: Location? = null
        for (provider in providers) {
            val l = try { lm.getLastKnownLocation(provider) } catch (e: Exception) { null }
            if (l != null) {
                if (bestLocation == null || l.accuracy < bestLocation.accuracy) {
                    bestLocation = l
                }
            }
        }
        return bestLocation
    }

    fun saveMapState(lat: Double, lon: Double, zoom: Double) {
        prefs.edit {
            putFloat("last_map_lat", lat.toFloat())
            putFloat("last_map_lon", lon.toFloat())
            putFloat("last_map_zoom", zoom.toFloat())
            putBoolean("has_map_state", true)
        }
    }

    fun getLastMapState(): Triple<Double, Double, Double>? {
        if (!prefs.getBoolean("has_map_state", false)) return null
        return Triple(
            prefs.getFloat("last_map_lat", 0f).toDouble(),
            prefs.getFloat("last_map_lon", 0f).toDouble(),
            prefs.getFloat("last_map_zoom", 15f).toDouble()
        )
    }

    fun refreshTowerLocations() {
        val s = _settings.value
        viewModelScope.launch {
            val currentLoc = getFreshLocation()
            if (currentLoc == null) {
                _syncStatus.emit("Scan failed: No GPS fix. Try moving or opening Google Maps once.")
                return@launch
            }

            _syncStatus.emit("Syncing OpenCellID...")
            val lookupManager = CellLookupManager(s.beaconDbKey, s.openCellIdKey, s.useBeaconDb, s.useOpenCellId)

            withContext(Dispatchers.IO) {
                if (s.useOpenCellId && s.openCellIdKey.isNotBlank()) {
                    val towers = lookupManager.getTowersInArea(currentLoc.latitude, currentLoc.longitude)
                    if (towers.isEmpty()) {
                        _syncStatus.emit("No towers found. Check API Key or BBOX order.")
                    } else {
                        towers.forEach { n ->
                            if (n.lat != null && n.lon != null) {
                                forensicDao.upsertTower(CellTower(
                                    cellId = n.cellId ?: "OCID-${(Math.random()*100000).toInt()}", 
                                    mcc = n.mcc ?: "---", mnc = n.mnc ?: "---", lac = n.lac ?: 0,
                                    rat = n.rat ?: "LTE", latitude = n.lat, longitude = n.lon,
                                    isVerified = true, range = n.range ?: 1000.0, source = "OpenCellID API",
                                    lastSeen = System.currentTimeMillis()
                                ))
                            }
                        }
                        _syncStatus.emit("Success: Map populated with ${towers.size} towers.")
                    }
                } else {
                    _syncStatus.emit("OpenCellID API is disabled in settings!")
                }
            }
        }
    }

    fun checkSystemStatus() {
        viewModelScope.launch {
            val hasRoot = RootRepository.isRootAvailable()
            val isModule = if (hasRoot) RootRepository.fileExists("/data/adb/modules/sentry_radio_hardening/module.prop") else false
            val isXposed = isXposedModuleActive()
            
            // Check module version and updates
            val moduleUpdateInfo = checkModuleUpdate(hasRoot, isModule)
            
            _dashboardState.update { 
                it.copy(
                    hasRoot = hasRoot, 
                    isHardeningModuleActive = isModule, 
                    isXposedActive = isXposed,
                    moduleUpdateAvailable = moduleUpdateInfo.updateAvailable,
                    currentModuleVersion = moduleUpdateInfo.currentVersion,
                    availableModuleVersion = moduleUpdateInfo.availableVersion
                ) 
            }
            if (hasRoot) performFingerprinting()
            else {
                // Perform non-root fingerprinting if possible
                performFingerprinting()
            }
        }
    }

    private data class ModuleUpdateInfo(
        val updateAvailable: Boolean,
        val currentVersion: String,
        val availableVersion: String
    )

    private suspend fun checkModuleUpdate(hasRoot: Boolean, isModuleInstalled: Boolean): ModuleUpdateInfo {
        if (!hasRoot || !isModuleInstalled) {
            return ModuleUpdateInfo(
                updateAvailable = false,
                currentVersion = "Not installed",
                availableVersion = ""
            )
        }

        return try {
            // Get current installed module version
            val installedModuleProp = RootRepository.execute("cat /data/adb/modules/sentry_radio_hardening/module.prop").output
            val currentVersionCode = extractVersionCode(installedModuleProp)
            val currentVersion = extractVersion(installedModuleProp)

            // Get available module version from assets
            val assetManager = getApplication<Application>().assets
            val availableModuleProp = assetManager.open("sentry_module/module.prop").bufferedReader().readText()
            val availableVersionCode = extractVersionCode(availableModuleProp)
            val availableVersion = extractVersion(availableModuleProp)

            val updateAvailable = availableVersionCode > currentVersionCode

            ModuleUpdateInfo(
                updateAvailable = updateAvailable,
                currentVersion = if (currentVersionCode > 0) currentVersion else "Unknown",
                availableVersion = if (updateAvailable) availableVersion else ""
            )
        } catch (e: Exception) {
            ModuleUpdateInfo(
                updateAvailable = false,
                currentVersion = "Error reading version",
                availableVersion = ""
            )
        }
    }

    private fun extractVersionCode(moduleProp: String): Int {
        return moduleProp.lines()
            .find { it.startsWith("versionCode=") }
            ?.substringAfter("versionCode=")
            ?.trim()
            ?.toIntOrNull() ?: 0
    }

    private fun extractVersion(moduleProp: String): String {
        return moduleProp.lines()
            .find { it.startsWith("version=") }
            ?.substringAfter("version=")
            ?.trim() ?: "Unknown"
    }

    private fun convertCodenameToTechnicalName(codename: String): String {
        val normalized = codename.lowercase().trim()
        
        // Map codenames to technical names
        val codenameMap = mapOf(
            // =========================
            // Google Tensor Series
            // =========================
            "gs401" to "gs401",          // Tensor G4
            "tensor g4" to "gs401",     // Tensor G4 alias
            "zuma pro" to "gs401",      // Tensor G4 codename
            "zumapro" to "tele",       // Tensor G4 codename
            
            "gs301" to "gs301",         // Tensor G3
            "tensor g3" to "gs301",     // Tensor G3 alias
            "zuma" to "gs301",          // Tensor G3 codename
            
            "gs201" to "gs201",         // Tensor G2
            "tensor g2" to "gs201",     // Tensor G2 alias
            "cloudripper" to "gs201",   // Tensor G2 codename
            
            "gs101" to "gs101",         // Tensor G1
            "tensor g1" to "gs101",     // Tensor G1 alias
            "whitechapel" to "gs101",  // Tensor G1 codename
            
            // =========================
            // Qualcomm Snapdragon Series
            // =========================
            // Latest Snapdragon 8 Series
            "sm8750" to "sm8750",      // Snapdragon 8 Gen 4
            "storm" to "sm8750",       // Snapdragon 8 Gen 4 codename
            
            "sm8650" to "sm8650",      // Snapdragon 8 Gen 3
            "pineapple" to "sm8650",   // Snapdragon 8 Gen 3 codename
            
            "sm8550" to "sm8550",      // Snapdragon 8 Gen 2
            "kalama" to "sm8550",      // Snapdragon 8 Gen 2 codename
            
            "sm8450" to "sm8450",      // Snapdragon 8 Gen 1
            
            "sm8350" to "sm8350",      // Snapdragon 888
            "lahaina" to "sm8350",     // Snapdragon 888 codename
            
            "sm8250" to "sm8250",      // Snapdragon 865
            "kona" to "sm8250",        // Snapdragon 865 codename
            
            "sm8150" to "sm8150",      // Snapdragon 855
            "msmnile" to "sm8150",     // Snapdragon 855 codename
            
            "sdm845" to "sm8450",      // Snapdragon 845
            "sdm835" to "sm8350",      // Snapdragon 835
            "msm8998" to "msm8998",    // Snapdragon 835 alternative
            
            // =========================
            // MediaTek Dimensity Series
            // =========================
            "mt6990" to "mt6990",     // Dimensity 9400
            "mt6989" to "mt6989",     // Dimensity 9300
            "mt6985" to "mt6985",     // Dimensity 9200
            "mt6983" to "mt6983",     // Dimensity 9000
            "mt6895" to "mt6895",     // Dimensity 8100
            "mt6893" to "mt6893",     // Dimensity 1200
            "mt6879" to "mt6879",     // Dimensity 1000
            "mt6877" to "mt6877",     // Dimensity 900
            "mt6875" to "mt6875",     // Dimensity 800
            "mt6853" to "mt6853",     // Dimensity 700
            "mt6833" to "mt6833",     // Dimensity 600
            
            // =========================
            // MediaTek Helio Series
            // =========================
            "mt6765" to "mt6765",     // Helio P60
            "mt6779" to "mt6779",     // Helio G90T
            "mt6785" to "mt6785",     // Helio G80
            "mt6768" to "mt6768",     // Helio G85
            
            // =========================
            // Legacy MediaTek
            // =========================
            "mt6735" to "mt6735",     // MT6735
            "mt6737" to "mt6737",     // MT6737
            "mt6739" to "mt6739",     // MT6739
            "mt6750" to "mt6750",     // MT6750
            "mt6752" to "mt6752",     // MT6752
            "mt6795" to "mt6795",     // MT6795
            
            // =========================
            // Samsung Exynos Series
            // =========================
            "exynos2500" to "exynos2500", // Exynos 2500
            "s5e9925" to "exynos2500",   // Exynos 2500 codename
            
            "exynos2400" to "exynos2400", // Exynos 2400
            "s5e9945" to "exynos2400",   // Exynos 2400 codename
            
            "exynos2100" to "exynos2100", // Exynos 2100
            "s5e9840" to "exynos2100",   // Exynos 2100 codename
            
            "exynos1280" to "exynos1280", // Exynos 1280
            "s5e8835" to "exynos1280",   // Exynos 1280 codename
            
            "exynos1080" to "exynos1080", // Exynos 1080
            "s5e8825" to "exynos1080",   // Exynos 1080 codename
            
            "exynos990" to "exynos990",   // Exynos 990
            "s5e9830" to "exynos990",   // Exynos 990 codename
            
            "exynos980" to "exynos980",   // Exynos 980
            "s5e8820" to "exynos980",   // Exynos 980 codename
            
            "exynos9611" to "exynos9611", // Exynos 9611
            "s5e9823" to "exynos9611",   // Exynos 9611 codename
            
            "exynos9825" to "exynos9825", // Exynos 9825
            "s5e9810" to "exynos9825",   // Exynos 9825 codename
            
            "exynos9820" to "exynos9820", // Exynos 9820
            "s5e9800" to "exynos9820",   // Exynos 9820 codename
            
            // Legacy Exynos
            "exynos7420" to "exynos7420", // Exynos 7420
            "exynos8890" to "exynos8890", // Exynos 8890
            "exynos8895" to "exynos8895", // Exynos 8895
            "exynos9810" to "exynos9810", // Exynos 9810
            
            // =========================
            // UNISOC (Spreadtrum)
            // =========================
            "ums512" to "ums512",       // UNISOC T770
            "ums9620" to "ums9620",     // UNISOC T820
            "ums9230" to "ums9230",     // UNISOC T606
            "sc9863a" to "sc9863a",     // UNISOC SC9863A
            "sc9832e" to "sc9832e",     // UNISOC SC9832E
            "sc7731e" to "sc7731e",     // UNISOC SC7731E
            
            // Generic fallbacks
            "qcom" to "qcom",        // Generic Qualcomm fallback
            "msm" to "msm",         // Generic MSM fallback
            "mt" to "mt",           // Generic MediaTek fallback
            "exynos" to "exynos",    // Generic Exynos fallback
            "unisoc" to "unisoc"     // Generic UNISOC fallback
        )
        
        return codenameMap[normalized] ?: codename.uppercase()
    }

    private suspend fun performFingerprinting() {
        // Set loading state for initial fingerprinting
        _dashboardState.update { it.copy(isLoadingCve = true) }
        
        try {
            val rawChipset = if (_dashboardState.value.hasRoot) {
                RootRepository.execute("getprop ro.board.platform").output.trim().ifEmpty { Build.HARDWARE }
            } else {
                Build.HARDWARE
            }
            
            // Convert codenames to technical chipset names for API compatibility
            val chipset = convertCodenameToTechnicalName(rawChipset)
            
            val baseband = if (_dashboardState.value.hasRoot) {
                RootRepository.execute("getprop gsm.version.baseband").output.trim().ifEmpty { Build.getRadioVersion() ?: "Unknown" }
            } else {
                Build.getRadioVersion() ?: "Unknown"
            }
            
            val securityPatch = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                Build.VERSION.SECURITY_PATCH
            } else {
                "Unknown"
            }
            
            val (vulns, cveCounts) = vulnerabilityManager.checkVulnerabilities(chipset, baseband, securityPatch, forceRefresh = false)
            val (totalCveCount, chipsetCveCount) = cveCounts
            
            // Get last CVE update time from DAO and manual sync
            val allCached = forensicDao.getAllCves()
            val lastDbUpdateMillis = allCached.maxOfOrNull { it.lastUpdated } ?: 0L
            val lastManualSyncMillis = prefs.getLong("last_cve_sync_manual", 0L)
            val lastRefreshMillis = prefs.getLong("last_cve_sync", 0L)
            val lastWorkerSyncMillis = prefs.getLong("last_cve_worker_sync", 0L)
            
            // Use the most recent time
            val lastUpdateMillis = maxOf(lastDbUpdateMillis, lastManualSyncMillis, lastRefreshMillis, lastWorkerSyncMillis)
            val lastUpdateStr = if (lastUpdateMillis > 0) {
                SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.getDefault()).format(Date(lastUpdateMillis))
            } else {
                "Never"
            }

            _dashboardState.update { it.copy(
                vulnerabilities = vulns, 
                detectedChipset = chipset.uppercase(), 
                detectedBaseband = baseband,
                lastCveUpdate = lastUpdateStr,
                securityPatch = securityPatch,
                totalCveCount = totalCveCount,
                chipsetCveCount = chipsetCveCount,
                isLoadingCve = false
            ) }
        } catch (e: Exception) {
            // Stop loading on error
            _dashboardState.update { it.copy(isLoadingCve = false) }
            Log.e("ForensicViewModel", "Error during fingerprinting: ${e.message}")
        }
    }

    fun installHardeningModule(context: Context) {
        viewModelScope.launch {
            if (!_dashboardState.value.hasRoot) { _syncStatus.emit("Installation failed: Root required"); return@launch }
            withContext(Dispatchers.IO) {
                try {
                    _syncStatus.emit("Installing... Root permission may be required.")
                    val assetManager = context.assets; val moduleDir = "/data/adb/modules/sentry_radio_hardening"
                    RootRepository.execute("mkdir -p $moduleDir/common"); RootRepository.execute("mkdir -p $moduleDir/system/bin")
                    listOf("module.prop", "system.prop", "common/service.sh", "system/bin/sentry-ctl").forEach { path ->
                        assetManager.open("sentry_module/$path").use { input -> 
                            val content = input.bufferedReader().readText()
                            RootRepository.execute("echo '${content.replace("'", "'\\''")}' > $moduleDir/$path") 
                        }
                    }
                    RootRepository.execute("chmod 0644 $moduleDir/*.prop"); RootRepository.execute("chmod 0755 $moduleDir/common/*.sh"); RootRepository.execute("chmod 0755 $moduleDir/system/bin/*")
                    _syncStatus.emit("Installation successful! Reboot required."); checkSystemStatus()
                } catch (e: Exception) { _syncStatus.emit("Error installing module: ${e.message}") }
            }
        }
    }

    private fun loadSettings() = UserSettings(
        updateRate = prefs.getInt("update_rate", 15), sensitivity = prefs.getInt("sensitivity", 1), logRootFeed = prefs.getBoolean("log_root_feed", false), logRadioMetrics = prefs.getBoolean("log_radio_metrics", false), logSuspiciousEvents = prefs.getBoolean("log_suspicious_events", false), autoPcap = prefs.getBoolean("auto_pcap", true), alarmSound = prefs.getBoolean("alarm_sound", true), alarmVibe = prefs.getBoolean("alarm_vibe", true), beaconDbKey = encryptedPrefs.getString("beacon_db_key", "") ?: "", openCellIdKey = encryptedPrefs.getString("open_cell_id_key", "") ?: "", useBeaconDb = prefs.getBoolean("use_beacon_db", true), useOpenCellId = prefs.getBoolean("use_open_cell_id", false), showBlockedEvents = prefs.getBoolean("show_blocked_events", false), blockGsm = prefs.getBoolean("block_gsm", false), rejectA50 = prefs.getBoolean("reject_a50", false), markFakeCells = prefs.getBoolean("mark_fake_cells", true), forceLte = prefs.getBoolean("force_lte", false), autoMitigation = prefs.getBoolean("auto_mitigation", false), zeroDayProtection = prefs.getBoolean("zero_day_protection", false), geoFencingProtection = prefs.getBoolean("geo_fencing_protection", false), advancedTelemetry = prefs.getBoolean("advanced_telemetry", false), extendedPanicMode = prefs.getBoolean("extended_panic_mode", false), realTimeModemMonitoring = prefs.getBoolean("real_time_modem_monitoring", false)
    )

    fun updateUseBeaconDb(value: Boolean) { _settings.update { it.copy(useBeaconDb = value) }; prefs.edit { putBoolean("use_beacon_db", value) } }
    fun updateLogRadioMetrics(value: Boolean) { _settings.update { it.copy(logRadioMetrics = value) }; prefs.edit { putBoolean("log_radio_metrics", value) } }
    fun updateLogSuspiciousEvents(value: Boolean) { _settings.update { it.copy(logSuspiciousEvents = value) }; prefs.edit { putBoolean("log_suspicious_events", value) } }
    fun updateLogRootFeed(value: Boolean) { _settings.update { it.copy(logRootFeed = value) }; prefs.edit { putBoolean("log_root_feed", value) } }
    fun updateShowBlockedEvents(value: Boolean) { _settings.update { it.copy(showBlockedEvents = value) }; prefs.edit { putBoolean("show_blocked_events", value) } }
    fun updateSensitivity(value: Int) { _settings.update { it.copy(sensitivity = value) }; prefs.edit { putInt("sensitivity", value) } }
    fun updateBeaconDbKey(key: String) { _settings.update { it.copy(beaconDbKey = key) }; encryptedPrefs.edit { putString("beacon_db_key", key) } }
    fun updateOpenCellIdKey(key: String) { _settings.update { it.copy(openCellIdKey = key) }; encryptedPrefs.edit { putString("open_cell_id_key", key) } }
    fun updateUseOpenCellId(value: Boolean) { _settings.update { it.copy(useOpenCellId = value) }; prefs.edit { putBoolean("use_open_cell_id", value) } }
    fun updateBlockGsm(value: Boolean) { 
        _settings.update { it.copy(blockGsm = value) }; 
        prefs.edit { putBoolean("block_gsm", value) }; 
        getApplication<Application>().sendBroadcast(Intent("dev.fzer0x.imsicatcherdetector2.SETTINGS_CHANGED").apply { putExtra("blockGsm", value); putExtra("reject_a50", _settings.value.rejectA50) })
        
        // Hardware-level GSM blocking via sentry-ctl
        if (_dashboardState.value.isHardeningModuleActive) {
            viewModelScope.launch {
                try {
                    var result = RootRepository.execute("sentry-ctl --block-2g ${if (value) "true" else "false"}")
                    if (!result.success) {
                        result = RootRepository.execute("/data/adb/modules/sentry_radio_hardening/system/bin/sentry-ctl --block-2g ${if (value) "true" else "false"}")
                    }
                    _syncStatus.emit("Hardware GSM Blocking ${if (value) "enabled" else "disabled"}: ${if (result.success) "Success" else "Failed"}")
                } catch (e: Exception) {
                    _syncStatus.emit("Hardware GSM Blocking error: ${e.message}")
                }
            }
        }
    }
    fun updateRejectA50(value: Boolean) { 
        _settings.update { it.copy(rejectA50 = value) }; 
        prefs.edit { putBoolean("reject_a50", value) }; 
        getApplication<Application>().sendBroadcast(Intent("dev.fzer0x.imsicatcherdetector2.SETTINGS_CHANGED").apply { putExtra("blockGsm", _settings.value.blockGsm); putExtra("reject_a50", value) })
        
        // Hardware-level A5/0 cipher rejection via sentry-ctl
        if (_dashboardState.value.isHardeningModuleActive) {
            viewModelScope.launch {
                try {
                    var result = RootRepository.execute("sentry-ctl --reject-a50 ${if (value) "true" else "false"}")
                    if (!result.success) {
                        result = RootRepository.execute("/data/adb/modules/sentry_radio_hardening/system/bin/sentry-ctl --reject-a50 ${if (value) "true" else "false"}")
                    }
                    _syncStatus.emit("Hardware A5/0 Rejection ${if (value) "enabled" else "disabled"}: ${if (result.success) "Success" else "Failed"}")
                } catch (e: Exception) {
                    _syncStatus.emit("Hardware A5/0 Rejection error: ${e.message}")
                }
            }
        }
    }
    fun updateMarkFakeCells(value: Boolean) { _settings.update { it.copy(markFakeCells = value) }; prefs.edit { putBoolean("mark_fake_cells", value) } }
    fun updateForceLte(value: Boolean) { 
        _settings.update { it.copy(forceLte = value) }; 
        prefs.edit { putBoolean("force_lte", value) }
        
        // Hardware-level LTE forcing via sentry-ctl
        if (_dashboardState.value.isHardeningModuleActive) {
            viewModelScope.launch {
                try {
                    var result = RootRepository.execute("sentry-ctl --force-lte ${if (value) "true" else "false"}")
                    if (!result.success) {
                        result = RootRepository.execute("/data/adb/modules/sentry_radio_hardening/system/bin/sentry-ctl --force-lte ${if (value) "true" else "false"}")
                    }
                    _syncStatus.emit("Hardware LTE Forcing ${if (value) "enabled" else "disabled"}: ${if (result.success) "Success" else "Failed"}")
                } catch (e: Exception) {
                    _syncStatus.emit("Hardware LTE Forcing error: ${e.message}")
                }
            }
        }
    }
    fun updateAutoMitigation(value: Boolean) { _settings.update { it.copy(autoMitigation = value) }; prefs.edit { putBoolean("auto_mitigation", value) }; getApplication<Application>().sendBroadcast(Intent("dev.fzer0x.imsicatcherdetector2.SETTINGS_CHANGED").apply { putExtra("autoMitigation", value) }) }
    fun updateZeroDayProtection(value: Boolean) { _settings.update { it.copy(zeroDayProtection = value) }; prefs.edit { putBoolean("zero_day_protection", value) }
        if (_dashboardState.value.isHardeningModuleActive) {
            viewModelScope.launch {
                try {
                    val action = if (value) "enable" else "disable"
                    var result = RootRepository.execute("sentry-ctl --zero-day-protect $action")
                    if (!result.success) {
                        result = RootRepository.execute("/data/adb/modules/sentry_radio_hardening/system/bin/sentry-ctl --zero-day-protect $action")
                    }
                    _syncStatus.emit("Zero-Day Protection ${if (value) "enabled" else "disabled"}: ${if (result.success) "Success" else "Failed - ${result.error}"}")
                } catch (e: Exception) {
                    _syncStatus.emit("Zero-Day Protection failed: ${e.message}")
                }
            }
        }
    }
    fun updateGeoFencingProtection(value: Boolean) { _settings.update { it.copy(geoFencingProtection = value) }; prefs.edit { putBoolean("geo_fencing_protection", value) }
        if (_dashboardState.value.isHardeningModuleActive) {
            viewModelScope.launch {
                try {
                    val action = if (value) "enable" else "disable"
                    var result = RootRepository.execute("sentry-ctl --geo-protect $action")
                    if (!result.success) {
                        result = RootRepository.execute("/data/adb/modules/sentry_radio_hardening/system/bin/sentry-ctl --geo-protect $action")
                    }
                    _syncStatus.emit("Geo-Fencing Protection ${if (value) "enabled" else "disabled"}: ${if (result.success) "Success" else "Failed - ${result.error}"}")
                } catch (e: Exception) {
                    _syncStatus.emit("Geo-Fencing Protection failed: ${e.message}")
                }
            }
        }
    }
    fun updateAdvancedTelemetry(value: Boolean) { _settings.update { it.copy(advancedTelemetry = value) }; prefs.edit { putBoolean("advanced_telemetry", value) }
        if (_dashboardState.value.isHardeningModuleActive) {
            viewModelScope.launch {
                try {
                    val result = RootRepository.execute("setprop persist.sentry.advanced_telemetry ${if (value) 1 else 0}")
                    _syncStatus.emit("Advanced Telemetry ${if (value) "enabled" else "disabled"}: ${if (result.success) "Success" else "Failed - ${result.error}"}")
                } catch (e: Exception) {
                    _syncStatus.emit("Advanced Telemetry failed: ${e.message}")
                }
            }
        }
    }
    fun updateExtendedPanicMode(value: Boolean) { _settings.update { it.copy(extendedPanicMode = value) }; prefs.edit { putBoolean("extended_panic_mode", value) }
        if (_dashboardState.value.isHardeningModuleActive) {
            viewModelScope.launch {
                try {
                    val result = RootRepository.execute("setprop persist.sentry.panic_extended ${if (value) 1 else 0}")
                    _syncStatus.emit("Extended Panic Mode ${if (value) "enabled" else "disabled"}: ${if (result.success) "Success" else "Failed - ${result.error}"}")
                } catch (e: Exception) {
                    _syncStatus.emit("Extended Panic Mode failed: ${e.message}")
                }
            }
        }
    }
    fun updateRealTimeModemMonitoring(value: Boolean) { _settings.update { it.copy(realTimeModemMonitoring = value) }; prefs.edit { putBoolean("real_time_modem_monitoring", value) }
        if (_dashboardState.value.isHardeningModuleActive) {
            viewModelScope.launch {
                try {
                    val result = RootRepository.execute("setprop persist.sentry.continuous_monitor ${if (value) 1 else 0}")
                    _syncStatus.emit("Real-time Modem Monitoring ${if (value) "enabled" else "disabled"}: ${if (result.success) "Success" else "Failed - ${result.error}"}")
                } catch (e: Exception) {
                    _syncStatus.emit("Real-time Modem Monitoring failed: ${e.message}")
                }
            }
        }
    }
    fun resetRadio() { viewModelScope.launch { if (_dashboardState.value.hasRoot) { 
        var result = RootRepository.execute("sentry-ctl --reset-radio")
        if (!result.success) {
            result = RootRepository.execute("/data/adb/modules/sentry_radio_hardening/system/bin/sentry-ctl --reset-radio")
        }
        _syncStatus.emit("Radio Reset command sent") 
    } } }
    fun triggerPanic() { viewModelScope.launch { if (_dashboardState.value.hasRoot) { 
        if (_settings.value.extendedPanicMode) {
            // Extended Panic Mode mit verbesserter Implementierung
            var result = RootRepository.execute("sentry-ctl --panic-extended")
            if (!result.success) {
                result = RootRepository.execute("/data/adb/modules/sentry_radio_hardening/system/bin/sentry-ctl --panic-extended")
            }
            _syncStatus.emit("EXTENDED PANIC MODE ACTIVATED")
            
            // Zusätzliche Hardware-Shutdown Befehle
            var hardShutdown = RootRepository.execute("sentry-ctl --hard-shutdown")
            if (!hardShutdown.success) {
                hardShutdown = RootRepository.execute("/data/adb/modules/sentry_radio_hardening/system/bin/sentry-ctl --hard-shutdown")
            }
            _syncStatus.emit("Hardware radio shutdown executed")
            
            // Validierung nach 2 Sekunden
            kotlinx.coroutines.delay(2000)
            var validation = RootRepository.execute("sentry-ctl --validate-panic")
            if (!validation.success) {
                validation = RootRepository.execute("/data/adb/modules/sentry_radio_hardening/system/bin/sentry-ctl --validate-panic")
            }
            if (validation.success) {
                _syncStatus.emit("PANIC VALIDATION: ${validation.output}")
            } else {
                _syncStatus.emit("PANIC VALIDATION FAILED: ${validation.error}")
            }
        } else {
            var result = RootRepository.execute("sentry-ctl --panic")
            if (!result.success) {
                result = RootRepository.execute("/data/adb/modules/sentry_radio_hardening/system/bin/sentry-ctl --panic")
            }
            _syncStatus.emit("PANIC MODE ACTIVATED")
        }
    } } }
    fun recoverFromPanic() { viewModelScope.launch { 
    if (_dashboardState.value.hasRoot && _dashboardState.value.isHardeningModuleActive) {
        var recovery = RootRepository.execute("sentry-ctl --recover")
        if (!recovery.success) {
            recovery = RootRepository.execute("/data/adb/modules/sentry_radio_hardening/system/bin/sentry-ctl --recover")
        }
        
        if (recovery.success) {
            _syncStatus.emit("RECOVERY SUCCESSFUL:\n${recovery.output}")
        } else {
            _syncStatus.emit("RECOVERY FAILED: ${recovery.error}")
        }
    } else {
        _syncStatus.emit("Recovery requires root and hardening module")
    }
} }
    
fun validatePanicMode() { viewModelScope.launch { 
    if (_dashboardState.value.hasRoot && _dashboardState.value.isHardeningModuleActive) {
        // Versuche zuerst über PATH, dann über vollen Pfad
        var validation = RootRepository.execute("sentry-ctl --validate-panic")
        if (!validation.success) {
            validation = RootRepository.execute("/data/adb/modules/sentry_radio_hardening/system/bin/sentry-ctl --validate-panic")
        }
        
        if (validation.success) {
            _syncStatus.emit("PANIC VALIDATION SUCCESSFUL:\n${validation.output}")
        } else {
            _syncStatus.emit("PANIC VALIDATION FAILED: ${validation.error}")
        }
    } else {
        _syncStatus.emit("Validation requires root and hardening module")
    }
} }
    
fun triggerForensicDump() { viewModelScope.launch { if (_dashboardState.value.hasRoot && _dashboardState.value.isHardeningModuleActive) { 
        RootRepository.execute("sentry-ctl --forensic-dump")
        _syncStatus.emit("Forensic dump completed")
    } else {
        _syncStatus.emit("Forensic dump requires hardening module")
    } } }
    fun syncCveDatabase() { viewModelScope.launch { if (_dashboardState.value.hasRoot && _dashboardState.value.isHardeningModuleActive) { 
        RootRepository.execute("sentry-ctl --zero-day-protect sync")
        _syncStatus.emit("CVE database sync initiated")
        
        // Update the last CVE sync time immediately and persist it
        val currentTime = System.currentTimeMillis()
        val currentTimeStr = SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.getDefault()).format(Date(currentTime))
        
        // Save to persistent storage
        prefs.edit { putLong("last_cve_sync_manual", currentTime) }
        
        // Update dashboard state
        _dashboardState.update { it.copy(lastCveUpdate = currentTimeStr) }
        
        // Also trigger a vulnerability check to refresh the data
        performFingerprinting()
        
        _syncStatus.emit("CVE database sync completed at $currentTimeStr")
    } else {
        _syncStatus.emit("CVE sync requires hardening module")
    } } }
    
    fun refreshCveDatabase() { viewModelScope.launch {
        try {
            // Set loading state
            _dashboardState.update { it.copy(isLoadingCve = true) }
            _syncStatus.emit("Checking for new CVEs...")
            
            // Get current device info
            val currentState = _dashboardState.value
            val chipset = currentState.detectedChipset
            val baseband = currentState.detectedBaseband
            val securityPatch = currentState.securityPatch
            
            // Refresh vulnerability database (inkrementell - nur neue CVEs hinzufügen)
            val (vulns, cveCounts) = vulnerabilityManager.checkVulnerabilities(chipset, baseband, securityPatch, forceRefresh = false)
            val (totalCveCount, chipsetCveCount) = cveCounts
            
            // Update last sync time
            val currentTime = System.currentTimeMillis()
            val currentTimeStr = SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.getDefault()).format(Date(currentTime))
            
            // Save to persistent storage
            prefs.edit { putLong("last_cve_sync", currentTime) }
            
            // Update dashboard state with fresh data and stop loading
            _dashboardState.update { 
                it.copy(
                    vulnerabilities = vulns,
                    totalCveCount = totalCveCount,
                    chipsetCveCount = chipsetCveCount,
                    lastCveUpdate = currentTimeStr,
                    isLoadingCve = false
                )
            }
            
            _syncStatus.emit("CVE database updated - keeping existing entries, added new ones at $currentTimeStr")
        } catch (e: Exception) {
            // Stop loading on error
            _dashboardState.update { it.copy(isLoadingCve = false) }
            _syncStatus.emit("Failed to refresh CVE database: ${e.message}")
        }
    } }
    fun clearLogs() { viewModelScope.launch { forensicDao.clearLogs() } }
    fun exportLogsToPcap(context: Context) { /* ... */ }
}
