package dev.fzer0x.imsicatcherdetector2.service

import android.annotation.SuppressLint
import android.app.*
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.location.Location
import android.os.Build
import android.os.IBinder
import android.os.Looper
import android.util.Log
import androidx.core.app.NotificationCompat
import com.google.android.gms.location.*
import dev.fzer0x.imsicatcherdetector2.MainActivity
import dev.fzer0x.imsicatcherdetector2.security.RootRepository
import dev.fzer0x.imsicatcherdetector2.security.VulnerabilityManager
import androidx.work.*
import androidx.core.content.edit
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.asSharedFlow
import java.io.BufferedReader
import java.io.InputStreamReader
import java.util.concurrent.Executors
import java.util.regex.Pattern

data class BlockingEvent(
    val timestamp: Long = System.currentTimeMillis(),
    val blockType: String,
    val description: String,
    val simSlot: Int,
    val severity: Int
)

class ForensicService : Service() {

    private val TAG = "ForensicService"
    private val serviceScope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private var logcatProcess: Process? = null
    private lateinit var wifiBluetoothScanner: WifiBluetoothScanner
    private lateinit var fusedLocationClient: FusedLocationProviderClient

    private var blockGsm = false
    private var rejectA50 = false
    private var autoMitigation = false
    private var extendedPanicMode = false
    private var isHardeningModuleActive = false

    private val processedCriticalAlerts = mutableMapOf<String, Long>()
    private val CRITICAL_ALERT_COOLDOWN = 5000L
    
    // Performance optimization: Batch size
    private val BATCH_SIZE = 50

    companion object {
        private val _blockingEventsFlow = MutableSharedFlow<BlockingEvent>(replay = 10, extraBufferCapacity = 50)
        val blockingEventsFlow = _blockingEventsFlow.asSharedFlow()

        private val blockingEventsList = mutableListOf<BlockingEvent>()
        const val MAX_BLOCKING_EVENTS = 500

        fun getBlockingEvents(): List<BlockingEvent> = synchronized(blockingEventsList) { blockingEventsList.toList() }

        @Volatile
        var lastServiceLocation: Location? = null
    }

    private val locationCallback = object : LocationCallback() {
        override fun onLocationResult(locationResult: LocationResult) {
            lastServiceLocation = locationResult.lastLocation
        }
    }

    private val commandReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            if (intent.action == "dev.fzer0x.imsicatcherdetector2.TRIGGER_HYBRID_SCAN") {
                val reason = intent.getStringExtra("reason") ?: "Suspicious cell activity"
                serviceScope.launch {
                    wifiBluetoothScanner.performQuickScan()
                    val risk = wifiBluetoothScanner.analyzeEnvironment()
                    if (risk.score > 50) {
                        val description = "HYBRID THREAT ($reason): Correlated with ${risk.description}"
                        Log.w(TAG, description)
                        broadcastAlert("HYBRID_ATTACK_SUSPECTED", 8, description, risk.suspiciousEntities.joinToString(), 0)
                    }
                }
            }
        }
    }

    private val blockingEventReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            if (intent.action != "dev.fzer0x.imsicatcherdetector2.RECORD_BLOCKING_EVENT") return
            val blockType = intent.getStringExtra("blockType") ?: return
            val description = intent.getStringExtra("description") ?: ""
            val severity = intent.getIntExtra("severity", 1)
            val simSlot = intent.getIntExtra("simSlot", 0)
            recordBlockingEvent(blockType, description, severity, simSlot)
        }
    }

    private val settingsReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            blockGsm = intent.getBooleanExtra("blockGsm", false)
            rejectA50 = intent.getBooleanExtra("reject_a50", false)
            autoMitigation = intent.getBooleanExtra("autoMitigation", false)
            Log.d(TAG, "Settings updated: BlockGSM=$blockGsm, RejectA50=$rejectA50, AutoMitigation=$autoMitigation")
        }
    }

    private val hardwareBlockingReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            if (intent.action != "dev.fzer0x.sentry.HARDWARE_BLOCKING") return
            val blockType = intent.getStringExtra("blockType") ?: return
            val description = intent.getStringExtra("description") ?: ""
            val severity = intent.getIntExtra("severity", 5)
            val simSlot = intent.getIntExtra("simSlot", 0)

            Log.i(TAG, "Hardware blocking event: $blockType - $description")
            recordBlockingEvent("HARDWARE_$blockType", description, severity, simSlot)
        }
    }

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
        startForeground(1, createNotification())
        loadSettingsFromPreferences()
        wifiBluetoothScanner = WifiBluetoothScanner(this)
        fusedLocationClient = LocationServices.getFusedLocationProviderClient(this)

        setupLocationTracking()

        serviceScope.launch {
            checkHardeningModule()
            startPolling()
            startRootLogcatMonitor()
            scheduleHourlyCveUpdate()
        }

        registerReceiver(settingsReceiver, IntentFilter("dev.fzer0x.imsicatcherdetector2.SETTINGS_CHANGED"), RECEIVER_EXPORTED)
        registerReceiver(blockingEventReceiver, IntentFilter("dev.fzer0x.imsicatcherdetector2.RECORD_BLOCKING_EVENT"), RECEIVER_EXPORTED)
        registerReceiver(hardwareBlockingReceiver, IntentFilter("dev.fzer0x.sentry.HARDWARE_BLOCKING"), RECEIVER_EXPORTED)
        registerReceiver(commandReceiver, IntentFilter("dev.fzer0x.imsicatcherdetector2.TRIGGER_HYBRID_SCAN"), RECEIVER_EXPORTED)
    }

    @SuppressLint("MissingPermission")
    private fun setupLocationTracking() {
        try {
            val locationRequest = LocationRequest.Builder(Priority.PRIORITY_HIGH_ACCURACY, 5000L)
                .setMinUpdateDistanceMeters(10f)
                .build()

            fusedLocationClient.requestLocationUpdates(locationRequest, locationCallback, Looper.getMainLooper())

            fusedLocationClient.lastLocation.addOnSuccessListener { location ->
                if (location != null) {
                    lastServiceLocation = location
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "Location tracking setup failed: ${e.message}")
        }
    }

    private fun loadSettingsFromPreferences() {
        try {
            val prefs = getSharedPreferences("sentry_settings", Context.MODE_PRIVATE)
            blockGsm = prefs.getBoolean("block_gsm", false)
            rejectA50 = prefs.getBoolean("reject_a50", false)
            autoMitigation = prefs.getBoolean("auto_mitigation", false)
            extendedPanicMode = prefs.getBoolean("extended_panic_mode", false)
        } catch (_: Exception) {}
    }

    private suspend fun checkHardeningModule() {
        isHardeningModuleActive = RootRepository.fileExists("/data/adb/modules/sentry_radio_hardening/module.prop")
    }

    private fun triggerAutoMitigation(reason: String, critical: Boolean = false) {
        if (!autoMitigation || !isHardeningModuleActive) return

        serviceScope.launch {
            if (critical) {
                Log.e(TAG, "AUTO-MITIGATION: CRITICAL THREAT ($reason). Activating EXTENDED PANIC MODE.")
                if (extendedPanicMode) {
                    // Extended Panic Mode mit voller Network Isolation
                    RootRepository.execute("sentry-ctl --panic-extended")
                    // Zusätzliche Hardware-Shutdown Befehle
                    RootRepository.execute("sentry-ctl --hard-shutdown")
                    Log.i(TAG, "Extended Panic Mode with hardware shutdown executed")
                } else {
                    // Standard Panic Mode
                    RootRepository.execute("sentry-ctl --panic")
                }
            } else {
                Log.w(TAG, "AUTO-MITIGATION: Threat detected ($reason). Resetting radio.")
                RootRepository.execute("sentry-ctl --reset-radio")
            }
        }
    }

    private fun startPolling() {
        serviceScope.launch {
            while (isActive) {
                pullAggressiveRootData()
                delay(2000)
            }
        }
    }

    private suspend fun pullAggressiveRootData() {
        val result = RootRepository.execute("dumpsys telephony.registry")
        if (!result.success) return
        val output = result.output

        // 1. Process ACTIVE SIM Slots
        for (slot in 0..1) {
            val slotSection = extractSlotSection(output, slot)
            val cid = extractFullCellId(slotSection, slot)
            val mcc = extractValue(slotSection, "Mcc", slot)
            val mnc = extractValue(slotSection, "Mnc", slot)
            val tac = extractValue(slotSection, "mTac", slot)?.toIntOrNull() ?: extractValue(slotSection, "mLac", slot)?.toIntOrNull()
            val pci = extractValue(slotSection, "mPci", slot)?.toIntOrNull()
            val earfcn = extractValue(slotSection, "mEarfcn", slot)?.toIntOrNull() ?: extractValue(slotSection, "mNrArfcn", slot)?.toIntOrNull()
            val dbm = extractAnySignal(slotSection, slot)
            val networkType = extractNetworkType(slotSection, slot)

            if (cid != null && mcc != null && mnc != null) {
                broadcastForensicData(pci, earfcn, cid, dbm, null, mcc, mnc, tac, slot, networkType, isNeighbor = false)
            }
        }

        // 2. Extract NEIGHBORS
        extractNeighborInfo(output).forEach { neighbor ->
            broadcastForensicData(
                neighbor.pci, neighbor.earfcn, neighbor.cid, neighbor.dbm,
                null, neighbor.mcc, neighbor.mnc, neighbor.tac, neighbor.slot, neighbor.type, isNeighbor = true
            )
        }
    }

    private fun extractSlotSection(input: String, slot: Int): String {
        return input.lines().filter { it.contains("[$slot]") || it.contains("subId=$slot") }.joinToString("\n")
    }

    private data class NeighborData(
        val slot: Int, val type: String, val cid: String, val mcc: String, val mnc: String,
        val tac: Int?, val pci: Int?, val earfcn: Int?, val dbm: Int?
    )

    private fun extractNeighborInfo(input: String): List<NeighborData> {
        val neighbors = mutableListOf<NeighborData>()
        val pattern = Pattern.compile("mCellInfo\\[(\\d+)\\]=\\{(.+?)\\}", Pattern.CASE_INSENSITIVE)
        val matcher = pattern.matcher(input)
        while (matcher.find()) {
            val slot = matcher.group(1).toIntOrNull() ?: 0
            val info = matcher.group(2) ?: ""

            val type = if (info.contains("LTE", true)) "LTE" else if (info.contains("NR", true)) "NR" else if (info.contains("GSM", true)) "GSM" else if (info.contains("WCDMA", true)) "WCDMA" else "UNKNOWN"
            val cid = extractRegexValue(info, "mCi=(-?\\d+)|mCid=(-?\\d+)|mNci=(-?\\d+)")
            val mcc = extractRegexValue(info, "mMcc=([0-9]{3})")
            val mnc = extractRegexValue(info, "mMnc=([0-9]{1,3})")
            val tac = extractRegexValue(info, "mTac=(-?\\d+)|mLac=(-?\\d+)").let { it?.toIntOrNull() }
            val pci = extractRegexValue(info, "mPci=(-?\\d+)").let { it?.toIntOrNull() }
            val earfcn = extractRegexValue(info, "mEarfcn=(-?\\d+)|mArfcn=(-?\\d+)").let { it?.toIntOrNull() }
            val dbm = extractRegexValue(info, "ss=(-?\\d+)|rsrp=(-?\\d+)|dbm=(-?\\d+)").let { it?.toIntOrNull() }

            if (cid != null && cid != "2147483647" && cid != "-1" && mcc != null && mnc != null) {
                neighbors.add(NeighborData(slot, type, cid, mcc, mnc, if (tac == -1) null else tac, if (pci == -1) null else pci, if (earfcn == -1) null else earfcn, if (dbm == -120) null else dbm))
            }
        }
        return neighbors
    }

    private fun extractRegexValue(input: String, regex: String): String? {
        val m = Pattern.compile(regex, Pattern.CASE_INSENSITIVE).matcher(input)
        if (m.find()) {
            for (i in 1..m.groupCount()) {
                val v = m.group(i)
                if (v != null) return v
            }
        }
        return null
    }

    private fun extractValue(input: String, key: String, slot: Int): String? {
        val pattern = Pattern.compile("m?$key\\[$slot\\]=(-?\\d+)|m?$key=(-?\\d+)", Pattern.CASE_INSENSITIVE)
        val m = pattern.matcher(input); var found: String? = null
        while (m.find()) {
            val v = m.group(1) ?: m.group(2)
            if (isValidValue(v)) found = v
        }
        return found
    }

    private fun isValidValue(v: String?): Boolean {
        return v != null && v != "2147483647" && v != "4095" && v != "65535" && v != "-1" && v != "9223372036854775807"
    }

    private fun extractNetworkType(input: String, slot: Int): String? {
        val pattern = Pattern.compile("mDataNetworkType\\[$slot\\]=(\\d+)|mNetworkType\\[$slot\\]=(\\d+)", Pattern.CASE_INSENSITIVE)
        val m = pattern.matcher(input)
        if (m.find()) {
            val typeInt = (m.group(1) ?: m.group(2))?.toIntOrNull() ?: return null
            val baseType = when (typeInt) {
                13 -> "LTE"; 20 -> "NR"; 1, 2, 16 -> "GSM";
                3, 8, 9, 10, 15 -> "WCDMA"; else -> "LTE"
            }

            // Enhanced 5G/SA detection
            if (baseType == "NR") {
                return when {
                    input.contains("ENDC_SUPPORT:false", true) -> "5G SA (Standalone)"
                    input.contains("NR_STANDALONE", true) -> "5G SA (Standalone)"
                    input.contains("ENDC_SUPPORT:true", true) -> "5G NSA (EN-DC)"
                    input.contains("NR_NON_STANDALONE", true) -> "5G NSA (EN-DC)"
                    else -> "5G NR"
                }
            }

            return baseType
        }
        return null
    }

    private fun extractAnySignal(input: String, slot: Int): Int? {
        // Prioritize RSRP for LTE/NR as it's the most accurate power metric
        for (key in listOf("rsrp", "mLteRsrp", "mNrRsrp", "rssi", "dbm", "mSignalStrength")) {
            val v = extractValue(input, key, slot)?.toIntOrNull()
            // Validate range. -116 is often a dummy value on Samsung, -140 is baseline.
            // We only accept values that look like real signal strengths.
            if (v != null && v in -139..-40 && v != -116) return v
        }
        return null
    }

    private fun extractFullCellId(input: String, slot: Int): String? {
        for (key in listOf("mNci", "mCi", "mCid")) {
            val v = extractValue(input, key, slot); if (v != null && v != "9223372036854775807" && v != "2147483647") return v
        }
        return null
    }

    private fun startRootLogcatMonitor() {
        serviceScope.launch {
            try {
                // Logcat still needs a process, but we run it within our scope
                logcatProcess = Runtime.getRuntime().exec(arrayOf("su", "-c", "logcat -b radio -b main -v time *:V"))
                val reader = BufferedReader(InputStreamReader(logcatProcess?.inputStream))
                val sigPattern = Pattern.compile("(?:rsrp|dbm|rssi)[:=]\\s*(-?\\d+)", Pattern.CASE_INSENSITIVE)
                val silentSmsPattern = Pattern.compile("RIL_UNSOL_RESPONSE_NEW_SMS|SMS_ON_CH|SMS_ACK|tp-pid:?\\s*0|SMSC:?\\s*(\\+?\\d+)", Pattern.CASE_INSENSITIVE)
                val cipheringPattern = Pattern.compile("Ciphering:?\\s*(OFF|0|NONE)|A5/0|encryption:?\\s*false", Pattern.CASE_INSENSITIVE)
                val rejectPattern = Pattern.compile("Location Updating Reject|Cause\\s*#?\\s*(\\d+)", Pattern.CASE_INSENSITIVE)
                val downgradePattern = Pattern.compile("RAT changed|NetworkType changed|Handover to GSM", Pattern.CASE_INSENSITIVE)

                withContext(Dispatchers.IO) {
                    var line: String? = null
                    while (isActive && reader.readLine().also { line = it } != null) {
                        val l = line ?: ""; val simSlot = if (l.contains("sub=1") || l.contains("simId=1")) 1 else 0

                        if (cipheringPattern.matcher(l).find() && canProcessAlert("CIPHERING_OFF", simSlot)) {
                            broadcastAlert("CIPHERING_OFF", 10, "CRITICAL: Encryption disabled (A5/0) on SIM $simSlot!", l, simSlot)
                            triggerAutoMitigation("A5/0 Cipher Detected", critical = true)
                        }
                        val mSilent = silentSmsPattern.matcher(l)
                        if (mSilent.find() && canProcessAlert("SILENT_SMS", simSlot)) {
                            var extraInfo = ""
                            try {
                                val smsc = mSilent.group(1)
                                if (smsc != null) extraInfo = " (SMSC: $smsc)"
                            } catch (e: Exception) {}

                            broadcastAlert("IMSI_CATCHER_ALERT", 9, "SUSPICIOUS: Silent SMS on SIM $simSlot$extraInfo", l, simSlot)
                            triggerAutoMitigation("Silent SMS Detection")
                        }
                        val mRej = rejectPattern.matcher(l); if (mRej.find() && canProcessAlert("NETWORK_REJECT", simSlot)) {
                            broadcastAlert("IMSI_CATCHER_ALERT", 8, "NETWORK REJECT: Cause #${mRej.group(1)} on SIM $simSlot", l, simSlot)
                            triggerAutoMitigation("Network Reject Cause")
                        }
                        if (downgradePattern.matcher(l).find() && canProcessAlert("CELL_DOWNGRADE", simSlot)) {
                            broadcastAlert("CELL_DOWNGRADE", 9, "CRITICAL: Network downgrade to GSM on SIM $simSlot", l, simSlot)
                            triggerAutoMitigation("Unexpected GSM Downgrade")
                        }
                    }
                }
            } catch (e: Exception) {
                Log.e(TAG, "Logcat monitor failed", e)
            }
        }
    }

    private fun canProcessAlert(type: String, simSlot: Int): Boolean {
        val key = "${type}_$simSlot"; val now = System.currentTimeMillis(); val last = processedCriticalAlerts[key] ?: 0L
        if (now - last < CRITICAL_ALERT_COOLDOWN) return false
        processedCriticalAlerts[key] = now; return true
    }

    private fun broadcastAlert(type: String, severity: Int, description: String, rawData: String?, simSlot: Int) {
        val intent = Intent("dev.fzer0x.imsicatcherdetector2.FORENSIC_EVENT").setPackage(packageName)
        intent.putExtra("eventType", type); intent.putExtra("severity", severity).putExtra("description", description).putExtra("simSlot", simSlot)
        rawData?.let { intent.putExtra("rawData", it) }; sendBroadcast(intent)
    }

    private fun recordBlockingEvent(blockType: String, description: String, severity: Int, simSlot: Int) {
        val event = BlockingEvent(blockType = blockType, description = description, simSlot = simSlot, severity = severity)
        synchronized(blockingEventsList) {
            blockingEventsList.add(event)
            if (blockingEventsList.size > MAX_BLOCKING_EVENTS) blockingEventsList.removeAt(0)
        }
        serviceScope.launch {
            _blockingEventsFlow.emit(event)
        }
    }

    private fun broadcastForensicData(pci: Int?, earfcn: Int?, cid: String?, dbm: Int?, neighbors: Int?, mcc: String?, mnc: String?, tac: Int?, simSlot: Int, networkType: String? = null, isNeighbor: Boolean = false) {
        val intent = Intent("dev.fzer0x.imsicatcherdetector2.FORENSIC_EVENT").setPackage(packageName)
        intent.putExtra("eventType", "RADIO_METRICS_UPDATE").putExtra("simSlot", simSlot).putExtra("severity", 1)
        intent.putExtra("isNeighbor", isNeighbor)
        cid?.let { intent.putExtra("cellId", it) }; mcc?.let { intent.putExtra("mcc", it) }; mnc?.let { intent.putExtra("mnc", it) }
        tac?.let { intent.putExtra("tac", it) }; pci?.let { intent.putExtra("pci", it) }; earfcn?.let { intent.putExtra("earfcn", it) }
        dbm?.let { intent.putExtra("dbm", it) }; neighbors?.let { intent.putExtra("neighbors", it) }; networkType?.let { intent.putExtra("networkType", it) }
        sendBroadcast(intent)
    }

    private fun createNotificationChannel() {
        val channel = NotificationChannel("forensic_monitoring", "Sentry Radio Monitoring", NotificationManager.IMPORTANCE_LOW)
        getSystemService(NotificationManager::class.java).createNotificationChannel(channel)
    }

    private fun createNotification(): Notification {
        val pendingIntent = PendingIntent.getActivity(this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE)
        return NotificationCompat.Builder(this, "forensic_monitoring").setContentTitle("Sentry Radio").setContentText("Forensic Engine: Active").setSmallIcon(android.R.drawable.ic_lock_idle_lock).setContentIntent(pendingIntent).setOngoing(true).build()
    }

    private fun scheduleHourlyCveUpdate() {
        val cveUpdateRequest = PeriodicWorkRequestBuilder<CveUpdateWorker>(1, TimeUnit.HOURS)
            .setConstraints(Constraints.Builder()
                .setRequiredNetworkType(NetworkType.CONNECTED)
                .build())
            .build()

        WorkManager.getInstance(this).enqueueUniquePeriodicWork(
            "cve_update_worker",
            ExistingPeriodicWorkPolicy.KEEP,
            cveUpdateRequest
        )

        Log.d(TAG, "Scheduled hourly CVE database updates")
    }

    class CveUpdateWorker(appContext: Context, workerParams: WorkerParameters) : CoroutineWorker(appContext, workerParams) {
        private val vulnerabilityManager = VulnerabilityManager(appContext)

        override suspend fun doWork(): Result {
            return try {
                // Get device info from build properties
                val chipset = Build.HARDWARE
                val baseband = Build.getRadioVersion() ?: "Unknown"
                val securityPatch = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                    Build.VERSION.SECURITY_PATCH
                } else {
                    "Unknown"
                }

                vulnerabilityManager.checkVulnerabilities(chipset, baseband, securityPatch, forceRefresh = true)

                // Save last update time
                val prefs = applicationContext.getSharedPreferences("sentry_settings", Context.MODE_PRIVATE)
                val editor = prefs.edit()
                editor.putLong("last_cve_worker_sync", System.currentTimeMillis())
                editor.commit()

                Log.d("CveUpdateWorker", "CVE database updated successfully")
                Result.success()
            } catch (e: Exception) {
                Log.e("CveUpdateWorker", "Failed to update CVE database: ${e.message}")
                Result.retry()
            }
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int = START_STICKY
    override fun onDestroy() {
        try { fusedLocationClient.removeLocationUpdates(locationCallback) } catch (e: Exception) {}
        unregisterReceiver(settingsReceiver); unregisterReceiver(blockingEventReceiver); unregisterReceiver(commandReceiver)
        logcatProcess?.destroy()
        serviceScope.cancel()
        super.onDestroy()
    }
    override fun onBind(intent: Intent?): IBinder? = null
}