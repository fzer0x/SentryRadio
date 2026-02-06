package dev.fzer0x.imsicatcherdetector2.service

import android.app.*
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.IBinder
import android.util.Log
import androidx.core.app.NotificationCompat
import dev.fzer0x.imsicatcherdetector2.MainActivity
import dev.fzer0x.imsicatcherdetector2.security.ProcessSafetyManager
import dev.fzer0x.imsicatcherdetector2.security.RegexSafetyManager
import dev.fzer0x.imsicatcherdetector2.security.HttpClientSecurityManager
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
    private val executor = Executors.newSingleThreadScheduledExecutor()
    private val rootExecutor = Executors.newSingleThreadScheduledExecutor()
    private var logcatProcess: Process? = null

    private var blockGsm = false
    private var rejectA50 = false

    // Suppression für Alerts - verhindert dass der gleiche Alert-Typ zu oft kommt
    private val processedCriticalAlerts = mutableMapOf<String, Long>() // Alert-Type + SIM -> Timestamp
    private val CRITICAL_ALERT_COOLDOWN = 5000L // 5 Sekunden Cooldown für gleiche Alerts

    companion object {
        private val blockingEvents = mutableListOf<BlockingEvent>()
        const val MAX_BLOCKING_EVENTS = 500

        fun getBlockingEvents(): List<BlockingEvent> = blockingEvents.toList()
        fun clearBlockingEvents() = blockingEvents.clear()
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
            rejectA50 = intent.getBooleanExtra("rejectA50", false)
            Log.d(TAG, "Settings updated in Service: BlockGSM=$blockGsm, RejectA50=$rejectA50")
        }
    }

    override fun onCreate() {
        super.onCreate()
        Log.d(TAG, "Service onCreate - Engines starting...")
        createNotificationChannel()
        startForeground(1, createNotification())

        // Lade gespeicherte Security Settings aus SharedPreferences
        loadSettingsFromPreferences()

        registerReceiver(settingsReceiver, IntentFilter("dev.fzer0x.imsicatcherdetector2.SETTINGS_CHANGED"), RECEIVER_EXPORTED)
        registerReceiver(blockingEventReceiver, IntentFilter("dev.fzer0x.imsicatcherdetector2.RECORD_BLOCKING_EVENT"), RECEIVER_EXPORTED)

        executor.scheduleWithFixedDelay({
            pullAggressiveRootData()
        }, 0, 2, java.util.concurrent.TimeUnit.SECONDS)

        startRootLogcatMonitor()
    }

    private fun loadSettingsFromPreferences() {
        try {
            val prefs = getSharedPreferences("sentry_settings", Context.MODE_PRIVATE)
            blockGsm = prefs.getBoolean("block_gsm", false)
            rejectA50 = prefs.getBoolean("reject_a50", false)
            Log.d(TAG, "Settings loaded from preferences on Service start - BlockGSM: $blockGsm, RejectA50: $rejectA50")
        } catch (e: Exception) {
            Log.e(TAG, "Failed to load settings: ${e.message}")
        }
    }

    private fun pullAggressiveRootData() {
        rootExecutor.execute {
            try {
                // SECURITY: Use ProcessSafetyManager with timeout to prevent hangs
                val result = ProcessSafetyManager.executeCommandWithTimeout(
                    arrayOf("su", "-c", "dumpsys telephony.registry"),
                    timeoutSec = 5L
                )

                if (!result.success) {
                    Log.w(TAG, "Dumpsys command failed: ${result.error}")
                    return@execute
                }

                val output = result.output

                for (slot in 0..1) {
                    val cid = extractFullCellId(output, slot)
                    val mcc = extractValue(output, "Mcc", slot)
                    val mnc = extractValue(output, "Mnc", slot)
                    val tac = extractValue(output, "mTac", slot)?.toIntOrNull() ?: extractValue(output, "mLac", slot)?.toIntOrNull()
                    val pci = extractValue(output, "mPci", slot)?.toIntOrNull()
                    val earfcn = extractValue(output, "mEarfcn", slot)?.toIntOrNull() ?: extractValue(output, "mNrArfcn", slot)?.toIntOrNull()
                    val dbm = extractAnySignal(output, slot)
                    val networkType = extractNetworkType(output, slot)
                    
                    if (cid != null) {
                        broadcastForensicData(pci, earfcn, cid, dbm, null, mcc, mnc, tac, slot, networkType)
                    }
                }
            } catch (e: Exception) {
                Log.e(TAG, "Dumpsys Error: ${e.message}")
            }
        }
    }

    private fun extractValue(input: String, key: String, slot: Int): String? {
        val pattern = Pattern.compile("m?$key\\[$slot\\]=(-?\\d+)|m?$key=(-?\\d+)", Pattern.CASE_INSENSITIVE)
        val m = pattern.matcher(input)
        var found: String? = null
        while (m.find()) {
            val v = m.group(1) ?: m.group(2)
            if (v != "2147483647" && v != "4095" && v != "65535" && v != "-1") {
                found = v
            }
        }
        return found
    }

    private fun extractNetworkType(input: String, slot: Int): String? {
        val pattern = Pattern.compile("mDataNetworkType\\[$slot\\]=(\\d+)|mNetworkType\\[$slot\\]=(\\d+)", Pattern.CASE_INSENSITIVE)
        val m = pattern.matcher(input)
        if (m.find()) {
            val typeInt = (m.group(1) ?: m.group(2))?.toIntOrNull() ?: return null
            return when (typeInt) {
                13 -> "LTE"
                20 -> "NR (5G)"
                1, 2, 16 -> "GSM"
                3, 8, 9, 10, 15 -> "WCDMA/HSPA"
                else -> "Type-$typeInt"
            }
        }
        return null
    }

    private fun extractAnySignal(input: String, slot: Int): Int? {
        val keys = listOf("rsrp", "rssi", "dbm", "mSignalStrength")
        for (key in keys) {
            val v = extractValue(input, key, slot)?.toIntOrNull()
            if (v != null && v in -140..-30) return v
        }
        return null
    }

    private fun extractFullCellId(input: String, slot: Int): String? {
        val keys = listOf("mNci", "mCi", "mCid")
        for (key in keys) {
            val v = extractValue(input, key, slot)
            if (v != null && v != "9223372036854775807") return v
        }
        return null
    }

    private fun analyzeSignalAnomaly(dbm: Int, rsrp: Int?, sinr: Int?, simSlot: Int) {
        rootExecutor.execute {
            try {
                if (dbm > -30) {
                    broadcastAlert("SIGNAL_ANOMALY", 7, "SUSPICIOUS: Signal strength unrealistic (${dbm}dBm) on SIM $simSlot", null, simSlot)
                }

                if (sinr != null && sinr < -5) {
                    broadcastAlert("INTERFERENCE_DETECTED", 6, "WARNING: High interference detected (SINR=${sinr}dB) on SIM $simSlot", null, simSlot)
                }
            } catch (e: Exception) {}
        }
    }

    private fun extractBasebandVersion(output: String): String? {
        val patterns = listOf(
            "baseband_version\\s*=\\s*([\\w\\-\\.]+)",
            "modem_version\\s*=\\s*([\\w\\-\\.]+)",
            "radio_version\\s*=\\s*([\\w\\-\\.]+)",
            "firmware\\s*version\\s*=\\s*([\\w\\-\\.]+)"
        )
        for (pattern in patterns) {
            val m = Pattern.compile(pattern, Pattern.CASE_INSENSITIVE).matcher(output)
            if (m.find()) return m.group(1)
        }
        return null
    }

    private fun analyzeBasebandVulnerabilities(version: String?, simSlot: Int) {
        if (version == null) return
        rootExecutor.execute {
            try {
                val vulnerableVersions = listOf("SDM845", "SDM855", "MDM9650")
                if (vulnerableVersions.any { version.contains(it, ignoreCase = true) }) {
                    broadcastAlert("VULNERABLE_BASEBAND", 8, "CRITICAL: Device runs vulnerable baseband ($version) on SIM $simSlot", null, simSlot)
                }
            } catch (e: Exception) {}
        }
    }

    private val lastRrcStates = mutableMapOf<Int, String>()
    private val rrcStateChangeTimes = mutableMapOf<Int, Long>()

    private fun trackRrcStateChanges(logLine: String, simSlot: Int) {
        val rrcPattern = Pattern.compile("RRC_STATE[:\\s]*([A-Z_]+)", Pattern.CASE_INSENSITIVE)
        val m = rrcPattern.matcher(logLine)

        if (m.find()) {
            val currentState = m.group(1)
            val now = System.currentTimeMillis()
            val lastRrcState = lastRrcStates[simSlot]
            val rrcStateChangeTime = rrcStateChangeTimes[simSlot] ?: 0L

            if (lastRrcState != null && lastRrcState != currentState) {
                val timeDiff = now - rrcStateChangeTime
                if (timeDiff < 1000) {
                    broadcastAlert("RRC_STATE_CHANGE", 5, "NOTICE: Rapid RRC state changes detected on SIM $simSlot ($lastRrcState -> $currentState)", null, simSlot)
                }
                if (lastRrcState == "CONNECTED" && currentState == "IDLE" && timeDiff < 500) {
                    broadcastAlert("RRC_ANOMALY", 6, "SUSPICIOUS: Unusual RRC state transition timing on SIM $simSlot", null, simSlot)
                }
            }

            lastRrcStates[simSlot] = currentState
            rrcStateChangeTimes[simSlot] = now
        }
    }

    private data class HandoverEvent(
        val timestamp: Long,
        val sourceCellId: String,
        val targetCellId: String,
        val simSlot: Int
    )

    private val handoverHistory = mutableListOf<HandoverEvent>()
    private val lastCellIds = mutableMapOf<Int, String>()

    private fun detectHandoverAnomalies(cellId: String, logLine: String, simSlot: Int) {
        val lastCellId = lastCellIds[simSlot]
        if (lastCellId != null && lastCellId != cellId) {
            val now = System.currentTimeMillis()
            val handover = HandoverEvent(now, lastCellId, cellId, simSlot)
            handoverHistory.add(handover)

            if (handoverHistory.size > 100) handoverHistory.removeAt(0)

            val recentHandovers = handoverHistory.filter { it.simSlot == simSlot && now - it.timestamp < 60000 }
            if (recentHandovers.size > 10) {
                broadcastAlert("HANDOVER_ANOMALY", 6, "WARNING: Excessive cell handovers on SIM $simSlot", null, simSlot)
            }

            if (handoverHistory.size >= 2) {
                val prev = handoverHistory.filter { it.simSlot == simSlot }.let { if (it.size >= 2) it[it.size - 2] else null }
                if (prev != null && prev.targetCellId == lastCellId && prev.sourceCellId == cellId) {
                    broadcastAlert("HANDOVER_PINGPONG", 7, "SUSPICIOUS: Ping-pong handover pattern on SIM $simSlot", null, simSlot)
                }
            }
        }
        lastCellIds[simSlot] = cellId
    }

    private fun analyzeNetworkCapabilities(output: String, simSlot: Int) {
        rootExecutor.execute {
            try {
                val has5g = output.contains("5G", ignoreCase = true) || output.contains("NR", ignoreCase = true)
                val hasLte = output.contains("LTE", ignoreCase = true) || output.contains("4G", ignoreCase = true)
                val has2g3g = output.contains("GSM", ignoreCase = true) || output.contains("WCDMA", ignoreCase = true)

                if ((has5g || hasLte) && has2g3g && !output.contains("LTE", ignoreCase = true) && !output.contains("NR", ignoreCase = true)) {
                    broadcastAlert("NETWORK_DEGRADATION", 9, "CRITICAL: Network downgrade detected on SIM $simSlot", null, simSlot)
                }
            } catch (e: Exception) {}
        }
    }

    private fun startRootLogcatMonitor() {
        rootExecutor.execute {
            try {
                logcatProcess = Runtime.getRuntime().exec(arrayOf("su", "-c", "logcat -b radio -b main -v time *:V"))
                val reader = BufferedReader(InputStreamReader(logcatProcess?.inputStream))
                
                val sigPattern = Pattern.compile("(?:rsrp|dbm|rssi)[:=]\\s*(-?\\d+)", Pattern.CASE_INSENSITIVE)
                val silentSmsPattern = Pattern.compile("RIL_UNSOL_RESPONSE_NEW_SMS|SMS_ON_CH|SMS_ACK|tp-pid:?\\s*0", Pattern.CASE_INSENSITIVE)
                val cipheringPattern = Pattern.compile("Ciphering:?\\s*(OFF|0|NONE)|A5/0|encryption:?\\s*false", Pattern.CASE_INSENSITIVE)
                val rejectPattern = Pattern.compile("Location Updating Reject|Cause\\s*#?\\s*(\\d+)", Pattern.CASE_INSENSITIVE)
                val downgradePattern = Pattern.compile("RAT changed|NetworkType changed|Handover to GSM", Pattern.CASE_INSENSITIVE)
                val sinrPattern = Pattern.compile("sinr[:=]\\s*(-?\\d+)", Pattern.CASE_INSENSITIVE)
                val cellIdPattern = Pattern.compile("cell[_id]*\\s*[:=]\\s*([0-9a-fA-F]+)", Pattern.CASE_INSENSITIVE)

                var line: String? = null
                while (reader.readLine().also { line = it } != null) {
                    val l = line ?: ""

                    val simSlot = if (l.contains("sub=1") || l.contains("simId=1") || l.contains("[1]")) 1 else 0
                    
                    val mSig = sigPattern.matcher(l)
                    if (mSig.find()) {
                        val raw = mSig.group(1).toIntOrNull() ?: continue
                        val dbm = if (raw in 0..31) -113 + (2 * raw) else raw
                        if (dbm in -140..-30) {
                            broadcastForensicData(null, null, null, dbm, null, null, null, null, simSlot)
                            val sinrMatch = sinrPattern.matcher(l)
                            val sinr = if (sinrMatch.find()) sinrMatch.group(1).toIntOrNull() else null
                            analyzeSignalAnomaly(dbm, raw, sinr, simSlot)
                        }
                    }

                    if (cipheringPattern.matcher(l).find()) {
                        if (canProcessAlert("CIPHERING_OFF", simSlot)) {
                            val status = if (rejectA50) "BLOCKED & ALERT" else "CRITICAL ALERT"
                            broadcastAlert("CIPHERING_OFF", 10, "$status: Encryption disabled (A5/0) on SIM $simSlot!", l, simSlot)

                            if (rejectA50) {
                                recordBlockingEvent(
                                    blockType = "A5_0_CIPHER",
                                    description = "A5/0 unencrypted connection blocked on SIM $simSlot",
                                    severity = 10,
                                    simSlot = simSlot
                                )
                            }
                        }
                    }

                    if (silentSmsPattern.matcher(l).find()) {
                        if (canProcessAlert("SILENT_SMS", simSlot)) {
                            broadcastAlert("IMSI_CATCHER_ALERT", 9, "SUSPICIOUS: Silent SMS (Type-0) detected on SIM $simSlot", l, simSlot)
                        }
                    }

                    val mRej = rejectPattern.matcher(l)
                    if (mRej.find()) {
                        if (canProcessAlert("NETWORK_REJECT", simSlot)) {
                            val cause = mRej.group(1) ?: "Unknown"
                            broadcastAlert("IMSI_CATCHER_ALERT", 8, "NETWORK REJECT: Location Update Rejected (Cause #$cause) on SIM $simSlot", l, simSlot)
                        }
                    }

                    if (downgradePattern.matcher(l).find()) {
                        if (canProcessAlert("CELL_DOWNGRADE", simSlot)) {
                            val severity = if (blockGsm) 9 else 7
                            val status = if (blockGsm) "BLOCKED" else "WARNING"
                            broadcastAlert("CELL_DOWNGRADE", severity, "$status: Sudden network downgrade to GSM on SIM $simSlot", l, simSlot)

                            if (blockGsm) {
                                recordBlockingEvent(
                                    blockType = "GSM_DOWNGRADE",
                                    description = "GSM downgrade attempt blocked on SIM $simSlot",
                                    severity = severity,
                                    simSlot = simSlot
                                )
                            }
                        }
                    }

                    if (l.contains("RRC_STATE")) trackRrcStateChanges(l, simSlot)

                    if (l.contains("handover")) {
                        val cellMatch = cellIdPattern.matcher(l)
                        if (cellMatch.find()) detectHandoverAnomalies(cellMatch.group(1), l, simSlot)
                    }

                    if (l.contains("baseband") || l.contains("modem")) {
                        analyzeBasebandVulnerabilities(extractBasebandVersion(l), simSlot)
                    }

                    if (l.contains("capability")) analyzeNetworkCapabilities(l, simSlot)
                }
            } catch (e: Exception) {
                Log.e(TAG, "Logcat Monitor Error: ${e.message}")
            }
        }
    }

    private fun canProcessAlert(alertType: String, simSlot: Int): Boolean {
        val key = "${alertType}_SIM${simSlot}"
        val now = System.currentTimeMillis()
        val lastTime = processedCriticalAlerts[key] ?: 0L

        if (now - lastTime < CRITICAL_ALERT_COOLDOWN) {
            Log.d(TAG, "Alert SUPPRESSED (cooldown): $alertType on SIM $simSlot")
            return false
        }

        processedCriticalAlerts[key] = now
        return true
    }

    private fun broadcastAlert(type: String, severity: Int, description: String, rawData: String? = null, simSlot: Int) {
        val intent = Intent("dev.fzer0x.imsicatcherdetector2.FORENSIC_EVENT")
        intent.setPackage(packageName)
        intent.putExtra("eventType", type)
        intent.putExtra("severity", severity)
        intent.putExtra("description", description)
        intent.putExtra("simSlot", simSlot)
        rawData?.let { intent.putExtra("rawData", it) }
        sendBroadcast(intent)

        Log.d(TAG, "Alert sent: $type - $description on SIM $simSlot")
    }

    private fun recordBlockingEvent(blockType: String, description: String, severity: Int, simSlot: Int) {

        val event = BlockingEvent(
            blockType = blockType,
            description = description,
            simSlot = simSlot,
            severity = severity
        )
        synchronized(blockingEvents) {
            blockingEvents.add(event)
            if (blockingEvents.size > MAX_BLOCKING_EVENTS) {
                blockingEvents.removeAt(0)
            }
        }
        Log.d(TAG, "Blocking Event recorded: $blockType - $description")
    }

    private fun broadcastForensicData(pci: Int?, earfcn: Int?, cid: String?, dbm: Int?, neighbors: Int?, mcc: String?, mnc: String?, tac: Int?, simSlot: Int, networkType: String? = null) {
        val intent = Intent("dev.fzer0x.imsicatcherdetector2.FORENSIC_EVENT")
        intent.setPackage(packageName)
        intent.putExtra("eventType", "RADIO_METRICS_UPDATE")
        cid?.let { intent.putExtra("cellId", it) }
        mcc?.let { intent.putExtra("mcc", it) }
        mnc?.let { intent.putExtra("mnc", it) }
        tac?.let { intent.putExtra("tac", it) }
        pci?.let { intent.putExtra("pci", it) }
        earfcn?.let { intent.putExtra("earfcn", it) }
        dbm?.let { intent.putExtra("dbm", it) }
        neighbors?.let { intent.putExtra("neighbors", it) }
        networkType?.let { intent.putExtra("networkType", it) }
        intent.putExtra("simSlot", simSlot)
        intent.putExtra("severity", 1)
        sendBroadcast(intent)
    }

    private fun createNotificationChannel() {
        val channel = NotificationChannel("forensic_monitoring", "Sentry Radio Monitoring", NotificationManager.IMPORTANCE_LOW)
        getSystemService(NotificationManager::class.java).createNotificationChannel(channel)
    }

    private fun createNotification(): Notification {
        val intent = Intent(this, MainActivity::class.java)
        val pendingIntent = PendingIntent.getActivity(this, 0, intent, PendingIntent.FLAG_IMMUTABLE)
        return NotificationCompat.Builder(this, "forensic_monitoring")
            .setContentTitle("Sentry Radio")
            .setContentText("Forensic Engine: Active")
            .setSmallIcon(android.R.drawable.ic_lock_idle_lock)
            .setContentIntent(pendingIntent)
            .setOngoing(true)
            .build()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int = START_STICKY
    override fun onDestroy() {
        unregisterReceiver(settingsReceiver)
        unregisterReceiver(blockingEventReceiver)
        executor.shutdown(); logcatProcess?.destroy(); rootExecutor.shutdown()
        super.onDestroy()
    }
    override fun onBind(intent: Intent?): IBinder? = null
}
