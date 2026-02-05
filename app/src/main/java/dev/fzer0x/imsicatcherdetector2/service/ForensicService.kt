package dev.fzer0x.imsicatcherdetector2.service

import android.app.*
import android.content.Context
import android.content.Intent
import android.os.IBinder
import android.util.Log
import androidx.core.app.NotificationCompat
import dev.fzer0x.imsicatcherdetector2.MainActivity
import java.io.BufferedReader
import java.io.InputStreamReader
import java.util.concurrent.Executors
import java.util.regex.Pattern

class ForensicService : Service() {

    private val TAG = "ForensicService"
    private val executor = Executors.newSingleThreadScheduledExecutor()
    private val rootExecutor = Executors.newSingleThreadExecutor()
    private var logcatProcess: Process? = null

    override fun onCreate() {
        super.onCreate()
        Log.d(TAG, "Service onCreate - Engines starting...")
        createNotificationChannel()
        startForeground(1, createNotification())
        
        executor.scheduleWithFixedDelay({
            pullAggressiveRootData()
        }, 0, 2, java.util.concurrent.TimeUnit.SECONDS)

        startRootLogcatMonitor()
    }

    private fun pullAggressiveRootData() {
        rootExecutor.execute {
            try {
                val process = Runtime.getRuntime().exec(arrayOf("su", "-c", "dumpsys telephony.registry"))
                val reader = BufferedReader(InputStreamReader(process.inputStream))
                val output = reader.readText()
                
                for (slot in 0..1) {
                    val cid = extractFullCellId(output, slot)
                    val mcc = extractValue(output, "Mcc", slot)
                    val mnc = extractValue(output, "Mnc", slot)
                    val tac = extractValue(output, "mTac", slot)?.toIntOrNull() ?: extractValue(output, "mLac", slot)?.toIntOrNull()
                    val pci = extractValue(output, "mPci", slot)?.toIntOrNull()
                    val earfcn = extractValue(output, "mEarfcn", slot)?.toIntOrNull() ?: extractValue(output, "mNrArfcn", slot)?.toIntOrNull()
                    val dbm = extractAnySignal(output, slot)
                    
                    if (cid != null) {
                        broadcastForensicData(pci, earfcn, cid, dbm, null, mcc, mnc, tac, slot)
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

                var line: String?
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
                        broadcastAlert("CIPHERING_OFF", 10, "CRITICAL: Encryption disabled on SIM $simSlot!", l, simSlot)
                    }

                    if (silentSmsPattern.matcher(l).find()) {
                        broadcastAlert("IMSI_CATCHER_ALERT", 9, "SUSPICIOUS: Silent SMS activity on SIM $simSlot", l, simSlot)
                    }

                    val mRej = rejectPattern.matcher(l)
                    if (mRej.find()) {
                        broadcastAlert("IMSI_CATCHER_ALERT", 8, "Network anomaly: Location Update Rejected on SIM $simSlot", l, simSlot)
                    }

                    if (downgradePattern.matcher(l).find()) {
                        broadcastAlert("CELL_DOWNGRADE", 7, "Warning: Sudden network downgrade on SIM $simSlot", l, simSlot)
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

    private fun broadcastAlert(type: String, severity: Int, description: String, rawData: String? = null, simSlot: Int) {
        val intent = Intent("dev.fzer0x.imsicatcherdetector2.FORENSIC_EVENT")
        intent.setPackage(packageName)
        intent.putExtra("eventType", type)
        intent.putExtra("severity", severity)
        intent.putExtra("description", description)
        intent.putExtra("simSlot", simSlot)
        rawData?.let { intent.putExtra("rawData", it) }
        sendBroadcast(intent)
    }

    private fun broadcastForensicData(pci: Int?, earfcn: Int?, cid: String?, dbm: Int?, neighbors: Int?, mcc: String?, mnc: String?, tac: Int?, simSlot: Int) {
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
            .setContentTitle("Sentry Radio by fzer0x")
            .setContentText("Forensic Engine: Active")
            .setSmallIcon(android.R.drawable.ic_lock_idle_lock)
            .setContentIntent(pendingIntent)
            .setOngoing(true)
            .build()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int = START_STICKY
    override fun onDestroy() {
        executor.shutdown(); logcatProcess?.destroy(); rootExecutor.shutdown()
        super.onDestroy()
    }
    override fun onBind(intent: Intent?): IBinder? = null
}
