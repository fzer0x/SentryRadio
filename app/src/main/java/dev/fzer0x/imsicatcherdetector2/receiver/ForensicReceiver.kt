package dev.fzer0x.imsicatcherdetector2.receiver

import android.Manifest
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.location.Location
import android.location.LocationManager
import android.os.Build
import android.os.VibrationEffect
import android.os.Vibrator
import android.os.VibratorManager
import android.util.Log
import androidx.core.content.ContextCompat
import dev.fzer0x.imsicatcherdetector2.data.CellTower
import dev.fzer0x.imsicatcherdetector2.data.EventType
import dev.fzer0x.imsicatcherdetector2.data.ForensicDatabase
import dev.fzer0x.imsicatcherdetector2.data.ForensicEvent
import dev.fzer0x.imsicatcherdetector2.service.CellLookupManager
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import java.util.concurrent.ConcurrentHashMap

class ForensicReceiver : BroadcastReceiver() {

    private val TAG = "ForensicReceiver"

    companion object {
        private val apiThrottleCache = ConcurrentHashMap<String, Long>()
        private val eventDeduplicationCache = ConcurrentHashMap<String, Long>()
        private val lastLacs = ConcurrentHashMap<Int, Int>()
        private val lastCellIds = ConcurrentHashMap<Int, String>()
    }

    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != "dev.fzer0x.imsicatcherdetector2.FORENSIC_EVENT") return

        val eventTypeStr = intent.getStringExtra("eventType") ?: return
        val descriptionStr = intent.getStringExtra("description") ?: ""
        val cellId = intent.getStringExtra("cellId")
        val simSlot = intent.getIntExtra("simSlot", 0)

        val dedupKey = "${eventTypeStr}_${descriptionStr}_${cellId}_$simSlot"
        val now = System.currentTimeMillis()
        val lastSeen = eventDeduplicationCache[dedupKey] ?: 0L
        if (now - lastSeen < 10000) {
            return
        }
        eventDeduplicationCache[dedupKey] = now

        val eventType = try { EventType.valueOf(eventTypeStr) } catch(e: Exception) {
            when(eventTypeStr) {
                "CIPHERING_OFF" -> EventType.CIPHERING_OFF
                "IMSI_CATCHER_ALERT" -> EventType.IMSI_CATCHER_ALERT
                "RADIO_METRICS_UPDATE" -> EventType.RADIO_METRICS_UPDATE
                "CELL_DOWNGRADE" -> EventType.CELL_DOWNGRADE
                "SILENT_SMS" -> EventType.SILENT_SMS
                else -> return
            }
        }

        val mcc = intent.getStringExtra("mcc")
        val mnc = intent.getStringExtra("mnc")

        val lac = if (intent.hasExtra("lac")) intent.getIntExtra("lac", -1).let { if (it == -1) null else it } else null
        val tac = if (intent.hasExtra("tac")) intent.getIntExtra("tac", -1).let { if (it == -1) null else it } else null
        val pci = if (intent.hasExtra("pci")) intent.getIntExtra("pci", -1).let { if (it == -1) null else it } else null
        val earfcn = if (intent.hasExtra("earfcn")) intent.getIntExtra("earfcn", -1).let { if (it == -1) null else it } else null
        val dbm = if (intent.hasExtra("dbm")) intent.getIntExtra("dbm", -120) else null
        val ta = if (intent.hasExtra("ta")) intent.getIntExtra("ta", -1) else null
        val neighbors = if (intent.hasExtra("neighbors")) intent.getIntExtra("neighbors", -1) else null
        var severity = intent.getIntExtra("severity", 1)
        var description = descriptionStr
        val rawData = intent.getStringExtra("rawData")

        val currentLac = lac ?: tac
        val lastLac = lastLacs[simSlot]
        val lastCellId = lastCellIds[simSlot]

        if (currentLac != null && lastLac != null && currentLac != lastLac) {
            if (cellId == lastCellId) {
                severity = 9
                description = "CRITICAL: LAC changed for SAME Cell ID ($lastLac -> $currentLac) on SIM $simSlot"
                sendAlertBroadcast(context, "LOCATION_ANOMALY", severity, description, simSlot)
            }
        }
        if (currentLac != null) lastLacs[simSlot] = currentLac
        if (cellId != null) lastCellIds[simSlot] = cellId

        if (eventType == EventType.RADIO_METRICS_UPDATE && neighbors == 0 && severity < 5) {
            severity = 6
            description = "SUSPICIOUS: Lonely Cell detected (No neighbors found) on SIM $simSlot"
            sendAlertBroadcast(context, "IMSI_CATCHER_ALERT", severity, description, simSlot)
        }

        if (ta != null && ta == 0 && (dbm ?: -120) > -60) {
            severity = 7
            description = "WARNING: Base station is extremely close (TA=0, Signal=${dbm}dBm) on SIM $simSlot"
            sendAlertBroadcast(context, "TIMING_ADVANCE_ANOMALY", severity, description, simSlot)
        }

        val event = ForensicEvent(
            type = eventType,
            severity = severity,
            description = description,
            cellId = cellId,
            lac = lac,
            tac = tac,
            pci = pci,
            earfcn = earfcn,
            mnc = mnc,
            mcc = mcc,
            networkType = intent.getStringExtra("networkType"),
            signalStrength = if (dbm != -120) dbm else null,
            neighborCount = if (neighbors != -1) neighbors else null,
            timingAdvance = if (ta != -1) ta else null,
            rawData = rawData,
            simSlot = simSlot
        )

        if (severity >= 7) {
            triggerAlarm(context)
        }

        val db = ForensicDatabase.getDatabase(context)
        val dao = db.forensicDao()
        val prefs = context.getSharedPreferences("sentry_settings", Context.MODE_PRIVATE)
        
        val ocidKey = prefs.getString("opencellid_key", "") ?: ""
        val ulKey = prefs.getString("unwiredlabs_key", "") ?: ""
        val useBdb = prefs.getBoolean("use_beacondb", true)
        val useOcid = prefs.getBoolean("use_opencellid", false)
        val useUl = prefs.getBoolean("use_unwiredlabs", false)

        CoroutineScope(Dispatchers.IO).launch {
            dao.insertEvent(event)

            if (cellId != null && mcc != null && mnc != null) {
                val realLac = lac ?: tac ?: 0
                val lastRequest = apiThrottleCache[cellId] ?: 0L
                val isThrottled = System.currentTimeMillis() - lastRequest < 30000

                val existingTower = dao.getTowerById(cellId)
                val localLoc = requestFreshLocation(context)

                if (existingTower == null || existingTower.latitude == null || !existingTower.isVerified) {
                    var towerLat: Double? = null
                    var towerLon: Double? = null
                    var isVerified = false
                    var range: Double? = null
                    var samples: Int? = null
                    var changeable: Boolean? = null
                    var towerSource: String? = null

                    if (!isThrottled) {
                        apiThrottleCache[cellId] = System.currentTimeMillis()
                        val result = CellLookupManager(
                            openCellIdKey = ocidKey, 
                            unwiredLabsKey = ulKey,
                            useBeaconDb = useBdb,
                            useOpenCellId = useOcid,
                            useUnwiredLabs = useUl
                        ).lookup(mcc, mnc, realLac, cellId)

                        if (result.isFound) {
                            towerLat = result.lat
                            towerLon = result.lon
                            range = result.range
                            samples = result.samples
                            changeable = result.changeable
                            towerSource = result.source
                            isVerified = true
                        }
                    }

                    if (towerLat == null && localLoc != null && (existingTower?.latitude == null)) {
                        towerLat = localLoc.latitude
                        towerLon = localLoc.longitude
                        isVerified = false
                        towerSource = "Local GPS"
                    }

                    if (towerLat != null || existingTower != null) {
                        val tower = existingTower ?: CellTower(
                            cellId = cellId, mcc = mcc, mnc = mnc, lac = realLac, rat = event.networkType ?: "LTE"
                        )
                        dao.upsertTower(tower.copy(
                            latitude = towerLat ?: tower.latitude,
                            longitude = towerLon ?: tower.longitude,
                            isVerified = isVerified || tower.isVerified,
                            range = range ?: tower.range,
                            samples = samples ?: tower.samples,
                            changeable = changeable ?: tower.changeable,
                            lastSeen = System.currentTimeMillis(),
                            source = towerSource ?: tower.source
                        ))
                    }
                } else {
                    dao.upsertTower(existingTower.copy(lastSeen = System.currentTimeMillis()))
                }
            }
        }
    }

    private fun sendAlertBroadcast(context: Context, type: String, severity: Int, desc: String, simSlot: Int) {
        val intent = Intent("dev.fzer0x.imsicatcherdetector2.FORENSIC_EVENT")
        intent.setPackage(context.packageName)
        intent.putExtra("eventType", type)
        intent.putExtra("severity", severity)
        intent.putExtra("description", desc)
        intent.putExtra("simSlot", simSlot)
        context.sendBroadcast(intent)
    }

    private fun requestFreshLocation(context: Context): Location? {
        if (ContextCompat.checkSelfPermission(context, Manifest.permission.ACCESS_FINE_LOCATION) != PackageManager.PERMISSION_GRANTED) return null
        val lm = context.getSystemService(Context.LOCATION_SERVICE) as LocationManager
        return try {
            val loc = lm.getLastKnownLocation(LocationManager.GPS_PROVIDER) ?: lm.getLastKnownLocation(LocationManager.NETWORK_PROVIDER)
            if (loc != null && System.currentTimeMillis() - loc.time < 600000) loc else null
        } catch (e: Exception) { null }
    }

    private fun triggerAlarm(context: Context) {
        val prefs = context.getSharedPreferences("sentry_settings", Context.MODE_PRIVATE)
        if (!prefs.getBoolean("alarm_vibe", true)) return
        try {
            val vibrator = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                (context.getSystemService(Context.VIBRATOR_MANAGER_SERVICE) as VibratorManager).defaultVibrator
            } else {
                @Suppress("DEPRECATION") context.getSystemService(Context.VIBRATOR_SERVICE) as Vibrator
            }
            vibrator.vibrate(VibrationEffect.createOneShot(500, VibrationEffect.DEFAULT_AMPLITUDE))
        } catch (e: Exception) {}
    }
}
