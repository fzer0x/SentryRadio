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
import dev.fzer0x.imsicatcherdetector2.security.InputValidator
import dev.fzer0x.imsicatcherdetector2.service.CellLookupManager
import dev.fzer0x.imsicatcherdetector2.ui.AlertActivity
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import java.util.concurrent.ConcurrentHashMap
import kotlin.math.*

class ForensicReceiver : BroadcastReceiver() {

    private val TAG = "ForensicReceiver"

    companion object {
        private val apiThrottleCache = ConcurrentHashMap<String, Long>()
        private val lastLacs = ConcurrentHashMap<Int, Int>()
        private val lastCellIds = ConcurrentHashMap<Int, String>()
    }

    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != "dev.fzer0x.imsicatcherdetector2.FORENSIC_EVENT") return

        val eventTypeStr = intent.getStringExtra("eventType") ?: return
        val descriptionStr = intent.getStringExtra("description") ?: ""
        val cellId = intent.getStringExtra("cellId")
        val simSlot = intent.getIntExtra("simSlot", 0)
        val isNeighbor = intent.getBooleanExtra("isNeighbor", false)

        if (!InputValidator.validateSimSlot(simSlot)) return
        if (cellId != null && cellId.isBlank()) return

        val eventType = try { EventType.valueOf(eventTypeStr) } catch(e: Exception) {
            when(eventTypeStr) {
                "CIPHERING_OFF" -> EventType.CIPHERING_OFF
                "IMSI_CATCHER_ALERT" -> EventType.IMSI_CATCHER_ALERT
                "RADIO_METRICS_UPDATE" -> EventType.RADIO_METRICS_UPDATE
                "CELL_DOWNGRADE" -> EventType.CELL_DOWNGRADE
                "SILENT_SMS" -> EventType.SILENT_SMS
                "LOCATION_ANOMALY" -> EventType.LOCATION_ANOMALY
                "TIMING_ADVANCE_ANOMALY" -> EventType.TIMING_ADVANCE_ANOMALY
                "HYBRID_ATTACK_SUSPECTED" -> EventType.IMSI_CATCHER_ALERT
                else -> return
            }
        }

        val mcc = intent.getStringExtra("mcc")
        val mnc = intent.getStringExtra("mnc")
        val lac = if (intent.hasExtra("lac")) intent.getIntExtra("lac", -1).let { if (it == -1) null else it } else null
        val tac = if (intent.hasExtra("tac")) intent.getIntExtra("tac", -1).let { if (it == -1) null else it } else null
        val pci = if (intent.hasExtra("pci")) intent.getIntExtra("pci", -1).let { if (it == -1) null else it } else null
        val dbm = if (intent.hasExtra("dbm")) intent.getIntExtra("dbm", -120).let { if (it == -120) null else it } else null
        val ta = if (intent.hasExtra("ta")) intent.getIntExtra("ta", -1).let { if (it == -1) null else it } else null
        val earfcn = if (intent.hasExtra("earfcn")) intent.getIntExtra("earfcn", -1).let { if (it == -1) null else it } else null
        val neighbors = if (intent.hasExtra("neighbors")) intent.getIntExtra("neighbors", -1).let { if (it == -1) null else it } else null
        val networkType = intent.getStringExtra("networkType") ?: "LTE"
        var severity = intent.getIntExtra("severity", 1)
        var description = descriptionStr

        val currentLac = lac ?: tac
        val lastLac = lastLacs[simSlot]
        val lastCellId = lastCellIds[simSlot]

        if (!isNeighbor) {
            if (currentLac != null && lastLac != null && currentLac != lastLac) {
                if (cellId != null && cellId == lastCellId) {
                    severity = 9
                    description = "CRITICAL: LAC changed for SAME Cell ID ($lastLac -> $currentLac) on SIM $simSlot"
                }
            }
            if (currentLac != null) lastLacs[simSlot] = currentLac
            if (cellId != null) lastCellIds[simSlot] = cellId
        }

        val event = ForensicEvent(
            type = eventType, severity = severity, description = description, cellId = cellId,
            lac = lac, tac = tac, pci = pci, mnc = mnc, mcc = mcc,
            networkType = networkType, signalStrength = dbm, neighborCount = neighbors,
            timingAdvance = ta, earfcn = earfcn, simSlot = simSlot, rawData = intent.getStringExtra("rawData")
        )

        val db = ForensicDatabase.getDatabase(context)
        val dao = db.forensicDao()
        val prefs = context.getSharedPreferences("sentry_settings", Context.MODE_PRIVATE)
        
        CoroutineScope(Dispatchers.IO).launch {
            dao.insertEvent(event)

            if (cellId != null && mcc != null && mnc != null) {
                val realLac = currentLac ?: 0
                val lastRequest = apiThrottleCache[cellId] ?: 0L
                val isThrottled = System.currentTimeMillis() - lastRequest < 5000 

                val existingTower = dao.getTowerById(cellId)
                val localLoc = requestFreshLocation(context)

                if (existingTower == null || existingTower.latitude == null || !existingTower.isVerified) {
                    if (!isThrottled) {
                        apiThrottleCache[cellId] = System.currentTimeMillis()
                        val result = CellLookupManager(
                            beaconDbKey = prefs.getString("beacondb_key", "") ?: "",
                            openCellIdKey = prefs.getString("opencellid_key", "") ?: "",
                            useBeaconDb = prefs.getBoolean("use_beacondb", true),
                            useOpenCellId = prefs.getBoolean("use_opencellid", false)
                        ).lookup(mcc, mnc, realLac, cellId, networkType, pci, ta, dbm)

                        if (result.isFound && result.lat != null && result.lon != null) {
                            // LOCATION VALIDATION
                            if (localLoc != null) {
                                val distance = calculateDistance(localLoc.latitude, localLoc.longitude, result.lat, result.lon)
                                if (distance > 50000) { // > 50km is extremely suspicious
                                    val alertDesc = "LOCATION ANOMALY: Cell $cellId reported at ${result.lat}, ${result.lon} is ${distance/1000}km away!"
                                    Log.e(TAG, alertDesc)
                                    dao.insertEvent(ForensicEvent(
                                        type = EventType.IMSI_CATCHER_ALERT,
                                        severity = 10,
                                        description = alertDesc,
                                        cellId = cellId,
                                        simSlot = simSlot,
                                        mcc = mcc,
                                        mnc = mnc,
                                        lac = lac,
                                        tac = tac,
                                        signalStrength = dbm,
                                        earfcn = earfcn
                                    ))
                                    
                                    // Trigger Hybrid Scan for location anomalies
                                    context.sendBroadcast(Intent("dev.fzer0x.imsicatcherdetector2.TRIGGER_HYBRID_SCAN").apply {
                                        putExtra("reason", "Location Anomaly ($cellId)")
                                    })
                                }
                            }

                            val tower = existingTower ?: CellTower(
                                cellId = cellId, mcc = mcc, mnc = mnc, lac = realLac, rat = networkType
                            )
                            dao.upsertTower(tower.copy(
                                latitude = result.lat, longitude = result.lon,
                                pci = pci ?: tower.pci, ta = ta ?: tower.ta, dbm = dbm ?: tower.dbm,
                                isVerified = true, isMissingInDb = false, range = result.range,
                                lastSeen = System.currentTimeMillis(), source = result.source
                            ))
                        } else if (existingTower == null) {
                             // UNKNOWN CELL -> Possible IMSI Catcher
                             if (localLoc != null) {
                                 dao.upsertTower(CellTower(
                                    cellId = cellId, mcc = mcc, mnc = mnc, lac = realLac, rat = networkType,
                                    latitude = localLoc.latitude, longitude = localLoc.longitude,
                                    pci = pci, ta = ta, dbm = dbm, isVerified = false, source = "Local GPS",
                                    isMissingInDb = true
                                ))
                                
                                // Trigger Hybrid Scan for completely unknown cells
                                context.sendBroadcast(Intent("dev.fzer0x.imsicatcherdetector2.TRIGGER_HYBRID_SCAN").apply {
                                    putExtra("reason", "Unknown Cell ($cellId)")
                                })
                             }
                        }
                    }
                } else {
                    dao.upsertTower(existingTower.copy(
                        lastSeen = System.currentTimeMillis(),
                        pci = pci ?: existingTower.pci, ta = ta ?: existingTower.ta, dbm = dbm ?: existingTower.dbm
                    ))
                }
            }
        }
    }

    private fun calculateDistance(lat1: Double, lon1: Double, lat2: Double, lon2: Double): Double {
        val r = 6371e3
        val phi1 = lat1 * PI / 180
        val phi2 = lat2 * PI / 180
        val deltaPhi = (lat2 - lat1) * PI / 180
        val deltaLambda = (lon2 - lon1) * PI / 180
        val a = sin(deltaPhi / 2).pow(2) + cos(phi1) * cos(phi2) * sin(deltaLambda / 2).pow(2)
        val c = 2 * atan2(sqrt(a), sqrt(1 - a))
        return r * c
    }

    private fun requestFreshLocation(context: Context): Location? {
        if (ContextCompat.checkSelfPermission(context, Manifest.permission.ACCESS_FINE_LOCATION) != PackageManager.PERMISSION_GRANTED) return null
        val lm = context.getSystemService(Context.LOCATION_SERVICE) as LocationManager
        return try { lm.getLastKnownLocation(LocationManager.GPS_PROVIDER) ?: lm.getLastKnownLocation(LocationManager.NETWORK_PROVIDER) } catch (e: Exception) { null }
    }
}
