package dev.fzer0x.imsicatcherdetector2.service

import android.annotation.SuppressLint
import android.bluetooth.BluetoothManager
import android.bluetooth.le.ScanCallback
import android.bluetooth.le.ScanResult
import android.content.Context
import android.net.wifi.ScanResult as WifiScanResult
import android.net.wifi.WifiManager
import android.os.Build
import android.util.Log
import androidx.core.content.ContextCompat.getSystemService
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/**
 * Scanner for Wi-Fi and Bluetooth LE devices.
 * Used for cross-correlation with suspicious cellular events.
 */
class WifiBluetoothScanner(private val context: Context) {
    private val TAG = "WifiBluetoothScanner"
    
    private val wifiManager = context.applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
    private val bluetoothAdapter by lazy {
        (context.applicationContext.getSystemService(Context.BLUETOOTH_SERVICE) as? BluetoothManager)?.adapter
    }
    
    private val _wifiResults = MutableStateFlow<List<WifiScanResult>>(emptyList())
    val wifiResults = _wifiResults.asStateFlow()
    
    private val _bleResults = MutableStateFlow<List<ScanResult>>(emptyList())
    val bleResults = _bleResults.asStateFlow()

    private val scanMutex = Mutex()

    @SuppressLint("MissingPermission")
    suspend fun performQuickScan(durationMs: Long = 5000) = scanMutex.withLock {
        Log.d(TAG, "Starting quick hybrid scan for correlation...")
        
        // Start Wi-Fi Scan
        try {
            wifiManager.startScan()
        } catch (e: Exception) {
            Log.w(TAG, "Wi-Fi scan failed: ${e.message}")
        }
        
        // Start BLE Scan
        val bleScanner = bluetoothAdapter?.bluetoothLeScanner
        val bleCallback = object : ScanCallback() {
            val results = mutableListOf<ScanResult>()
            override fun onScanResult(callbackType: Int, result: ScanResult) {
                if (results.none { it.device.address == result.device.address }) {
                    results.add(result)
                    _bleResults.value = results.toList()
                }
            }
        }

        try {
            bleScanner?.startScan(bleCallback)
        } catch (e: Exception) {
            Log.w(TAG, "BLE scan failed: ${e.message}")
        }

        delay(durationMs)

        // Stop scans and collect results
        try {
            bleScanner?.stopScan(bleCallback)
            _wifiResults.value = wifiManager.scanResults
        } catch (e: Exception) {
            Log.w(TAG, "Error stopping scans: ${e.message}")
        }
        
        Log.d(TAG, "Hybrid scan completed. Found ${_wifiResults.value.size} Wi-Fi and ${_bleResults.value.size} BLE devices.")
    }

    /**
     * Checks if current environment contains "suspicious" wireless signatures.
     * e.g. Wi-Fi networks with no SSID or specific vendor prefixes often used in surveillance gear.
     */
    fun analyzeEnvironment(): EnvironmentRisk {
        val wifiList = _wifiResults.value
        val bleList = _bleResults.value
        
        val suspiciousWifi = wifiList.filter { 
            it.SSID.isEmpty() || it.SSID.contains("Tactical", true) || it.SSID.contains("Surveillance", true)
        }
        
        val highSignalBle = bleList.filter { it.rssi > -50 }
        
        val riskScore = (suspiciousWifi.size * 30 + highSignalBle.size * 10).coerceAtMost(100)
        
        return EnvironmentRisk(
            score = riskScore,
            description = "Detected ${suspiciousWifi.size} hidden/suspicious Wi-Fi and ${highSignalBle.size} strong BLE devices.",
            suspiciousEntities = suspiciousWifi.map { "Wifi: ${it.BSSID}" } + highSignalBle.map { "BLE: ${it.device.address}" }
        )
    }

    data class EnvironmentRisk(
        val score: Int,
        val description: String,
        val suspiciousEntities: List<String>
    )
}
