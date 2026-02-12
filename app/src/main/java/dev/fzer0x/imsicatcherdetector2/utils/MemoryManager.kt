package dev.fzer0x.imsicatcherdetector2.utils

import android.app.ActivityManager
import android.content.Context
import android.os.Debug
import kotlinx.coroutines.*
import java.util.concurrent.ConcurrentHashMap

/**
 * Memory Manager for optimizing memory usage and preventing leaks
 */
object MemoryManager {
    
    private val memoryCache = ConcurrentHashMap<String, Any>()
    private val cacheTimestamps = ConcurrentHashMap<String, Long>()
    private val MAX_CACHE_SIZE = 100
    private val CACHE_TTL = 5 * 60 * 1000L // 5 minutes
    
    private var isMonitoring = false
    private var monitoringJob: Job? = null
    
    /**
     * Initialize memory monitoring
     */
    fun initialize(context: Context) {
        if (!isMonitoring) {
            isMonitoring = true
            startMemoryMonitoring(context)
        }
    }
    
    /**
     * Cache data with automatic cleanup
     */
    fun cache(key: String, value: Any) {
        // Cleanup old entries if cache is full
        if (memoryCache.size >= MAX_CACHE_SIZE) {
            cleanupCache()
        }
        
        memoryCache[key] = value
        cacheTimestamps[key] = System.currentTimeMillis()
    }
    
    /**
     * Get cached data
     */
    @Suppress("UNCHECKED_CAST")
    fun <T> getCache(key: String): T? {
        val timestamp = cacheTimestamps[key] ?: return null
        
        // Check if cache entry is still valid
        if (System.currentTimeMillis() - timestamp > CACHE_TTL) {
            memoryCache.remove(key)
            cacheTimestamps.remove(key)
            return null
        }
        
        return memoryCache[key] as? T
    }
    
    /**
     * Clear cache entries older than TTL
     */
    private fun cleanupCache() {
        val now = System.currentTimeMillis()
        val cutoff = now - CACHE_TTL
        
        cacheTimestamps.entries.removeIf { (key, timestamp) ->
            if (timestamp < cutoff) {
                memoryCache.remove(key)
                true
            } else {
                false
            }
        }
        
        // If still too many entries, remove oldest ones
        if (memoryCache.size > MAX_CACHE_SIZE / 2) {
            val sortedEntries = cacheTimestamps.toList().sortedBy { it.second }
            val toRemove = sortedEntries.take(memoryCache.size - MAX_CACHE_SIZE / 2)
            
            toRemove.forEach { (key, _) ->
                memoryCache.remove(key)
                cacheTimestamps.remove(key)
            }
        }
    }
    
    /**
     * Start memory monitoring
     */
    private fun startMemoryMonitoring(context: Context) {
        monitoringJob = CoroutineScope(Dispatchers.IO).launch {
            while (isActive) {
                try {
                    val memoryInfo = getMemoryInfo(context)
                    
                    // Trigger garbage collection if memory usage is high
                    if (memoryInfo.availMem < memoryInfo.totalMem * 0.1) { // Less than 10% available
                        System.gc()
                        cleanupCache()
                    }
                    
                    // Log memory usage for debugging
                    if (memoryInfo.availMem < memoryInfo.totalMem * 0.2) { // Less than 20% available
                        val usedPercentage = ((memoryInfo.totalMem - memoryInfo.availMem) * 100 / memoryInfo.totalMem).toInt()
                        android.util.Log.w("MemoryManager", "Memory usage high: ${usedPercentage}% used")
                    }
                    
                } catch (e: Exception) {
                    android.util.Log.e("MemoryManager", "Error in memory monitoring", e)
                }
                
                delay(30000) // Check every 30 seconds
            }
        }
    }
    
    /**
     * Get current memory information
     */
    private fun getMemoryInfo(context: Context): ActivityManager.MemoryInfo {
        val activityManager = context.getSystemService(Context.ACTIVITY_SERVICE) as ActivityManager
        val memoryInfo = ActivityManager.MemoryInfo()
        activityManager.getMemoryInfo(memoryInfo)
        return memoryInfo
    }
    
    /**
     * Get detailed memory statistics
     */
    fun getMemoryStats(context: Context): MemoryStats {
        val memoryInfo = getMemoryInfo(context)
        val runtime = Runtime.getRuntime()
        val heapInfo = Debug.MemoryInfo()
        Debug.getMemoryInfo(heapInfo)
        
        return MemoryStats(
            totalMemory = runtime.totalMemory(),
            freeMemory = runtime.freeMemory(),
            maxMemory = runtime.maxMemory(),
            usedMemory = runtime.totalMemory() - runtime.freeMemory(),
            systemTotalMemory = memoryInfo.totalMem,
            systemAvailableMemory = memoryInfo.availMem,
            systemThreshold = memoryInfo.threshold,
            nativeHeapSize = heapInfo.nativePss,
            dalvikHeapSize = heapInfo.dalvikPss
        )
    }
    
    /**
     * Force cleanup of all caches
     */
    fun forceCleanup() {
        memoryCache.clear()
        cacheTimestamps.clear()
        System.gc()
    }
    
    /**
     * Stop memory monitoring
     */
    fun stop() {
        monitoringJob?.cancel()
        isMonitoring = false
        forceCleanup()
    }
}

data class MemoryStats(
    val totalMemory: Long,
    val freeMemory: Long,
    val maxMemory: Long,
    val usedMemory: Long,
    val systemTotalMemory: Long,
    val systemAvailableMemory: Long,
    val systemThreshold: Long,
    val nativeHeapSize: Int,
    val dalvikHeapSize: Int
) {
    val memoryUsagePercentage: Int
        get() = ((usedMemory * 100) / maxMemory).toInt()
        
    val systemMemoryUsagePercentage: Int
        get() = (((systemTotalMemory - systemAvailableMemory) * 100) / systemTotalMemory).toInt()
}
