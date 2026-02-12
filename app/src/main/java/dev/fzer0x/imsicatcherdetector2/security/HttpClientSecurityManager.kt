package dev.fzer0x.imsicatcherdetector2.security

import android.util.Log
import okhttp3.ConnectionSpec
import okhttp3.OkHttpClient
import okhttp3.TlsVersion
import java.util.concurrent.TimeUnit
import java.util.concurrent.ConcurrentHashMap

object HttpClientSecurityManager {
    private val TAG = "HttpSecurityMgr"
    
    // Performance optimization: Cache HTTP clients
    private val clientCache = ConcurrentHashMap<String, OkHttpClient>()
    private val MAX_CACHE_SIZE = 5
    private val CACHE_TTL = 5 * 60 * 1000L // 5 minutes
    private val cacheTimestamps = ConcurrentHashMap<String, Long>()

    /**
     * Creates a secure OkHttpClient with enforced TLS 1.2+ and performance optimizations.
     */
    fun createSecureOkHttpClient(): OkHttpClient {
        return getCachedClient("default") {
            createBaseClient().build()
        }
    }

    /**
     * Creates a secure OkHttpClient with custom timeouts and caching.
     */
    fun createSecureOkHttpClientWithTimeout(
        connectTimeoutSec: Long = 10,
        readTimeoutSec: Long = 30,
        writeTimeoutSec: Long = 30
    ): OkHttpClient {
        val cacheKey = "${connectTimeoutSec}_${readTimeoutSec}_${writeTimeoutSec}"
        return getCachedClient(cacheKey) {
            createBaseClient()
                .connectTimeout(connectTimeoutSec, TimeUnit.SECONDS)
                .readTimeout(readTimeoutSec, TimeUnit.SECONDS)
                .writeTimeout(writeTimeoutSec, TimeUnit.SECONDS)
                .callTimeout(connectTimeoutSec + readTimeoutSec, TimeUnit.SECONDS)
                .build()
        }
    }
    
    /**
     * Base client configuration with security settings
     */
    private fun createBaseClient(): OkHttpClient.Builder {
        return try {
            // Enforce TLS 1.2+ only
            val connectionSpec = ConnectionSpec.Builder(ConnectionSpec.RESTRICTED_TLS)
                .tlsVersions(TlsVersion.TLS_1_2, TlsVersion.TLS_1_3)
                .build()

            OkHttpClient.Builder()
                .connectTimeout(15, TimeUnit.SECONDS)
                .readTimeout(30, TimeUnit.SECONDS)
                .writeTimeout(30, TimeUnit.SECONDS)
                .callTimeout(60, TimeUnit.SECONDS)
                .connectionSpecs(listOf(connectionSpec))
                .retryOnConnectionFailure(true)
        } catch (e: Exception) {
            Log.e(TAG, "Error creating base OkHttpClient: ${e.message}")
            OkHttpClient.Builder()
        }
    }
    
    /**
     * Get cached client or create and cache new one
     */
    private fun getCachedClient(key: String, factory: () -> OkHttpClient): OkHttpClient {
        // Check cache first
        val cachedClient = clientCache[key]
        val timestamp = cacheTimestamps[key] ?: 0L
        
        if (cachedClient != null && (System.currentTimeMillis() - timestamp < CACHE_TTL)) {
            return cachedClient
        }
        
        // Create new client
        val newClient = factory()
        
        // Cleanup old cache entries if needed
        if (clientCache.size >= MAX_CACHE_SIZE) {
            cleanupCache()
        }
        
        // Cache the new client
        clientCache[key] = newClient
        cacheTimestamps[key] = System.currentTimeMillis()
        
        return newClient
    }
    
    /**
     * Cleanup old cache entries
     */
    private fun cleanupCache() {
        val now = System.currentTimeMillis()
        val cutoff = now - CACHE_TTL
        
        cacheTimestamps.entries.removeIf { (key, timestamp) ->
            if (timestamp < cutoff) {
                clientCache.remove(key)
                true
            } else {
                false
            }
        }
        
        // If still too many entries, remove oldest ones
        if (clientCache.size > MAX_CACHE_SIZE / 2) {
            val sortedEntries = cacheTimestamps.toList().sortedBy { it.second }
            val toRemove = sortedEntries.take(clientCache.size - MAX_CACHE_SIZE / 2)
            
            toRemove.forEach { (key, _) ->
                clientCache.remove(key)
                cacheTimestamps.remove(key)
            }
        }
    }
    
    /**
     * Clear all cached clients
     */
    fun clearCache() {
        clientCache.clear()
        cacheTimestamps.clear()
    }
}
