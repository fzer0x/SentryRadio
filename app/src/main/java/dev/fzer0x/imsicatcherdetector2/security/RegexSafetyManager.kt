package dev.fzer0x.imsicatcherdetector2.security

import android.util.Log
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.regex.PatternSyntaxException

object RegexSafetyManager {
    private val TAG = "RegexSafety"
    
    // Centralized timeout configuration
    private val DEFAULT_TIMEOUT_MS = 100L
    private val MAX_TIMEOUT_MS = 5000L
    private val threadPool = java.util.concurrent.Executors.newCachedThreadPool { r ->
        Thread(r, "RegexSafety-${Thread.currentThread().id}").apply {
            isDaemon = true
            priority = Thread.MIN_PRIORITY
        }
    }
    
    // Thread-safe regex pattern cache with LRU eviction
    private val patternCache = ConcurrentHashMap<String, CacheEntry>()
    private val MAX_CACHE_SIZE = 500 // Increased from 100
    private val CACHE_TTL_MS = 300_000L // 5 minutes TTL
    
    // Cache entry with timestamp and access count
    private data class CacheEntry(
        val pattern: java.util.regex.Pattern,
        val timestamp: Long = System.currentTimeMillis(),
        var accessCount: Long = 0,
        var lastAccess: Long = System.currentTimeMillis()
    )
    
    // Performance metrics
    private var cacheHits = 0L
    private var cacheMisses = 0L
    private var totalCompilations = 0L

    fun safeRegexMatch(pattern: String, input: String, timeoutMs: Long = DEFAULT_TIMEOUT_MS): Boolean {
        val actualTimeout = timeoutMs.coerceIn(1, MAX_TIMEOUT_MS)
        
        return try {
            // Get or create compiled pattern from enhanced cache
            val compiledPattern = getOrCompilePattern(pattern)

            // Execute match with timeout using thread pool
            val future = threadPool.submit<Boolean> {
                try {
                    compiledPattern.matcher(input).find()
                } catch (e: Exception) {
                    Log.w(TAG, "Regex match error: ${e.message}")
                    false
                }
            }

            try {
                future.get(actualTimeout, TimeUnit.MILLISECONDS)
            } catch (e: java.util.concurrent.TimeoutException) {
                future.cancel(true)
                Log.w(TAG, "Regex match timeout for pattern: ${pattern.take(50)}")
                false
            } catch (e: Exception) {
                Log.e(TAG, "Regex execution error: ${e.message}")
                false
            }
        } catch (e: PatternSyntaxException) {
            Log.w(TAG, "Invalid regex pattern: ${e.message}")
            false
        } catch (e: Exception) {
            Log.e(TAG, "Regex error: ${e.message}")
            false
        }
    }

    fun safeRegexExtract(pattern: String, input: String, group: Int = 1, timeoutMs: Long = DEFAULT_TIMEOUT_MS): String? {
        val actualTimeout = timeoutMs.coerceIn(1, MAX_TIMEOUT_MS)
        
        return try {
            val compiledPattern = getOrCompilePattern(pattern)

            val future = threadPool.submit<String?> {
                try {
                    val matcher = compiledPattern.matcher(input)
                    if (matcher.find() && group <= matcher.groupCount()) {
                        matcher.group(group)
                    } else null
                } catch (e: Exception) {
                    Log.w(TAG, "Regex extract error: ${e.message}")
                    null
                }
            }

            try {
                future.get(actualTimeout, TimeUnit.MILLISECONDS)
            } catch (e: java.util.concurrent.TimeoutException) {
                future.cancel(true)
                Log.w(TAG, "Regex extract timeout")
                null
            } catch (e: Exception) {
                Log.e(TAG, "Regex extract error: ${e.message}")
                null
            }
        } catch (e: Exception) {
            Log.e(TAG, "Regex extract error: ${e.message}")
            null
        }
    }

    fun sanitizeForRegex(input: String): String {
        return java.util.regex.Pattern.quote(input)
    }
    
    /**
     * Get or compile pattern with enhanced caching
     */
    private fun getOrCompilePattern(pattern: String): java.util.regex.Pattern {
        val now = System.currentTimeMillis()
        
        // Try to get from cache
        val cachedEntry = patternCache[pattern]
        if (cachedEntry != null) {
            // Check if cache entry is still valid
            if (now - cachedEntry.timestamp < CACHE_TTL_MS) {
                // Update access statistics
                cachedEntry.accessCount++
                cachedEntry.lastAccess = now
                cacheHits++
                return cachedEntry.pattern
            } else {
                // Remove expired entry
                patternCache.remove(pattern)
            }
        }
        
        cacheMisses++
        totalCompilations++
        
        // Compile new pattern
        val compiledPattern = java.util.regex.Pattern.compile(pattern)
        val newEntry = CacheEntry(compiledPattern, now, 1L, now)
        
        // Add to cache with eviction if needed
        if (patternCache.size >= MAX_CACHE_SIZE) {
            evictLeastUsefulEntries()
        }
        
        patternCache[pattern] = newEntry
        return compiledPattern
    }
    
    /**
     * Intelligent LRU+LFU hybrid eviction strategy
     */
    private fun evictLeastUsefulEntries() {
        val now = System.currentTimeMillis()
        val entriesToRemove = patternCache.entries
            .sortedWith(compareBy<Map.Entry<String, CacheEntry>> { 
                // Primary sort: Age (older first)
                now - it.value.timestamp 
            }.thenBy { 
                // Secondary sort: Access frequency (less frequent first)
                it.value.accessCount 
            }.thenBy { 
                // Tertiary sort: Last access time (older first)
                now - it.value.lastAccess 
            })
            .take(MAX_CACHE_SIZE / 10) // Remove 10% of entries
            .map { it.key }
        
        entriesToRemove.forEach { key -> 
            patternCache.remove(key)
        }
        
        Log.d(TAG, "Cache eviction: removed ${entriesToRemove.size} entries")
    }
    
    /**
     * Get cache performance statistics
     */
    fun getCacheStats(): Map<String, Any> {
        val totalRequests = cacheHits + cacheMisses
        val hitRate = if (totalRequests > 0) (cacheHits.toDouble() / totalRequests * 100) else 0.0
        
        return mapOf(
            "cacheSize" to patternCache.size,
            "maxCacheSize" to MAX_CACHE_SIZE,
            "cacheHits" to cacheHits,
            "cacheMisses" to cacheMisses,
            "hitRate" to hitRate,
            "totalCompilations" to totalCompilations,
            "cacheTtlMinutes" to (CACHE_TTL_MS / 60_000)
        )
    }
    
    /**
     * Clear pattern cache and reset statistics
     */
    fun clearCache() {
        patternCache.clear()
        cacheHits = 0L
        cacheMisses = 0L
        totalCompilations = 0L
        Log.d(TAG, "Cache cleared and statistics reset")
    }
    
    /**
     * Precompile common patterns for better performance
     */
    fun precompileCommonPatterns() {
        val commonPatterns = listOf(
            "CIPHERING\\s*[:=]\\s*OFF",
            "CIPHERING\\s*[:=]\\s*0",
            "A5/0",
            "NO\\s*CIPHER",
            "\\d{4}-\\d{2}-\\d{2}", // Date patterns
            "\\b[A-F0-9]{8}\\b", // Hex patterns
            "\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}" // IP patterns
        )
        
        commonPatterns.forEach { pattern ->
            try {
                getOrCompilePattern(pattern)
            } catch (e: Exception) {
                Log.w(TAG, "Failed to precompile pattern: $pattern")
            }
        }
        
        Log.d(TAG, "Precompiled ${commonPatterns.size} common patterns")
    }
    
    /**
     * Clear pattern cache and shutdown thread pool
     */
    fun cleanup() {
        clearCache()
        threadPool.shutdown()
        try {
            if (!threadPool.awaitTermination(5, TimeUnit.SECONDS)) {
                threadPool.shutdownNow()
            }
        } catch (e: InterruptedException) {
            threadPool.shutdownNow()
            Thread.currentThread().interrupt()
        }
    }
}
