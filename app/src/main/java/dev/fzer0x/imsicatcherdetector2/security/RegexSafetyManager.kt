package dev.fzer0x.imsicatcherdetector2.security

import android.util.Log
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.regex.PatternSyntaxException

object RegexSafetyManager {
    private val TAG = "RegexSafety"
    private const val REGEX_TIMEOUT_MS = 100L // 100ms timeout für Regex-Matching

    fun safeRegexMatch(pattern: String, input: String, timeoutMs: Long = REGEX_TIMEOUT_MS): Boolean {
        return try {
            // Validiere Pattern kompiliert werden kann
            val compiledPattern = java.util.regex.Pattern.compile(pattern)

            // Führe Match mit Timeout aus
            val result = CountDownLatch(1)
            var matched = false

            val thread = Thread {
                try {
                    matched = compiledPattern.matcher(input).find()
                    result.countDown()
                } catch (e: Exception) {
                    Log.w(TAG, "Regex match error: ${e.message}")
                    result.countDown()
                }
            }
            thread.isDaemon = true
            thread.start()

            // Warte mit Timeout
            if (result.await(timeoutMs, TimeUnit.MILLISECONDS)) {
                matched
            } else {
                Log.w(TAG, "Regex match timeout for pattern: ${pattern.take(50)}")
                thread.interrupt()
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

    fun safeRegexExtract(pattern: String, input: String, group: Int = 1, timeoutMs: Long = REGEX_TIMEOUT_MS): String? {
        return try {
            val compiledPattern = java.util.regex.Pattern.compile(pattern)

            val result = CountDownLatch(1)
            var extracted: String? = null

            val thread = Thread {
                try {
                    val matcher = compiledPattern.matcher(input)
                    if (matcher.find() && group <= matcher.groupCount()) {
                        extracted = matcher.group(group)
                    }
                    result.countDown()
                } catch (e: Exception) {
                    Log.w(TAG, "Regex extract error: ${e.message}")
                    result.countDown()
                }
            }
            thread.isDaemon = true
            thread.start()

            if (result.await(timeoutMs, TimeUnit.MILLISECONDS)) {
                extracted
            } else {
                Log.w(TAG, "Regex extract timeout")
                thread.interrupt()
                null
            }
        } catch (e: Exception) {
            Log.e(TAG, "Regex extract error: ${e.message}")
            null
        }
    }

    fun sanitizeForRegex(input: String): String {
        // Escape special regex characters
        return java.util.regex.Pattern.quote(input)
    }
}
