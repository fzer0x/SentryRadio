package dev.fzer0x.imsicatcherdetector2.security

import android.content.Context
import android.util.Log
import java.text.SimpleDateFormat
import java.util.*
import java.util.concurrent.ConcurrentLinkedQueue

/**
 * Sicherheits-Audit-Log System
 * Protokolliert alle sicherheitsrelevanten Ereignisse für Forensik und Debugging
 */
object SecurityAuditLog {
    private val TAG = "SecurityAudit"
    private val auditQueue = ConcurrentLinkedQueue<AuditEntry>()
    private val dateFormat = SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS", Locale.US)

    data class AuditEntry(
        val timestamp: Long = System.currentTimeMillis(),
        val severity: AuditSeverity,
        val category: AuditCategory,
        val message: String,
        val details: Map<String, Any> = emptyMap(),
        val stackTrace: String? = null
    )

    enum class AuditSeverity {
        INFO, WARNING, ERROR, CRITICAL
    }

    enum class AuditCategory {
        // Security Events
        INPUT_VALIDATION_FAILED,
        API_CALL_BLOCKED,
        CERTIFICATE_PIN_VERIFICATION_FAILED,
        UNAUTHORIZED_ACCESS_ATTEMPT,
        BROADCAST_SIGNATURE_VERIFICATION_FAILED,

        // Performance Events
        REGEX_TIMEOUT,
        PROCESS_TIMEOUT,
        API_TIMEOUT,

        // Threat Events
        IMSI_CATCHER_DETECTED,
        CIPHERING_OFF_DETECTED,
        SILENT_SMS_DETECTED,
        NETWORK_DOWNGRADE_DETECTED,

        // System Events
        SERVICE_STARTED,
        SERVICE_STOPPED,
        XPOSED_HOOK_LOADED,
        XPOSED_HOOK_FAILED,

        // Configuration Events
        SECURITY_SETTING_CHANGED,
        KEY_ROTATION_PERFORMED,
        DATABASE_MIGRATION_STARTED
    }

    fun log(
        severity: AuditSeverity,
        category: AuditCategory,
        message: String,
        details: Map<String, Any> = emptyMap(),
        throwable: Throwable? = null
    ) {
        try {
            val stackTrace = throwable?.let { formatStackTrace(it) }
            val entry = AuditEntry(
                severity = severity,
                category = category,
                message = message,
                details = details,
                stackTrace = stackTrace
            )

            auditQueue.offer(entry)

            // Limit queue size
            if (auditQueue.size > SecurityConfig.AUDIT_LOG_MAX_ENTRIES) {
                auditQueue.poll()
            }

            // Log to Android Log based on severity
            val logMessage = formatLogMessage(entry)
            when (severity) {
                AuditSeverity.INFO -> Log.i(TAG, logMessage)
                AuditSeverity.WARNING -> Log.w(TAG, logMessage)
                AuditSeverity.ERROR -> Log.e(TAG, logMessage, throwable)
                AuditSeverity.CRITICAL -> {
                    Log.e(TAG, "⚠️ CRITICAL SECURITY EVENT ⚠️")
                    Log.e(TAG, logMessage, throwable)
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error logging audit entry: ${e.message}")
        }
    }

    fun logInputValidationFailed(field: String, value: Any, reason: String) {
        log(
            AuditSeverity.WARNING,
            AuditCategory.INPUT_VALIDATION_FAILED,
            "Input validation failed for field: $field",
            mapOf(
                "field" to field,
                "reason" to reason,
                "valueLength" to value.toString().length
            )
        )
    }

    fun logApiCallBlocked(url: String, reason: String) {
        log(
            AuditSeverity.WARNING,
            AuditCategory.API_CALL_BLOCKED,
            "API call blocked: $reason",
            mapOf("url" to url, "reason" to reason)
        )
    }

    fun logCertificatePinVerificationFailed(domain: String) {
        log(
            AuditSeverity.CRITICAL,
            AuditCategory.CERTIFICATE_PIN_VERIFICATION_FAILED,
            "Certificate pinning verification failed for domain: $domain",
            mapOf("domain" to domain)
        )
    }

    fun logUnauthorizedAccessAttempt(source: String, action: String) {
        log(
            AuditSeverity.CRITICAL,
            AuditCategory.UNAUTHORIZED_ACCESS_ATTEMPT,
            "Unauthorized access attempt detected",
            mapOf("source" to source, "action" to action)
        )
    }

    fun logBroadcastSignatureVerificationFailed(action: String) {
        log(
            AuditSeverity.WARNING,
            AuditCategory.BROADCAST_SIGNATURE_VERIFICATION_FAILED,
            "Broadcast signature verification failed for action: $action",
            mapOf("action" to action)
        )
    }

    fun logRegexTimeout(pattern: String) {
        log(
            AuditSeverity.WARNING,
            AuditCategory.REGEX_TIMEOUT,
            "Regex matching timeout",
            mapOf("patternLength" to pattern.length)
        )
    }

    fun logProcessTimeout(command: String) {
        log(
            AuditSeverity.WARNING,
            AuditCategory.PROCESS_TIMEOUT,
            "Process execution timeout",
            mapOf("command" to command)
        )
    }

    fun logImsiCatcherDetected(severity: Int, details: String, simSlot: Int) {
        log(
            if (severity >= 9) AuditSeverity.CRITICAL else AuditSeverity.WARNING,
            AuditCategory.IMSI_CATCHER_DETECTED,
            "IMSI Catcher detected: $details",
            mapOf("severity" to severity, "simSlot" to simSlot)
        )
    }

    fun logCipheringOffDetected(simSlot: Int) {
        log(
            AuditSeverity.CRITICAL,
            AuditCategory.CIPHERING_OFF_DETECTED,
            "Unencrypted connection (A5/0) detected",
            mapOf("simSlot" to simSlot)
        )
    }

    fun logSecuritySettingChanged(setting: String, oldValue: Any?, newValue: Any?) {
        log(
            AuditSeverity.INFO,
            AuditCategory.SECURITY_SETTING_CHANGED,
            "Security setting changed: $setting",
            mapOf(
                "setting" to setting,
                "oldValue" to (oldValue?.toString() ?: "null"),
                "newValue" to (newValue?.toString() ?: "null")
            )
        )
    }

    fun getAuditLog(): List<AuditEntry> {
        return auditQueue.toList()
    }

    fun getAuditLogAsString(): String {
        return auditQueue.joinToString("\n") { formatLogMessage(it) }
    }

    fun clearAuditLog() {
        auditQueue.clear()
    }

    fun getAuditStatistics(): String {
        val entries = auditQueue.toList()
        val bySeverity = entries.groupingBy { it.severity }.eachCount()
        val byCategory = entries.groupingBy { it.category }.eachCount()

        return """
            ╔════════════════════════════════════════════╗
            ║     SECURITY AUDIT LOG STATISTICS          ║
            ╠════════════════════════════════════════════╣
            ║ Total Entries: ${entries.size}
            ║ By Severity:
            ${bySeverity.entries.joinToString("\n") { "║   - ${it.key}: ${it.value}" }}
            ║ Critical Categories:
            ${byCategory.entries.filter { it.value > 0 }.take(5).joinToString("\n") { "║   - ${it.key}: ${it.value}" }}
            ╚════════════════════════════════════════════╝
        """.trimIndent()
    }

    private fun formatLogMessage(entry: AuditEntry): String {
        val timestamp = dateFormat.format(Date(entry.timestamp))
        val detailsStr = if (entry.details.isNotEmpty()) {
            " | ${entry.details.entries.joinToString(", ") { "${it.key}=${it.value}" }}"
        } else {
            ""
        }
        return "[$timestamp] [${entry.severity}] [${entry.category}] ${entry.message}$detailsStr"
    }

    private fun formatStackTrace(throwable: Throwable): String {
        val sw = java.io.StringWriter()
        throwable.printStackTrace(java.io.PrintWriter(sw))
        return sw.toString().take(500) // Limit to 500 chars
    }
}
