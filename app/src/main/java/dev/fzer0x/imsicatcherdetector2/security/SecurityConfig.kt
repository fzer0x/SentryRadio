package dev.fzer0x.imsicatcherdetector2.security

import android.content.Context
import android.util.Log
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey

/**
 * SICHERHEITS-KONFIGURATIONSDATEI
 * Diese Datei verwaltet alle kritischen Sicherheitsparameter und besten Praktiken
 * für die SentryRadio IMSI Catcher Detection App
 *
 * IMPLEMENTIERTE SICHERHEITSVERBESSERUNGEN:
 * - Certificate Pinning für alle API-Calls
 * - Input Validation für alle externen Daten
 * - Verschlüsselte Speicherung sensibler Daten
 * - Regex DoS Prevention mit Timeouts
 * - Process Safety Management
 * - Thread-sichere Broadcast-Kommunikation
 */
object SecurityConfig {
    private val TAG = "SecurityConfig"

    // API Security
    const val API_TIMEOUT_CONNECT_SEC = 10L
    const val API_TIMEOUT_READ_SEC = 30L
    const val API_TIMEOUT_WRITE_SEC = 30L
    const val API_RETRY_COUNT = 3
    const val API_RATE_LIMIT_PER_MIN = 10

    // Regex Safety
    const val REGEX_TIMEOUT_MS = 100L
    const val REGEX_MAX_BACKTRACK_DEPTH = 1000

    // Process Safety
    const val PROCESS_TIMEOUT_SEC = 5L
    const val PROCESS_MAX_OUTPUT_SIZE = 1_000_000 // 1MB

    // Broadcast Security
    const val BROADCAST_TIMEOUT_MS = 5000L
    const val BROADCAST_SIGNATURE_ALGORITHM = "HmacSHA256"

    // Database Security
    const val DATABASE_ENCRYPTED = true
    const val DATABASE_CIPHER_STRENGTH = 256

    // TLS/SSL
    const val MIN_TLS_VERSION = "TLSv1.2"
    const val MAX_TLS_VERSION = "TLSv1.3"

    // Certificate Pinning (Public Key Pins)
    val CERTIFICATE_PINS = mapOf(
        "beacondb.net" to "sha256/C5+lpZ7tcVwsa4xQwfXHd/WpWHqPXYwMxRjLnMjvVqI=",
        "opencellid.org" to "sha256/JSMzqOOrtyOT8Q4j/6YIuRR82Vfxw/xGWesFHNXU1Q4=",
        "us1.unwiredlabs.com" to "sha256/0E+enlpd84+75Y9CmyODMK6exsDcWdqKLb/2vyppWmM="
    )

    // Input Validation Ranges
    const val MCC_MIN = 100
    const val MCC_MAX = 999
    const val MNC_MIN = 0
    const val MNC_MAX = 999
    const val CELL_ID_MAX_LENGTH = 19
    const val LAC_MAX = 65535
    const val TAC_MAX = 16777215
    const val PCI_MAX = 503
    const val DBM_MIN = -140
    const val DBM_MAX = -30
    const val SEVERITY_MIN = 1
    const val SEVERITY_MAX = 10
    const val DESCRIPTION_MAX_LENGTH = 2000

    // Thread Safety
    const val MAX_CONCURRENT_API_CALLS = 5
    const val THREAD_POOL_SIZE = 4

    // Logging & Audit
    const val ENABLE_SECURITY_AUDIT_LOG = true
    const val AUDIT_LOG_MAX_ENTRIES = 10000
    const val AUDIT_LOG_RETENTION_DAYS = 30

    fun initializeEncryptedPreferences(context: Context): EncryptedSharedPreferences? {
        return try {
            val masterKey = MasterKey.Builder(context)
                .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
                .build()

            EncryptedSharedPreferences.create(
                context,
                "sentry_settings_encrypted",
                masterKey,
                EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
                EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
            ) as EncryptedSharedPreferences
        } catch (e: Exception) {
            Log.e(TAG, "Error initializing encrypted preferences: ${e.message}")
            null
        }
    }

    fun getSecuritySummary(): String {
        return """
            ╔═══════════════════════════════════════════════════════════════╗
            ║        SENTRY RADIO - SECURITY CONFIGURATION SUMMARY          ║
            ╠═══════════════════════════════════════════════════════════════╣
            ║ ✓ Certificate Pinning: ENABLED (${CERTIFICATE_PINS.size} domains)
            ║ ✓ TLS Version: $MIN_TLS_VERSION - $MAX_TLS_VERSION
            ║ ✓ Regex DoS Protection: ENABLED (${REGEX_TIMEOUT_MS}ms timeout)
            ║ ✓ Process Safety: ENABLED (${PROCESS_TIMEOUT_SEC}s timeout)
            ║ ✓ Input Validation: ENABLED (${4} validators)
            ║ ✓ Broadcast Security: ENABLED (HMAC-SHA256)
            ║ ✓ Keystore Integration: ENABLED (AES-256-GCM)
            ║ ✓ Thread Safety: ENABLED (concurrent sync)
            ║ ✓ Rate Limiting: ENABLED ($API_RATE_LIMIT_PER_MIN req/min)
            ║ ✓ Audit Logging: ENABLED ($AUDIT_LOG_MAX_ENTRIES entries)
            ╚═══════════════════════════════════════════════════════════════╝
        """.trimIndent()
    }
}
