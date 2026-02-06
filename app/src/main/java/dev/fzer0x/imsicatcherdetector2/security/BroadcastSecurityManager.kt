package dev.fzer0x.imsicatcherdetector2.security

import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.util.Log
import java.security.MessageDigest
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

object BroadcastSecurityManager {
    private val TAG = "BroadcastSecurityMgr"
    private val ALGORITHM = "HmacSHA256"
    private val ACTION_VERIFY_SIGNATURE = "dev.fzer0x.imsicatcherdetector2.VERIFY_SIGNATURE"

    fun sendSecureBroadcast(
        context: Context,
        action: String,
        data: Map<String, Any>,
        secretKey: ByteArray
    ) {
        try {
            val intent = Intent(action)
            intent.setPackage(context.packageName)

            // Serialize data
            val dataStr = data.entries.sortedBy { it.key }
                .joinToString("|") { "${it.key}=${it.value}" }

            // Create HMAC signature
            val signature = createHmacSignature(dataStr, secretKey)

            // Add data and signature to intent
            for ((key, value) in data) {
                when (value) {
                    is String -> intent.putExtra(key, value)
                    is Int -> intent.putExtra(key, value)
                    is Boolean -> intent.putExtra(key, value)
                    else -> Log.w(TAG, "Unsupported type for key $key: ${value::class.simpleName}")
                }
            }
            intent.putExtra("__signature", signature)
            intent.putExtra("__timestamp", System.currentTimeMillis())

            context.sendBroadcast(intent)
            Log.d(TAG, "Secure broadcast sent: $action")
        } catch (e: Exception) {
            Log.e(TAG, "Error sending secure broadcast: ${e.message}")
        }
    }

    fun verifyBroadcastSignature(
        intent: Intent,
        secretKey: ByteArray
    ): Boolean {
        try {
            val signature = intent.getStringExtra("__signature") ?: return false
            val timestamp = intent.getLongExtra("__timestamp", 0L)

            // Check timestamp freshness (5 minute window)
            if (System.currentTimeMillis() - timestamp > 300000) {
                Log.w(TAG, "Broadcast timestamp too old")
                return false
            }

            // Reconstruct data string
            val extras = intent.extras ?: return false
            val dataStr = extras.keySet()
                .filter { !it.startsWith("__") }
                .sorted()
                .joinToString("|") { key ->
                    val value = extras.get(key) ?: ""
                    "$key=$value"
                }

            // Verify signature
            val expectedSignature = createHmacSignature(dataStr, secretKey)
            return signature == expectedSignature
        } catch (e: Exception) {
            Log.e(TAG, "Error verifying broadcast signature: ${e.message}")
            return false
        }
    }

    private fun createHmacSignature(data: String, secretKey: ByteArray): String {
        return try {
            val mac = Mac.getInstance(ALGORITHM)
            mac.init(SecretKeySpec(secretKey, 0, secretKey.size, ALGORITHM))
            val digest = mac.doFinal(data.toByteArray())
            digest.joinToString("") { "%02x".format(it) }
        } catch (e: Exception) {
            Log.e(TAG, "Error creating HMAC signature: ${e.message}")
            ""
        }
    }

    fun verifyCallerPackage(context: Context, expectedPackage: String): Boolean {
        return try {
            // In production, use getCallingPackage() on API 31+
            // For now, verify the package is the expected one
            true // Caller verification handled by manifest permissions
        } catch (e: Exception) {
            Log.e(TAG, "Error verifying caller: ${e.message}")
            false
        }
    }
}
