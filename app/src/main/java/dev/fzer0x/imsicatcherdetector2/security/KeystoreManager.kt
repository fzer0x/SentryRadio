package dev.fzer0x.imsicatcherdetector2.security

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import android.util.Log
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

object KeystoreManager {
    private val TAG = "KeystoreManager"
    private val KEYSTORE_ALIAS = "sentry_radio_api_key"
    private val ANDROID_KEYSTORE = "AndroidKeyStore"
    private val CIPHER_ALGORITHM = "AES/GCM/NoPadding"
    private val KEY_ALGORITHM = "AES"
    private val GCM_TAG_LENGTH = 128

    fun initializeKeystore(): Boolean {
        return try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
                keyStore.load(null)

                if (!keyStore.containsAlias(KEYSTORE_ALIAS)) {
                    generateKey()
                }
                true
            } else {
                Log.w(TAG, "Keystore requires Android 6.0+")
                false
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error initializing keystore: ${e.message}")
            false
        }
    }

    fun encryptApiKey(apiKey: String): String? {
        return try {
            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) {
                Log.w(TAG, "Encryption requires Android 6.0+")
                return null
            }

            val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
            keyStore.load(null)
            val key = keyStore.getKey(KEYSTORE_ALIAS, null) as? SecretKey ?: return null

            val cipher = Cipher.getInstance(CIPHER_ALGORITHM)
            cipher.init(Cipher.ENCRYPT_MODE, key)

            val encryptedData = cipher.doFinal(apiKey.toByteArray())
            val iv = cipher.iv

            // Combine IV + encrypted data
            val combined = iv + encryptedData
            Base64.encodeToString(combined, Base64.DEFAULT)
        } catch (e: Exception) {
            Log.e(TAG, "Error encrypting API key: ${e.message}")
            null
        }
    }

    fun decryptApiKey(encryptedApiKey: String): String? {
        return try {
            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) {
                Log.w(TAG, "Decryption requires Android 6.0+")
                return null
            }

            val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
            keyStore.load(null)
            val key = keyStore.getKey(KEYSTORE_ALIAS, null) as? SecretKey ?: return null

            val combined = Base64.decode(encryptedApiKey, Base64.DEFAULT)
            val iv = combined.sliceArray(0..11) // First 12 bytes are IV
            val encryptedData = combined.sliceArray(12 until combined.size)

            val cipher = Cipher.getInstance(CIPHER_ALGORITHM)
            val spec = GCMParameterSpec(GCM_TAG_LENGTH, iv)
            cipher.init(Cipher.DECRYPT_MODE, key, spec)

            val decryptedData = cipher.doFinal(encryptedData)
            String(decryptedData)
        } catch (e: Exception) {
            Log.e(TAG, "Error decrypting API key: ${e.message}")
            null
        }
    }

    private fun generateKey() {
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                val keyGen = KeyGenerator.getInstance(KEY_ALGORITHM, ANDROID_KEYSTORE)

                val keyGenSpec = KeyGenParameterSpec.Builder(
                    KEYSTORE_ALIAS,
                    KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
                )
                    .setKeySize(256)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setRandomizedEncryptionRequired(true)
                    .build()

                keyGen.init(keyGenSpec)
                keyGen.generateKey()
                Log.d(TAG, "Keystore key generated successfully")
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error generating keystore key: ${e.message}")
        }
    }
}
