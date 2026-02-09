package dev.fzer0x.imsicatcherdetector2.security

import android.util.Log
import okhttp3.ConnectionSpec
import okhttp3.OkHttpClient
import okhttp3.TlsVersion
import java.util.concurrent.TimeUnit

object HttpClientSecurityManager {
    private val TAG = "HttpSecurityMgr"

    /**
     * Creates a secure OkHttpClient with enforced TLS 1.2+.
     * Note: Certificate Pinning has been removed to avoid connection failures due to 
     * server-side certificate rotations.
     */
    fun createSecureOkHttpClient(): OkHttpClient {
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
                // Use system trust store instead of hardcoded pins
                .connectionSpecs(listOf(connectionSpec))
                .retryOnConnectionFailure(true) 
                .build()
        } catch (e: Exception) {
            Log.e(TAG, "Error creating secure OkHttpClient: ${e.message}")
            OkHttpClient.Builder().build()
        }
    }

    fun createSecureOkHttpClientWithTimeout(
        connectTimeoutSec: Long = 10,
        readTimeoutSec: Long = 30,
        writeTimeoutSec: Long = 30
    ): OkHttpClient {
        return try {
            val connectionSpec = ConnectionSpec.Builder(ConnectionSpec.RESTRICTED_TLS)
                .tlsVersions(TlsVersion.TLS_1_2, TlsVersion.TLS_1_3)
                .build()

            OkHttpClient.Builder()
                .connectTimeout(connectTimeoutSec, TimeUnit.SECONDS)
                .readTimeout(readTimeoutSec, TimeUnit.SECONDS)
                .writeTimeout(writeTimeoutSec, TimeUnit.SECONDS)
                .callTimeout(connectTimeoutSec + readTimeoutSec, TimeUnit.SECONDS)
                .connectionSpecs(listOf(connectionSpec))
                .retryOnConnectionFailure(true)
                .build()
        } catch (e: Exception) {
            Log.e(TAG, "Error creating OkHttpClient with timeout: ${e.message}")
            OkHttpClient.Builder().build()
        }
    }
}
