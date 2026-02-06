package dev.fzer0x.imsicatcherdetector2.security

import android.util.Log
import okhttp3.CertificatePinner
import okhttp3.ConnectionSpec
import okhttp3.OkHttpClient
import okhttp3.TlsVersion
import java.security.cert.CertificateException
import java.util.concurrent.TimeUnit

object HttpClientSecurityManager {
    private val TAG = "HttpSecurityMgr"

    fun createSecureOkHttpClient(): OkHttpClient {
        return try {
            val certificatePinner = CertificatePinner.Builder()
                // BeaconDB - Public Key Pinning
                .add("beacondb.net", "sha256/C5+lpZ7tcVwsa4xQwfXHd/WpWHqPXYwMxRjLnMjvVqI=")

                // OpenCellID - Public Key Pinning
                .add("opencellid.org", "sha256/JSMzqOOrtyOT8Q4j/6YIuRR82Vfxw/xGWesFHNXU1Q4=")

                // UnwiredLabs - Public Key Pinning
                .add("us1.unwiredlabs.com", "sha256/0E+enlpd84+75Y9CmyODMK6exsDcWdqKLb/2vyppWmM=")
                .build()

            // Enforce TLS 1.2+ only
            val connectionSpec = ConnectionSpec.Builder(ConnectionSpec.RESTRICTED_TLS)
                .tlsVersions(TlsVersion.TLS_1_2, TlsVersion.TLS_1_3)
                .build()

            OkHttpClient.Builder()
                .connectTimeout(10, TimeUnit.SECONDS)
                .readTimeout(30, TimeUnit.SECONDS)
                .writeTimeout(30, TimeUnit.SECONDS)
                .callTimeout(60, TimeUnit.SECONDS)
                .certificatePinner(certificatePinner)
                .connectionSpecs(listOf(connectionSpec))
                .retryOnConnectionFailure(false) // Disable auto-retry
                .build()
        } catch (e: Exception) {
            Log.e(TAG, "Error creating secure OkHttpClient: ${e.message}")
            // Fallback to insecure client (should not happen)
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
                .retryOnConnectionFailure(false)
                .build()
        } catch (e: Exception) {
            Log.e(TAG, "Error creating OkHttpClient with timeout: ${e.message}")
            OkHttpClient.Builder().build()
        }
    }
}
