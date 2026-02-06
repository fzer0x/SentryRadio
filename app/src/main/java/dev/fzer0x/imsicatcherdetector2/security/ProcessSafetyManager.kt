package dev.fzer0x.imsicatcherdetector2.security

import android.util.Log
import java.io.BufferedReader
import java.io.InputStream
import java.util.concurrent.TimeUnit

object ProcessSafetyManager {
    private val TAG = "ProcessSafety"
    private const val PROCESS_TIMEOUT_SEC = 5L

    data class ProcessResult(
        val success: Boolean,
        val output: String,
        val error: String? = null
    )

    fun executeCommandWithTimeout(
        command: Array<String>,
        timeoutSec: Long = PROCESS_TIMEOUT_SEC
    ): ProcessResult {
        return try {
            val process = Runtime.getRuntime().exec(command)

            // Create threads to read output and error streams
            val outputBuilder = StringBuilder()
            val errorBuilder = StringBuilder()

            val outputThread = Thread {
                try {
                    BufferedReader(process.inputStream.reader()).use { reader ->
                        reader.forEachLine { outputBuilder.append(it).append("\n") }
                    }
                } catch (e: Exception) {
                    Log.w(TAG, "Error reading process output: ${e.message}")
                }
            }

            val errorThread = Thread {
                try {
                    BufferedReader(process.errorStream.reader()).use { reader ->
                        reader.forEachLine { errorBuilder.append(it).append("\n") }
                    }
                } catch (e: Exception) {
                    Log.w(TAG, "Error reading process error: ${e.message}")
                }
            }

            outputThread.start()
            errorThread.start()

            // Wait for process with timeout
            val completed = process.waitFor(timeoutSec, TimeUnit.SECONDS)

            if (!completed) {
                process.destroyForcibly()
                outputThread.interrupt()
                errorThread.interrupt()
                Log.w(TAG, "Process timeout after ${timeoutSec}s for command: ${command.joinToString(" ")}")
                return ProcessResult(false, "", "Process timeout")
            }

            outputThread.join(1000)
            errorThread.join(1000)

            val exitCode = process.exitValue()
            if (exitCode != 0) {
                Log.w(TAG, "Process exited with code $exitCode")
                return ProcessResult(false, outputBuilder.toString(), errorBuilder.toString())
            }

            ProcessResult(true, outputBuilder.toString())
        } catch (e: Exception) {
            Log.e(TAG, "Error executing command: ${e.message}")
            ProcessResult(false, "", e.message)
        }
    }

    fun closeStreamSafely(stream: InputStream?) {
        try {
            stream?.close()
        } catch (e: Exception) {
            Log.w(TAG, "Error closing stream: ${e.message}")
        }
    }

    fun destroyProcessSafely(process: Process?) {
        try {
            process?.inputStream?.close()
            process?.outputStream?.close()
            process?.errorStream?.close()
            process?.destroyForcibly()
        } catch (e: Exception) {
            Log.w(TAG, "Error destroying process: ${e.message}")
        }
    }
}
