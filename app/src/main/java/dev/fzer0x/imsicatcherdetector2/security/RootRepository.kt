package dev.fzer0x.imsicatcherdetector2.security

import android.util.Log
import com.topjohnwu.superuser.Shell
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Dedizierter Root-Repository für eine stabile Shell-Interaktion.
 * Nutzt libsu für persistente Shell-Sessions, was Akku und CPU spart.
 */
object RootRepository {
    private const val TAG = "RootRepository"

    init {
        // Globale Konfiguration für libsu
        Shell.setDefaultBuilder(Shell.Builder.create()
            .setFlags(Shell.FLAG_REDIRECT_STDERR)
            .setTimeout(10))
    }

    /**
     * Prüft, ob Root-Zugriff gewährt wurde.
     * Verbessert: Führt einen echten Test-Befehl aus.
     */
    suspend fun isRootAvailable(): Boolean = withContext(Dispatchers.IO) {
        try {
            // Manchmal liefert isRoot ein falsches Negativ, wenn die Shell noch nicht bereit ist.
            // Wir erzwingen eine Prüfung.
            Shell.getShell().isRoot || Shell.cmd("id").exec().isSuccess
        } catch (e: Exception) {
            Log.e(TAG, "Root check failed", e)
            false
        }
    }

    /**
     * Führt einen Befehl als Root aus und gibt das Ergebnis zurück.
     * Nutzt die globale Shell-Instanz von libsu (hält die Session offen).
     */
    suspend fun execute(command: String): ShellResult = withContext(Dispatchers.IO) {
        val result = Shell.cmd(command).exec()
        ShellResult(
            success = result.isSuccess,
            output = result.out.joinToString("\n"),
            error = result.err.joinToString("\n"),
            exitCode = result.code
        )
    }

    /**
     * Prüft die Existenz einer Datei oder eines Verzeichnisses als Root.
     */
    suspend fun fileExists(path: String): Boolean = withContext(Dispatchers.IO) {
        Shell.cmd("[ -f \"$path\" ] || [ -d \"$path\" ]").exec().isSuccess
    }

    data class ShellResult(
        val success: Boolean,
        val output: String,
        val error: String,
        val exitCode: Int
    )
}
