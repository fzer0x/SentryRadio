package dev.fzer0x.imsicatcherdetector2.security

object VersionComparator {
    /**
     * Vergleicht zwei Versionen im Format "versionCode-versionName" (z.B. 4-0.3.0)
     * Rückgabe: 1 wenn remote > local, -1 wenn local > remote, 0 wenn gleich
     */
    fun compare(local: String, remote: String): Int {
        try {
            val localParts = splitVersion(local)
            val remoteParts = splitVersion(remote)

            for (i in 0 until maxOf(localParts.size, remoteParts.size)) {
                val l = localParts.getOrElse(i) { 0 }
                val r = remoteParts.getOrElse(i) { 0 }
                if (r > l) return 1
                if (l > r) return -1
            }
        } catch (e: Exception) {
            return 0
        }
        return 0
    }

    private fun splitVersion(v: String): List<Int> {
        // Erwartetes Format: "versionCode-versionName" (z.B. "4-0.3.0")
        val mainParts = v.split("-")
        val versionCode = mainParts.getOrNull(0)?.toIntOrNull() ?: 0
        val versionName = if (mainParts.size > 1) mainParts[1] else ""
        
        // VersionName in Teile aufteilen (z.B. "0.3.0" -> [0, 3, 0])
        val versionNameParts = versionName.split(".").map { it.toIntOrNull() ?: 0 }
        
        return listOf(versionCode) + versionNameParts
    }
}
