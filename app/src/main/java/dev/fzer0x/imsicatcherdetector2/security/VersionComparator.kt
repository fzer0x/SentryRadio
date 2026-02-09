package dev.fzer0x.imsicatcherdetector2.security

object VersionComparator {
    /**
     * Vergleicht zwei Versionen im Format "MAJOR-MINOR.PATCH" (z.B. 3-0.2.1)
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
        // Bereinigt Suffixe wie -beta oder -alpha für den Vergleich
        val cleanV = v.split("-").firstOrNull { it.any { c -> c.isDigit() } } ?: v
        val mainParts = v.split("-")
        val major = mainParts.getOrNull(0)?.toIntOrNull() ?: 0
        val rest = if (mainParts.size > 1) mainParts[1].split(".") else emptyList()
        val restInts = rest.map { it.toIntOrNull() ?: 0 }
        return listOf(major) + restInts
    }
}
