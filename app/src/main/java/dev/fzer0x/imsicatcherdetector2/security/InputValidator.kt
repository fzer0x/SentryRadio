package dev.fzer0x.imsicatcherdetector2.security

import android.util.Log
import java.util.regex.Pattern

object InputValidator {
    private val TAG = "InputValidator"

    // Compile patterns once (prevent ReDoS)
    private val MCC_PATTERN = Pattern.compile("^[1-9]\\d{2}$")
    private val MNC_PATTERN = Pattern.compile("^\\d{2,3}$")
    private val CELL_ID_PATTERN = Pattern.compile("^[0-9a-fA-F]{1,19}$")
    private val COORDINATE_PATTERN = Pattern.compile("^-?\\d{1,3}(?:\\.\\d{1,8})?$")

    fun validateMCC(mcc: String?): Boolean {
        if (mcc == null || mcc.isEmpty()) return true // Allow empty/null for periodic updates
        return try {
            val num = mcc.toInt()
            num in 100..999 && MCC_PATTERN.matcher(mcc).matches()
        } catch (e: NumberFormatException) {
            Log.w(TAG, "Invalid MCC format: $mcc")
            false
        }
    }

    fun validateMNC(mnc: String?): Boolean {
        if (mnc == null || mnc.isEmpty()) return true // Allow empty/null for periodic updates
        return try {
            val num = mnc.toInt()
            num in 0..999 && MNC_PATTERN.matcher(mnc).matches()
        } catch (e: NumberFormatException) {
            Log.w(TAG, "Invalid MNC format: $mnc")
            false
        }
    }

    fun validateCellId(cellId: String?): Boolean {
        if (cellId == null || cellId.isEmpty()) return true
        return cellId.length <= 19 && CELL_ID_PATTERN.matcher(cellId).matches()
    }

    fun validateLAC(lac: Int?): Boolean {
        if (lac == null || lac == -1) return true
        return lac in 0..65535
    }

    fun validateTAC(tac: Int?): Boolean {
        if (tac == null || tac == -1) return true
        return tac in 0..16777215
    }

    fun validatePCI(pci: Int?): Boolean {
        if (pci == null || pci == -1) return true
        return pci in 0..1023 // NR PCIs can go up to 1007
    }

    fun validateDBM(dbm: Int?): Boolean {
        if (dbm == null || dbm == -120) return true
        return dbm in -150..-30
    }

    fun validateCoordinate(lat: Double?, lon: Double?): Boolean {
        if (lat == null || lon == null) return false
        if (lat.isNaN() || lon.isNaN() || lat.isInfinite() || lon.isInfinite()) return false
        return lat in -90.0..90.0 && lon in -180.0..180.0
    }

    fun validateSeverity(severity: Int?): Boolean {
        if (severity == null) return false
        return severity in 1..10
    }

    fun validateSimSlot(simSlot: Int?): Boolean {
        if (simSlot == null) return false
        return simSlot in 0..1
    }

    fun validateDescription(description: String?): Boolean {
        if (description == null) return true // Allow null, will be defaulted to empty string
        // Max 2000 chars, no control characters except newline
        return description.length <= 2000 &&
               !description.any { it.code in 0..8 || it.code in 14..31 }
    }
}
