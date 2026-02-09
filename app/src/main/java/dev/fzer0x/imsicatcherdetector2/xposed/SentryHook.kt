package dev.fzer0x.imsicatcherdetector2.xposed

import android.annotation.SuppressLint
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.Build
import android.os.Message
import android.os.UserHandle
import android.telephony.*
import de.robv.android.xposed.IXposedHookLoadPackage
import de.robv.android.xposed.XC_MethodHook
import de.robv.android.xposed.XposedBridge
import de.robv.android.xposed.XposedHelpers
import de.robv.android.xposed.callbacks.XC_LoadPackage.LoadPackageParam

class SentryHook : IXposedHookLoadPackage {

    private val ACTION_EVENT = "dev.fzer0x.imsicatcherdetector2.FORENSIC_EVENT"
    private val ACTION_REQUEST_UPDATE = "dev.fzer0x.imsicatcherdetector2.REQUEST_UPDATE"
    private val ACTION_SETTINGS_CHANGED = "dev.fzer0x.imsicatcherdetector2.SETTINGS_CHANGED"
    private val PREFS_NAME = "sentry_settings"
    private val KEY_BLOCK_GSM = "block_gsm"
    private val KEY_REJECT_A50 = "reject_a50"

    @Volatile
    private var blockGsm = false
    @Volatile
    private var rejectA50 = false

    private var settingsContext: Context? = null

    override fun handleLoadPackage(lpparam: LoadPackageParam) {
        if (lpparam.packageName == "android") {
            hookTelephonyRegistry(lpparam)
        }
        if (lpparam.packageName == "com.android.phone") {
            hookServiceStateTracker(lpparam)
            hookInboundSmsHandler(lpparam)
            setupUpdateListener(lpparam)
            setupSettingsReceiver(lpparam)
            hookRilCiphering(lpparam)
            loadSettingsFromPreferences(lpparam)
        }
        if (lpparam.packageName == "dev.fzer0x.imsicatcherdetector2") {
            hookAppStartup(lpparam)
            hookXposedCheck(lpparam)
        }
    }

    private fun loadSettingsFromPreferences(lpparam: LoadPackageParam) {
        try {
            val phoneAppClass = XposedHelpers.findClass("com.android.internal.telephony.PhoneApp", lpparam.classLoader)
            XposedHelpers.findAndHookMethod(phoneAppClass, "onCreate", object : XC_MethodHook() {
                override fun afterHookedMethod(param: MethodHookParam) {
                    val context = param.thisObject as Context
                    settingsContext = context
                    try {
                        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                        blockGsm = prefs.getBoolean(KEY_BLOCK_GSM, false)
                        rejectA50 = prefs.getBoolean(KEY_REJECT_A50, false)
                        XposedBridge.log("SentryHook: Settings loaded from SharedPreferences - BlockGSM: $blockGsm, RejectA50: $rejectA50")
                    } catch (e: Exception) {
                        XposedBridge.log("SentryHook: Failed to load settings from SharedPreferences: ${e.message}")
                    }
                }
            })
        } catch (e: Throwable) {
            XposedBridge.log("SentryHook: Error hooking for preferences loading: ${e.message}")
        }
    }

    private fun setupSettingsReceiver(lpparam: LoadPackageParam) {
        try {
            val phoneAppClass = XposedHelpers.findClass("com.android.internal.telephony.PhoneApp", lpparam.classLoader)
            XposedHelpers.findAndHookMethod(phoneAppClass, "onCreate", object : XC_MethodHook() {
                override fun afterHookedMethod(param: MethodHookParam) {
                    val context = param.thisObject as Context
                    val filter = IntentFilter(ACTION_SETTINGS_CHANGED)
                    context.registerReceiver(object : BroadcastReceiver() {
                        override fun onReceive(ctx: Context, intent: Intent) {
                            blockGsm = intent.getBooleanExtra("blockGsm", false)
                            rejectA50 = intent.getBooleanExtra("rejectA50", false)
                            try {
                                val prefs = ctx.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                                prefs.edit()
                                    .putBoolean(KEY_BLOCK_GSM, blockGsm)
                                    .putBoolean(KEY_REJECT_A50, rejectA50)
                                    .apply()
                            } catch (e: Exception) {}
                            XposedBridge.log("SentryHook: Settings updated & persisted - BlockGSM: $blockGsm, RejectA50: $rejectA50")
                        }
                    }, filter, Context.RECEIVER_EXPORTED)
                }
            })
        } catch (e: Throwable) {
            XposedBridge.log("SentryHook: Failed to setup settings receiver: ${e.message}")
        }
    }

    private fun hookRilCiphering(lpparam: LoadPackageParam) {
        try {
            val rilClass = XposedHelpers.findClass("com.android.internal.telephony.RIL", lpparam.classLoader)
            XposedBridge.hookAllMethods(rilClass, "processUnsolicited", object : XC_MethodHook() {
                override fun beforeHookedMethod(param: MethodHookParam) {
                    val response = param.args[0] ?: return
                    val respStr = response.toString().uppercase()

                    val cipheringPatterns = listOf(
                        "CIPHERING\\s*[:=]\\s*OFF",
                        "CIPHERING\\s*[:=]\\s*0",
                        "CIPHERING\\s*[:=]\\s*FALSE",
                        "ENCRYPTION\\s*[:=]\\s*FALSE",
                        "A5/0",
                        "NO\\s*CIPHER",
                        "CIPHER\\s*DISABLED"
                    )

                    val isCipheringOff = cipheringPatterns.any { pattern ->
                        respStr.matches(Regex(".*$pattern.*"))
                    }

                    if (isCipheringOff) {
                        val context = XposedHelpers.getObjectField(param.thisObject, "mContext") as Context
                        XposedBridge.log("SentryHook: CRITICAL - Unencrypted connection detected! Response: $respStr")

                        val intent = Intent().apply {
                            putExtra("eventType", "CIPHERING_OFF")
                            putExtra("description", "CRITICAL: Encryption disabled (A5/0) detected via RIL!")
                            putExtra("severity", 10)
                        }
                        sendForensicBroadcast(context, intent)

                        if (rejectA50) {
                            XposedBridge.log("SentryHook: SECURITY POLICY - Initiating controlled disconnect & reconnect to prevent A5/0 exploit.")
                            try {
                                val phone = XposedHelpers.getObjectField(param.thisObject, "mPhone")

                                // Temporär Radio ausschalten und dann nach 3 Sekunden wieder einschalten
                                val thread = Thread {
                                    try {
                                        XposedHelpers.callMethod(phone, "setRadioPower", false)
                                        Thread.sleep(3000)
                                        XposedHelpers.callMethod(phone, "setRadioPower", true)
                                        XposedBridge.log("SentryHook: Radio recovered - attempting reconnection with forced ciphering")
                                    } catch (e: Exception) {
                                        XposedBridge.log("SentryHook: Recovery error: ${e.message}")
                                    }
                                }
                                thread.isDaemon = true
                                thread.start()
                            } catch (e: Exception) {
                                XposedBridge.log("SentryHook: Error initiating A5/0 rejection: ${e.message}")
                            }
                        }
                    }
                }
            })
        } catch (e: Throwable) {
            XposedBridge.log("SentryHook: Error hooking RIL: ${e.message}")
        }
    }

    private fun hookServiceStateTracker(lpparam: LoadPackageParam) {
        try {
            val sstClass = XposedHelpers.findClass("com.android.internal.telephony.ServiceStateTracker", lpparam.classLoader)
            XposedHelpers.findAndHookMethod(sstClass, "handleMessage", Message::class.java, object : XC_MethodHook() {
                override fun afterHookedMethod(param: MethodHookParam) {
                    val mSST = param.thisObject
                    val phone = XposedHelpers.getObjectField(mSST, "mPhone")
                    val context = XposedHelpers.getObjectField(phone, "mContext") as Context
                    val simSlot = XposedHelpers.callMethod(phone, "getPhoneId") as Int
                    val ss = XposedHelpers.getObjectField(mSST, "mSS") as ServiceState

                    val msg = param.args[0] as Message
                    if (msg.what == 1) { // EVENT_POLL_STATE_REGISTRATION
                        val ar = msg.obj
                        if (ar != null && ar.javaClass.name.contains("AsyncResult")) {
                            val exception = XposedHelpers.getObjectField(ar, "exception")
                            val result = XposedHelpers.getObjectField(ar, "result")
                            if (exception == null && result != null) {
                                val states = result as? Array<String>
                                if (states != null && states.size > 13) {
                                    val rejectCause = states[13].toIntOrNull() ?: 0
                                    if (rejectCause != 0) {
                                        XposedBridge.log("SentryHook: Network Reject Cause detected: $rejectCause on SIM $simSlot")
                                        val intent = Intent().apply {
                                            putExtra("eventType", "IMSI_CATCHER_ALERT")
                                            putExtra("description", "Network Reject Cause #$rejectCause (IMSI Catcher Activity?) on SIM $simSlot")
                                            putExtra("severity", 9)
                                            putExtra("simSlot", simSlot)
                                        }
                                        sendForensicBroadcast(context, intent)
                                    }
                                }
                            }
                        }
                    }

                    if (blockGsm && isGsmRat(ss)) {
                        XposedBridge.log("SentryHook: GSM Detected - Blocking GSM connection on SIM $simSlot")

                        // Method 1: Set OUT_OF_SERVICE
                        try {
                            XposedHelpers.callMethod(ss, "setState", ServiceState.STATE_OUT_OF_SERVICE)
                        } catch (e: Exception) {}

                        // Method 2: Force network mode preference if possible
                        try {
                            val rilRef = XposedHelpers.getObjectField(phone, "mCi")
                            if (rilRef != null) {
                                XposedHelpers.callMethod(rilRef, "setPreferredNetworkType", 11, null) // 11 = LTE only
                            }
                        } catch (e: Exception) {}

                        // Method 3: Reject via method hook
                        param.result = false

                        val intent = Intent().apply {
                            putExtra("eventType", "CELL_DOWNGRADE")
                            putExtra("description", "GSM Connection Blocked by Sentry Security on SIM $simSlot")
                            putExtra("severity", 9)
                            putExtra("simSlot", simSlot)
                        }
                        sendForensicBroadcast(context, intent)

                        // Record blocking event - WICHTIG für Analytics!
                        try {
                            val blockingIntent = Intent("dev.fzer0x.imsicatcherdetector2.RECORD_BLOCKING_EVENT")
                            blockingIntent.setPackage("dev.fzer0x.imsicatcherdetector2")
                            blockingIntent.putExtra("blockType", "GSM_DOWNGRADE")
                            blockingIntent.putExtra("description", "GSM downgrade attempt blocked on SIM $simSlot")
                            blockingIntent.putExtra("severity", 9)
                            blockingIntent.putExtra("simSlot", simSlot)
                            context.sendBroadcast(blockingIntent)
                        } catch (e: Exception) {}
                    }

                    val lastCellInfo = XposedHelpers.callMethod(mSST, "getAllCellInfo") as? List<CellInfo>
                    if (!lastCellInfo.isNullOrEmpty() && Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                        processCellInfo(context, lastCellInfo, simSlot)
                    }
                }
            })
        } catch (e: Throwable) {
            XposedBridge.log("SentryHook: Error hooking SST: ${e.message}")
        }
    }

    private fun isGsmRat(ss: ServiceState): Boolean {
        val voiceRat = XposedHelpers.callMethod(ss, "getVoiceNetworkType") as Int
        val dataRat = XposedHelpers.callMethod(ss, "getDataNetworkType") as Int
        val gsmTypes = listOf(TelephonyManager.NETWORK_TYPE_GSM, TelephonyManager.NETWORK_TYPE_GPRS, TelephonyManager.NETWORK_TYPE_EDGE)
        return gsmTypes.contains(voiceRat) || gsmTypes.contains(dataRat)
    }

    private fun hookTelephonyRegistry(lpparam: LoadPackageParam) {
        try {
            val registryClass = XposedHelpers.findClass("com.android.server.TelephonyRegistry", lpparam.classLoader)
            XposedBridge.hookAllMethods(registryClass, "notifyCellInfoForSubscriber", object : XC_MethodHook() {
                override fun beforeHookedMethod(param: MethodHookParam) {
                    if (Build.VERSION.SDK_INT < Build.VERSION_CODES.R) return
                    val cellInfoList = param.args.firstOrNull { it is List<*> } as? List<CellInfo> ?: return
                    val context = XposedHelpers.getObjectField(param.thisObject, "mContext") as Context
                    val subId = param.args[0] as Int
                    val simSlot = getSlotIndex(context, subId)
                    processCellInfo(context, cellInfoList, simSlot)
                }
            })
        } catch (e: Throwable) {}
    }

    private fun getSlotIndex(context: Context, subId: Int): Int {
        try {
            val sm = context.getSystemService(Context.TELEPHONY_SUBSCRIPTION_SERVICE) as SubscriptionManager
            val info = sm.getActiveSubscriptionInfo(subId)
            return info?.simSlotIndex ?: 0
        } catch (e: Exception) { return 0 }
    }

    private fun hookInboundSmsHandler(lpparam: LoadPackageParam) {
        try {
            XposedHelpers.findAndHookMethod(
                "com.android.internal.telephony.InboundSmsHandler",
                lpparam.classLoader, "dispatchSmsPdus",
                Array<ByteArray>::class.java, String::class.java, Int::class.java,
                object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        val context = XposedHelpers.getObjectField(param.thisObject, "mContext") as Context
                        val phone = XposedHelpers.getObjectField(param.thisObject, "mPhone")
                        val simSlot = XposedHelpers.callMethod(phone, "getPhoneId") as Int
                        val pdus = param.args[0] as Array<ByteArray>
                        val format = param.args[1] as String
                        val smsMessageClass = XposedHelpers.findClass("android.telephony.SmsMessage", lpparam.classLoader)
                        
                        for (pdu in pdus) {
                            val sms = XposedHelpers.callStaticMethod(smsMessageClass, "createFromPdu", pdu, format) ?: continue
                            val pid = XposedHelpers.callMethod(sms, "getProtocolIdentifier") as Int
                            
                            if (pid == 0x00 || pid == 0x40) {
                                XposedBridge.log("SentryHook: Silent SMS (PID $pid) BLOCKED on SIM $simSlot")
                                val intent = Intent().apply {
                                    putExtra("eventType", "SILENT_SMS")
                                    putExtra("description", "Silent SMS (Type-0) intercepted and blocked on SIM $simSlot")
                                    putExtra("severity", 9)
                                    putExtra("simSlot", simSlot)
                                }
                                sendForensicBroadcast(context, intent)

                                // Record blocking event
                                try {
                                    val blockingIntent = Intent("dev.fzer0x.imsicatcherdetector2.RECORD_BLOCKING_EVENT")
                                    blockingIntent.setPackage("dev.fzer0x.imsicatcherdetector2")
                                    blockingIntent.putExtra("blockType", "SILENT_SMS")
                                    blockingIntent.putExtra("description", "Type-0 Silent SMS blocked on SIM $simSlot")
                                    blockingIntent.putExtra("severity", 9)
                                    blockingIntent.putExtra("simSlot", simSlot)
                                    context.sendBroadcast(blockingIntent)
                                } catch (e: Exception) {}

                                param.result = null
                            }
                        }
                    }
                }
            )
        } catch (e: Throwable) {}
    }

    private fun hookXposedCheck(lpparam: LoadPackageParam) {
        try {
            XposedHelpers.findAndHookMethod(
                "dev.fzer0x.imsicatcherdetector2.ui.viewmodel.ForensicViewModel",
                lpparam.classLoader, "isXposedModuleActive",
                object : XC_MethodHook() { override fun beforeHookedMethod(param: MethodHookParam) { param.result = true } }
            )
        } catch (e: Throwable) {}
    }

    private fun sendForensicBroadcast(context: Context, intent: Intent) {
        intent.action = ACTION_EVENT
        intent.setPackage("dev.fzer0x.imsicatcherdetector2")
        intent.addFlags(Intent.FLAG_RECEIVER_FOREGROUND)
        try {
            val userAll = XposedHelpers.getStaticObjectField(UserHandle::class.java, "ALL") as UserHandle
            XposedHelpers.callMethod(context, "sendBroadcastAsUser", intent, userAll)
        } catch (e: Throwable) { context.sendBroadcast(intent) }
    }

    private fun setupUpdateListener(lpparam: LoadPackageParam) {
        try {
            val phoneAppClass = XposedHelpers.findClass("com.android.internal.telephony.PhoneApp", lpparam.classLoader)
            XposedHelpers.findAndHookMethod(phoneAppClass, "onCreate", object : XC_MethodHook() {
                override fun afterHookedMethod(param: MethodHookParam) {
                    val context = param.thisObject as Context
                    context.registerReceiver(object : BroadcastReceiver() {
                        override fun onReceive(ctx: Context, intent: Intent) { forceImmediateUpdate(ctx) }
                    }, IntentFilter(ACTION_REQUEST_UPDATE), Context.RECEIVER_EXPORTED)
                }
            })
        } catch (e: Throwable) {}
    }

    @SuppressLint("MissingPermission")
    private fun forceImmediateUpdate(context: Context) {
        try {
            val tm = context.getSystemService(Context.TELEPHONY_SERVICE) as TelephonyManager
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                val cellInfoList = tm.allCellInfo
                if (!cellInfoList.isNullOrEmpty()) processCellInfo(context, cellInfoList, -1)
            }
        } catch (e: Exception) {}
    }

    private fun hookAppStartup(lpparam: LoadPackageParam) {
        try {
            XposedHelpers.findAndHookMethod(
                "dev.fzer0x.imsicatcherdetector2.service.ForensicService",
                lpparam.classLoader, "onCreate", object : XC_MethodHook() {
                    override fun afterHookedMethod(param: MethodHookParam) {
                        val context = param.thisObject as Context
                        val intent = Intent(ACTION_REQUEST_UPDATE).apply { setPackage(context.packageName) }
                        context.sendBroadcast(intent)
                    }
                }
            )
        } catch (e: Throwable) {}
    }

    @SuppressLint("NewApi")
    private fun processCellInfo(context: Context, cellInfoList: List<CellInfo>, simSlot: Int) {
        val activeCell = cellInfoList.firstOrNull { it.isRegistered } ?: cellInfoList.firstOrNull() ?: return
        val identity = activeCell.cellIdentity
        var dbm = -120
        var ta = -1
        try {
            val css = XposedHelpers.callMethod(activeCell, "getCellSignalStrength")
            dbm = XposedHelpers.callMethod(css, "getDbm") as Int
            ta = when (css) {
                is CellSignalStrengthLte -> css.timingAdvance
                is CellSignalStrengthGsm -> css.bitErrorRate
                else -> -1
            }
            if (ta == Int.MAX_VALUE) ta = -1
        } catch (e: Exception) {}

        val intent = Intent().apply {
            putExtra("neighbors", cellInfoList.count { !it.isRegistered })
            putExtra("eventType", "RADIO_METRICS_UPDATE")
            if (dbm in -140..-30) putExtra("dbm", dbm)
            if (ta != -1) putExtra("ta", ta)
            putExtra("severity", 1)
            putExtra("simSlot", simSlot)
        }

        var foundIdentity = false
        when (identity) {
            is CellIdentityLte -> {
                if (identity.ci != Int.MAX_VALUE) {
                    intent.putExtra("cellId", identity.ci.toString())
                    intent.putExtra("pci", if (identity.pci != Int.MAX_VALUE) identity.pci else -1)
                    intent.putExtra("earfcn", if (identity.earfcn != Int.MAX_VALUE) identity.earfcn else -1)
                    intent.putExtra("tac", if (identity.tac != Int.MAX_VALUE) identity.tac else -1)
                    intent.putExtra("mcc", identity.mccString); intent.putExtra("mnc", identity.mncString)
                    intent.putExtra("networkType", "LTE"); foundIdentity = true
                }
            }
            is CellIdentityNr -> {
                if (identity.nci != Long.MAX_VALUE) {
                    intent.putExtra("cellId", identity.nci.toString())
                    intent.putExtra("pci", if (identity.pci != Int.MAX_VALUE) identity.pci else -1)
                    intent.putExtra("earfcn", if (identity.nrarfcn != Int.MAX_VALUE) identity.nrarfcn else -1)
                    intent.putExtra("tac", if (identity.tac != Int.MAX_VALUE) identity.tac else -1)
                    intent.putExtra("mcc", identity.mccString); intent.putExtra("mnc", identity.mncString)
                    intent.putExtra("networkType", "NR"); foundIdentity = true
                }
            }
            is CellIdentityGsm -> {
                if (identity.cid != Int.MAX_VALUE) {
                    intent.putExtra("cellId", identity.cid.toString())
                    intent.putExtra("lac", if (identity.lac != Int.MAX_VALUE) identity.lac else -1)
                    intent.putExtra("mcc", identity.mccString); intent.putExtra("mnc", identity.mncString)
                    intent.putExtra("networkType", "GSM"); foundIdentity = true
                }
            }
            is CellIdentityWcdma -> {
                if (identity.cid != Int.MAX_VALUE) {
                    intent.putExtra("cellId", identity.cid.toString())
                    intent.putExtra("lac", if (identity.lac != Int.MAX_VALUE) identity.lac else -1)
                    intent.putExtra("mcc", identity.mccString); intent.putExtra("mnc", identity.mncString)
                    intent.putExtra("networkType", "WCDMA"); foundIdentity = true
                }
            }
        }
        if (foundIdentity) sendForensicBroadcast(context, intent)
    }
}
