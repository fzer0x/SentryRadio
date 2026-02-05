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
import androidx.annotation.RequiresApi
import de.robv.android.xposed.IXposedHookLoadPackage
import de.robv.android.xposed.XC_MethodHook
import de.robv.android.xposed.XposedBridge
import de.robv.android.xposed.XposedHelpers
import de.robv.android.xposed.callbacks.XC_LoadPackage.LoadPackageParam

class SentryHook : IXposedHookLoadPackage {

    private val ACTION_EVENT = "dev.fzer0x.imsicatcherdetector2.FORENSIC_EVENT"
    private val ACTION_REQUEST_UPDATE = "dev.fzer0x.imsicatcherdetector2.REQUEST_UPDATE"

    override fun handleLoadPackage(lpparam: LoadPackageParam) {
        if (lpparam.packageName == "android") {
            hookTelephonyRegistry(lpparam)
        }
        if (lpparam.packageName == "com.android.phone") {
            hookServiceStateTracker(lpparam)
            hookInboundSmsHandler(lpparam)
            setupUpdateListener(lpparam)
        }
        if (lpparam.packageName == "dev.fzer0x.imsicatcherdetector2") {
            hookAppStartup(lpparam)
            hookXposedCheck(lpparam)
        }
    }

    private fun hookXposedCheck(lpparam: LoadPackageParam) {
        try {
            XposedHelpers.findAndHookMethod(
                "dev.fzer0x.imsicatcherdetector2.ui.viewmodel.ForensicViewModel",
                lpparam.classLoader,
                "isXposedModuleActive",
                object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        param.result = true
                    }
                }
            )
        } catch (e: Throwable) {
            XposedBridge.log("SentryHook: Failed to hook isXposedModuleActive: ${e.message}")
        }
    }

    private fun sendForensicBroadcast(context: Context, intent: Intent) {
        intent.action = ACTION_EVENT
        intent.setPackage("dev.fzer0x.imsicatcherdetector2")
        intent.addFlags(Intent.FLAG_RECEIVER_FOREGROUND)
        try {
            val userAll = XposedHelpers.getStaticObjectField(UserHandle::class.java, "ALL") as UserHandle
            XposedHelpers.callMethod(context, "sendBroadcastAsUser", intent, userAll)
        } catch (e: Throwable) {
            context.sendBroadcast(intent)
        }
    }

    private fun setupUpdateListener(lpparam: LoadPackageParam) {
        try {
            XposedHelpers.findAndHookMethod(
                "com.android.internal.telephony.PhoneApp", 
                lpparam.classLoader, "onCreate", object : XC_MethodHook() {
                override fun afterHookedMethod(param: MethodHookParam) {
                    val context = param.thisObject as Context
                    context.registerReceiver(object : BroadcastReceiver() {
                        override fun onReceive(ctx: Context, intent: Intent) {
                            forceImmediateUpdate(ctx)
                        }
                    }, IntentFilter(ACTION_REQUEST_UPDATE), Context.RECEIVER_NOT_EXPORTED)
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
                if (!cellInfoList.isNullOrEmpty()) {
                    processCellInfo(context, cellInfoList, -1)
                }
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
                        val intent = Intent(ACTION_REQUEST_UPDATE)
                        intent.setPackage(context.packageName)
                        context.sendBroadcast(intent)
                    }
                }
            )
        } catch (e: Throwable) {}
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
                    val lastCellInfo = XposedHelpers.callMethod(mSST, "getAllCellInfo") as? List<CellInfo>
                    if (!lastCellInfo.isNullOrEmpty() && Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                        processCellInfo(context, lastCellInfo, simSlot)
                    }
                }
            })
        } catch (e: Throwable) {}
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
                            if (pid == 0x40) {
                                val intent = Intent().apply {
                                    putExtra("eventType", "SILENT_SMS")
                                    putExtra("description", "Type-0 SMS intercepted on SIM $simSlot")
                                    putExtra("severity", 9)
                                    putExtra("simSlot", simSlot)
                                }
                                sendForensicBroadcast(context, intent)
                            }
                        }
                    }
                }
            )
        } catch (e: Throwable) {}
    }

    @RequiresApi(Build.VERSION_CODES.R)
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
                    intent.putExtra("mcc", identity.mccString)
                    intent.putExtra("mnc", identity.mncString)
                    intent.putExtra("networkType", "LTE")
                    foundIdentity = true
                }
            }
            is CellIdentityNr -> {
                if (identity.nci != Long.MAX_VALUE) {
                    intent.putExtra("cellId", identity.nci.toString())
                    intent.putExtra("pci", if (identity.pci != Int.MAX_VALUE) identity.pci else -1)
                    intent.putExtra("earfcn", if (identity.nrarfcn != Int.MAX_VALUE) identity.nrarfcn else -1)
                    intent.putExtra("tac", if (identity.tac != Int.MAX_VALUE) identity.tac else -1)
                    intent.putExtra("mcc", identity.mccString)
                    intent.putExtra("mnc", identity.mncString)
                    intent.putExtra("networkType", "NR")
                    foundIdentity = true
                }
            }
            is CellIdentityGsm -> {
                if (identity.cid != Int.MAX_VALUE) {
                    intent.putExtra("cellId", identity.cid.toString())
                    intent.putExtra("lac", if (identity.lac != Int.MAX_VALUE) identity.lac else -1)
                    intent.putExtra("mcc", identity.mccString)
                    intent.putExtra("mnc", identity.mncString)
                    intent.putExtra("networkType", "GSM")
                    foundIdentity = true
                }
            }
            is CellIdentityWcdma -> {
                if (identity.cid != Int.MAX_VALUE) {
                    intent.putExtra("cellId", identity.cid.toString())
                    intent.putExtra("lac", if (identity.lac != Int.MAX_VALUE) identity.lac else -1)
                    intent.putExtra("mcc", identity.mccString)
                    intent.putExtra("mnc", identity.mncString)
                    intent.putExtra("networkType", "WCDMA")
                    foundIdentity = true
                }
            }
        }
        
        if (foundIdentity) {
            sendForensicBroadcast(context, intent)
        }
    }
}
