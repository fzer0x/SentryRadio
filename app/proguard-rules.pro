# Room forensic persistence
-keep class * extends androidx.room.RoomDatabase
-keep class dev.fzer0x.imsicatcherdetector2.data.** { *; }

# Xposed/LSPosed entry points
-keep class dev.fzer0x.imsicatcherdetector2.xposed.SentryHook { *; }
-keepnames class dev.fzer0x.imsicatcherdetector2.xposed.SentryHook

# Keep MainActivity for UI
-keep class dev.fzer0x.imsicatcherdetector2.MainActivity { *; }

# Keep Xposed API
-keep class de.robv.android.xposed.** { *; }
-dontwarn de.robv.android.xposed.**
