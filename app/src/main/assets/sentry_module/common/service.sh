#!/system/bin/sh
# Sentry Radio Hardening - Boot Service
while [ "$(getprop sys.boot_completed)" != "1" ]; do
    sleep 5
done

# Enforce SELinux hardening on boot
/data/adb/modules/sentry_radio_hardening/system/bin/sentry-ctl --harden-sepolicy

setprop persist.vendor.radio.debug_level 0
setprop persist.sys.radio.debug 0
# Create symlink in /system/bin (if possible) or /data/adb/bin
ln -sf /data/adb/modules/sentry_radio_hardening/system/bin/sentry-ctl /system/bin/sentry-ctl 2>/dev/null || \
ln -sf /data/adb/modules/sentry_radio_hardening/system/bin/sentry-ctl /data/adb/bin/sentry-ctl 2>/dev/null || \
log -t SentryHardening "Could not create sentry-ctl symlink - use full path"

# Check for persistent panic state and restore if needed
PANIC_ACTIVE=$(getprop persist.sentry.panic_active)
PANIC_EXTENDED=$(getprop persist.sentry.panic_extended_active)

if [ "$PANIC_EXTENDED" = "1" ]; then
    log -t SentryHardening "Restoring extended panic mode after reboot"
    /data/adb/modules/sentry_radio_hardening/system/bin/sentry-ctl --panic-extended
elif [ "$PANIC_ACTIVE" = "1" ]; then
    log -t SentryHardening "Restoring panic mode after reboot"
    /data/adb/modules/sentry_radio_hardening/system/bin/sentry-ctl --panic
fi

log -t SentryHardening "Service started. System radio hardening enforced."
