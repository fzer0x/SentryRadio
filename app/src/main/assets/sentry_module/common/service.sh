#!/system/bin/sh
# Sentry Radio Hardening - Boot Service
while [ "$(getprop sys.boot_completed)" != "1" ]; do
    sleep 5
done
setprop persist.vendor.radio.debug_level 0
setprop persist.sys.radio.debug 0
log -t SentryHardening "Service started. System radio hardening enforced."
