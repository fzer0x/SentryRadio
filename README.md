# Sentry Radio 📡

**Sentry Radio** is a professional-grade Android forensic tool designed to detect, analyze, and map cellular network anomalies, including potential IMSI Catchers (Stingrays), cell site simulators, and suspicious network downgrades.

Built for security researchers and privacy-conscious users, it provides deep insights into the radio stack, monitoring both SIM slots in real-time.

**Version 0.4.0 - Enhanced System Hardening with Advanced Panic Mode, Recovery Controls, and Improved Update Management.**

---
⚠️Before the new security features can be used, it is important to update the KSU/Magisk module in Settings!
---

## 🚀 Key Features

- **🛡️ Dynamic CVE Intelligence:** Fetches real-time modem vulnerabilities from the NIST NVD API, replacing the static, hardcoded list.
- **🛠️ System-Level Hardening (Magisk/KSU):** Optional module enforces secure radio parameters directly on the baseband level with automatic reboot detection.
- **⚡ Advanced Panic Mode:** Full system lockdown with network isolation and hardware radio disable for emergency situations.
- **🔄 Recovery Controls:** Automated recovery procedures and panic validation for post-incident analysis.
- **📱 App Update Management:** Automatic detection and notification of app updates via GitHub releases with integrated overlay dialog.
- **🔄 Reboot Management:** Intelligent reboot detection and overlay prompts after KSU/Magisk module installation or updates.
- **🛡️ Real-time Threat Detection:** Monitors for encryption deactivation, silent SMS, and suspicious cell handovers.
- **🚨 Full-screen Overlay Alarms:** Critical alerts now appear over all apps and on the lock screen for immediate notification.
- **📊 Advanced Radio Metrics:** Tracks PCI, EARFCN, Signal Strength (RSSI/RSRP), Timing Advance, and Neighboring cells.
- **🌐 Forensic Mapping:** Visualize detected cell towers and your movement on an offline-capable map using OSMDroid.
- **📡 Dual SIM Support:** Full monitoring for multi-slot devices.
- **🔍 Database Verification:** Cross-references cell data with OpenCellID, Unwired Labs, and BeaconDB to identify "fake" towers.
- **💾 PCAP Export:** Export radio events to GSMTAP-compatible PCAP files for further analysis in Wireshark.
- **🔐 Encrypted Credentials:** API keys and sensitive data now encrypted with AES-256-GCM in Android Keystore.
- **📍 Certificate Pinning:** All API connections protected against MITM attacks with public key pinning.

---

## 🛠️ Requirements

- **Android 10 (API 29) or higher.**
- **Root Access:** Required for deep radio logcat monitoring and installing the hardening module.
- **(Recommended) Magisk or KernelSU:** For installing the Sentry Radio Hardening module.
- **(Optional) Xposed/LSPosed:** For enhanced API hooking and stealth.
- **Permission:** "Display over other apps" (SYSTEM_ALERT_WINDOW) for full-screen alarm overlays.

---

## 📥 Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/fzer0x/SentryRadio.git
   ```
2. Open in **Android Studio** and build the project.
3. Install the APK on your rooted device.
4. Grant Root/Superuser permissions when prompted.
5. **Enable "Display over other apps"** in the app settings to allow full-screen alarms.
6. (Recommended) Go to the **'Settings'** tab and install the **Sentry Hardening Module** for system-level protection.

---

## ⚙️ Configuration

Add your API keys in the app settings (now encrypted in Keystore):
- [OpenCellID API Key](https://opencellid.org/)
- BeaconDB (API-Keyless)

---

## 🛡️ Security (v0.4.0)

Sentry Radio now includes enhanced security hardening with advanced emergency controls:

- **Dynamic CVE Scanning:** Live vulnerability checks against the NIST NVD database.
- **Advanced Panic Mode:** Full system lockdown with hardware radio disable and network isolation.
- **Recovery Controls:** Automated recovery procedures with panic validation and forensic analysis.
- **System-Level Hardening Module:** An optional Magisk/KSU module provides deep system integration to enforce radio security policies with intelligent reboot detection.
- **App Update Management:** Automatic detection of app updates via GitHub API with secure overlay notifications.
- **Reboot Management:** Intelligent detection of KSU/Magisk module installations with automatic reboot prompts and system state validation.
- **API Key Encryption:** AES-256-GCM encryption in Android Keystore
- **Certificate Pinning:** Public key pinning prevents MITM attacks on all APIs
- **Input Validation:** All data validated before processing
- **Full-screen Overlay Alarms:** Critical security alerts are displayed over other apps and on the lock screen.
- **Safe Root Execution:** Commands executed with timeout and resource limits
- **Audit Logging:** Security events logged for forensic analysis

---

## 📱 User Interface Tabs

Sentry Radio features a comprehensive tabbed interface:

### 1. **Status Tab** - Real-time Dashboard
- **System Integrity Scan** with CVE database sync status and device's Android Security Patch level.
- Live threat detection with color-coded severity levels.
- SIM slot switching (Dual SIM support).
- Real-time metrics: Signal strength, Timing Advance, Neighbor cell count.
- Threat gauge showing overall risk level.

### 2. **Map Tab** - Forensic Mapping
- **Improved User Experience:** Map state (zoom/center) is now saved. Automatically centers on your location on first use. Fixed empty pop-ups.
- Interactive offline map (OSMDroid) showing all detected cell towers.
- Cell tower markers with color-coded status.
- Auto-sync with API databases (BeaconDB, OpenCellID, UnwiredLabs).
- Tower details on click (coordinates, samples, range, etc.).

### 3. **Audit Tab** - Event Timeline & History
- Complete chronological log of all detected threats.
- Filter by SIM slot.
- Click events for detailed analysis.
- Color-coded event types (IMSI Catcher, Silent SMS, Downgrade, etc.).
- Includes raw logcat captures for forensic analysis.

### 4. **Security Tab** - Active Defense Controls
- **Block GSM Registrations** - Prevent 2G/GSM network downgrades.
- **Reject A5/0 Cipher** - Block unencrypted connections.
- **Advanced Panic Mode** - Full system lockdown with hardware radio disable.
- **Recovery Controls** - Automated recovery and panic validation procedures.
- **Threats Blocked Dashboard** - Real-time statistics of blocked attacks.
- **Blocking Events Log** - Full history of security actions taken.
- **Reboot Management** - Test and manage reboot dialogs for KSU/Magisk module installations.

### 5. **Analytics Tab** - Advanced Threat Analysis
- **Threat Summary** - Counts by type (signal, baseband, RRC, handover).
- **Handover Analysis** - Total handovers, anomalies, ping-pong events.
- **Network Capability Analysis** - Network degradation detection.
- **Signal Anomaly Detection** - Unrealistic signal jumps and interference.

### 6. **Settings Tab** - Configuration & Logging Control
- **Magisk/KSU Hardening Module:** Install or update the system-level security module.
- **Database Settings:** API keys for OpenCellID, Unwired Labs, BeaconDB.
- **Detection Sensitivity:** Slider to adjust threat detection threshold.
- **Logging Options & Alarm Control.**
- **App Update Notifications:** Automatic detection and overlay notifications for new releases.

---

## 🛡️ Security Analysis Layers

Sentry Radio analyzes several layers of the cellular protocol:
- **Physical Layer:** Unrealistic signal jumps or timing advance values.
- **Protocol Layer:** RRC state transitions and Location Update Rejects.
- **Security Layer:** Monitoring for Ciphering indicator (A5/0) and silent paging.
- **Baseband Layer:** Live fingerprinting against the NIST NVD database for known modem vulnerabilities (Qualcomm, MediaTek, Exynos) based on device chipset and patch level.

---

## 🤝 Contributing

Contributions are welcome! For major changes, please open an issue first.

---

## ⚖️ License

Distributed under the GNU GPL v3 License. See `LICENSE` for more information.

---

## 📝 Changelog

**v0.4.1**
- Improve blocking GSM/2G Downgrade Attack
- improve blocking A5/0 Cipher Attack

**v0.4.0**
- **Advanced Panic Mode & Recovery System:**
  - Implemented Extended Panic Mode with full system lockdown and hardware radio disable.
  - Added automated recovery procedures with panic validation for post-incident analysis.
  - Enhanced panic controls with hardware shutdown commands and validation feedback.
  - Persistent panic state management across device reboots with automatic restoration.
  - Multi-layer network isolation using Android APIs, iptables, and hardware-level controls.
- **Improved Hardening Module Integration:**
  - Updated Sentry Radio Hardening Module to v0.4.0 with enhanced system integration.
  - Improved command execution reliability with fallback path handling for all operations.
  - Added comprehensive recovery and validation commands with enhanced error handling.
  - Enhanced boot service with automatic panic state restoration and symlink management.
  - Improved hardware radio control with multiple reset methods and service management.
- **App Update Management System:**
  - Implemented automatic app update detection via GitHub API integration.
  - Added secure overlay notifications for new releases with version comparison.
  - Enhanced version parsing to support GitHub's "versionCode-versionName" format.
  - Integrated update manager with callback system for real-time update notifications.
  - Added automatic module version checking and update availability indicators.
- **Enhanced Security Controls:**
  - Improved root command execution with better error handling and fallback mechanisms.
  - Added comprehensive logging for panic and recovery operations with detailed status reporting.
  - Enhanced system integrity monitoring with detailed telemetry and validation procedures.
  - Implemented persistent configuration storage for panic states and security settings.
  - Added hardware-level radio controls with Qualcomm-specific interface support.
- **UI/UX Improvements:**
  - Updated Security Tab with new panic, recovery management controls.
  - Enhanced Settings Tab with app update notification preferences and module management.
  - Improved error messaging and user feedback throughout the application.
  - Added real-time validation feedback and status indicators for all security operations.
  - Streamlined button layout with improved accessibility and visual hierarchy.
- **Network & Connectivity Enhancements:**
  - Advanced network isolation with multiple fallback mechanisms for maximum compatibility.
  - Enhanced mobile data recovery with forced reconnection procedures and service restart.
  - Improved WiFi management with automated enable/disable sequences and state validation.
  - Added comprehensive network interface monitoring and control across all radio technologies.
- **System Resilience Features:**
  - Automatic service recovery and restart capabilities for telephony and radio services.
  - Enhanced error recovery with multiple fallback strategies for different device configurations.
  - Improved system state validation with comprehensive health checks and status reporting.
  - Added forensic data collection and analysis capabilities for incident investigation.

**v0.4.2-beta**
- **Enhanced CVE Detection & Chipset Compatibility:**
  - Added codename-to-technical-name mapping for Qualcomm chipsets (e.g., "LAHAINA" → "SM8350").
  - Expanded VulnerabilityMatcher with additional chipset aliases for better matching.
  - Enhanced NVD API rate limiting handling with intelligent delays.
  - Implemented consistent test CVE fallback system for reliable detection.
- **Improved Cache Management:**
  - Added detailed logging for cache refresh decisions and API operations.
  - Fixed cache clearing issues that caused inconsistent CVE counts.
- **System Stability Fixes:**
  - Resolved coroutine scope issues in MainActivity for proper async operations.
  - Fixed import references and compilation errors.
  - Enhanced error handling throughout the vulnerability detection pipeline.
  - **Map Tab Optimization:**
  - Improved cell tower radius circles visibility by removing fill color and using only outline strokes.
  - Increased line thickness for better visibility (4px normal, 8px for missing towers).
  - Fixed overlapping circle visibility issues in high-density cell tower areas.

**v0.3.0-beta**
- **Deep System Hardening (Magisk/KSU Module):**
  - Introduced the Sentry Radio Hardening Module for Magisk and KernelSU.
  - Enforces secure modem parameters at the system level (e.g., disables insecure network fallbacks).
  - Provides a low-level interface (`sentry-ctl`) for direct modem interaction.
- **Dynamic CVE Vulnerability Management:**
  - Replaced static vulnerability list with live NVD API v2.0 fetching for up-to-the-minute modem CVEs.
  - Implemented intelligent matching for device chipsets (Qualcomm, MediaTek, Exynos) against the CVE database.
  - Added a local Room cache for offline vulnerability scanning.
- **Enhanced Forensic Mapping Experience:**
  - Map state (position and zoom) is now saved and restored automatically.
  - The map now intelligently centers on the user's location on first launch or when no state is saved.
  - UI-Fix: Fixed a bug causing empty pop-up bubbles; info windows now only appear for cell tower markers.
- **System Integrity Dashboard Upgrade:**
  - Added Android Security Patch level to the System Integrity Scan card.
  - Added the timestamp of the last CVE database sync for transparency.
- **Stability & API Fixes:**
  - Repaired and optimized API communication for OpenCellID and BeaconDB.
  - Enhanced Xposed module hooks for better compatibility with modern Android versions.

**v0.2.1-beta**
- Added security hardening (8 new security modules)
- Full-screen Overlay Alarms (requires SYSTEM_ALERT_WINDOW permission)
- Certificate pinning for all APIs
- AES-256-GCM encryption for API keys in Keystore
- Input validation framework
- Comprehensive audit logging
- Memory leak prevention
- Thread-safe operations
- New Security Tab with active threat blocking:
    - Block GSM Registrations (prevents 2G downgrade attacks)
    - Reject A5/0 Cipher (blocks unencrypted connections)
    - Threats Blocked Dashboard (real-time blocking statistics)
    - Blocking Events Log (detailed forensic history)

---

## ⚠️ Disclaimer

*This tool is for educational and research purposes only. Monitoring cellular networks may be subject to legal restrictions in some jurisdictions. The developer assumes no liability for misuse.*

**Developed with ❤️ by [fzer0x](https://github.com/fzer0x)**

