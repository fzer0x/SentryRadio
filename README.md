# Sentry Radio 📡

**Sentry Radio** is a professional-grade Android forensic tool designed to detect, analyze, and map cellular network anomalies, including potential IMSI Catchers (Stingrays), cell site simulators, and suspicious network downgrades.

Built for security researchers and privacy-conscious users, it provides deep insights into the radio stack, monitoring both SIM slots in real-time.

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

Add your API key in the app settings (now encrypted in Keystore):
- [Free][OpenCellID API Key](https://opencellid.org/)
- BeaconDB (API-Keyless)

---

## 🛡️ Security (v0.5.0)

Sentry Radio now includes enhanced security hardening with advanced emergency controls and radio forensics:

- **Dynamic CVE Scanning:** Live vulnerability checks against the NIST NVD database.
- **Stationary Cell Monitoring (B1):** Detects suspicious cell changes while stationary (IMSI Catcher activity indicator).
- **Signal Inconsistency Analysis (B2):** Real-time monitoring for SNR anomalies and unrealistic signal power jumps.
- **Neighbor Consistency Check (B3):** Identifies isolated cells with zero neighbors, typical for malicious cell simulators.
- **Advanced Panic Mode:** Full system lockdown with hardware radio disable and network isolation.
- **Recovery Controls:** Automated recovery procedures with panic validation and forensic analysis.
- **System-Level Hardening Module:** An optional Magisk/KSU module provides deep system integration to enforce radio security policies with intelligent reboot detection.
- **App Update Management:** Automatic detection of app updates via GitHub API with secure overlay notifications.
- **API Key Encryption:** AES-256-GCM encryption in Android Keystore
- **Certificate Pinning:** Public key pinning prevents MITM attacks on all APIs
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
- **Baseband Layer:** Live fingerprinting against the NIST NVD database for known modem vulnerabilities.

---

## 🤝 Contributing

Contributions are welcome! For major changes, please open an issue first.

---

## ⚖️ License

Distributed under the GNU GPL v3 License. See `LICENSE` for more information.

---

## 📝 Changelog
**v0.5.0**
- **B1: Stationary Cell Monitoring:** Added "Lock-in Mode" to detect cell changes while the device is stationary.
- **B2: Signal Inconsistency Monitoring:** Added SNR/SINR analysis to identify suspicious high-power signal anomalies.
- **B3: Neighbor Cell Inconsistency Monitoring:** Detects isolated cells with zero neighbors, typical for malicious cell site simulators.
- **eBPF Firewall Integration:** Replaced standard iptables rules in Panic-Mode with deep eBPF-based (cBPF) kernel filtering for absolute network isolation.
- **SELinux Policy Hardening:** Added Magisk/KSU sepolicy rules to isolate radio device nodes (`/dev/smd*`), restricting access exclusively to Sentry and system radio processes.
- **Forensic Engine Update:** Integrated new monitors into the core forensic service.

**v0.4.6**
- Improve Battery safety
- Add App/Module On/Off Switch option in Settings
- Fix Root recognition for some devices
- Fix some minor bugs

**v0.4.5**
- **Enhanced Chipset Recognition System:**
    - Added comprehensive codename-to-technical-name mapping for all major chipset families.
- **Optimized CVE Database System:**
    - Added intelligent keyword generation based on device chipset.
- **Improved Performance:**
    - Faster loading times with targeted vulnerability fetching.

**v0.4.0-beta**
- **Advanced Panic Mode & Recovery System:**
   - Implemented Extended Panic Mode with full system lockdown and hardware radio disable.
   - Added automated recovery procedures with panic validation.
- **App Update Management System:**
   - Implemented automatic app update detection via GitHub API.

**v0.3.0-beta**
- **Deep System Hardening (Magisk/KSU Module):**
   - Introduced the Sentry Radio Hardening Module for Magisk and KernelSU.
- **Dynamic CVE Vulnerability Management:**
   - Replaced static vulnerability list with live NVD API v2.0 fetching.

**v0.2.1-beta**
   - Added security hardening (8 new security modules)
   - Full-screen Overlay Alarms
   - Certificate pinning for all APIs
   - AES-256-GCM encryption for API keys in Keystore

---

## ⚠️ Disclaimer

*This tool is for educational and research purposes only. Monitoring cellular networks may be subject to legal restrictions in some jurisdictions. The developer assumes no liability for misuse.*

**Developed with ❤️ by [fzer0x](https://github.com/fzer0x)**
