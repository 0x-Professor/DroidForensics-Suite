# 📋 Quick Reference Card - Android Forensics MCP Server

## 🚀 Quick Start Command

```powershell
cd u:\adb-connect
uv run mcp dev main.py
```

## 📱 10 Forensic Tools Reference

### 1️⃣ System Check
```
check_adb_status()
→ Verify ADB installation and version
```

### 2️⃣ Device Discovery
```
adb_devices()
→ List all connected Android devices
```

### 3️⃣ Device Connection
```
adb_connect_device(device_id="SERIAL")
→ Connect to specific device
```

### 4️⃣ Shell Commands
```
adb_shell_command(command="pm list packages", device_id="SERIAL")
→ Execute whitelisted shell commands (22 commands allowed)
```

### 5️⃣ Device Information
```
get_device_info(device_id="SERIAL")
→ Comprehensive device documentation
   • Manufacturer, Model, Brand
   • Android Version, SDK, Build ID
   • Security Patch Level
   • Build Fingerprint
```

### 6️⃣ Application List
```
list_installed_packages(device_id="SERIAL", system_apps=True)
→ List all installed applications with paths
```

### 7️⃣ Full Backup
```
adb_backup_device(
    output_file="backup.ab",
    device_id="SERIAL",
    include_apk=True,
    include_shared=True,
    all_apps=True
)
→ Create complete device backup
```

### 8️⃣ Pull Files
```
adb_pull_data(
    remote_path="/sdcard/DCIM",
    local_path="./photos",
    device_id="SERIAL"
)
→ Extract specific files/folders
```

### 9️⃣ Extract Backup
```
extract_backup_to_tar(
    backup_file="backup.ab",
    output_tar="backup.tar",
    password="optional"
)
→ Convert .ab to .tar (handles encryption)
```

### 🔟 Collect Artifacts
```
collect_forensic_artifacts(
    output_dir="./evidence",
    device_id="SERIAL"
)
→ Automated evidence collection
   • Device info
   • Installed packages
   • System logs
   • Call logs (if accessible)
   • SMS/MMS (if accessible)
   • Browser history (if accessible)
```

## 🔐 Whitelisted Commands (22 total)

```
File Operations:  ls, cat, pwd, find, du, df
System Info:      getprop, dumpsys, uname, date, uptime, id
Packages:         pm, am
Processes:        ps, top
Network:          netstat, ip, ifconfig
Logs:             logcat
Settings:         settings, content
Screen:           screencap, wm
```

## 📊 Common Workflows

### Workflow 1: Quick Investigation
```
1. check_adb_status()
2. adb_devices()
3. get_device_info(device_id)
4. list_installed_packages(device_id)
```

### Workflow 2: Full Acquisition
```
1. check_adb_status()
2. adb_devices()
3. get_device_info(device_id)
4. adb_backup_device(output_file, device_id)
5. extract_backup_to_tar(backup_file, output_tar)
6. collect_forensic_artifacts(output_dir, device_id)
```

### Workflow 3: Targeted Collection
```
1. check_adb_status()
2. adb_devices()
3. adb_pull_data("/sdcard/DCIM", "./photos", device_id)
4. adb_pull_data("/sdcard/WhatsApp", "./whatsapp", device_id)
5. adb_shell_command("logcat -d", device_id)
```

## 🛠️ Troubleshooting Quick Fixes

| Issue | Solution |
|-------|----------|
| ADB not found | Install Android Platform Tools, add to PATH |
| No devices | Enable USB debugging, accept RSA fingerprint |
| Unauthorized | Check device screen, tap "Allow" |
| Backup fails | User must confirm on device, keep unlocked |
| Permission denied | Requires root or use backup extraction |
| Timeout | Increase timeout parameter, check connection |

## 📝 Essential Files

| File | Purpose |
|------|---------|
| `main.py` | MCP Server (run this) |
| `test_server.py` | System check script |
| `README.md` | Full documentation |
| `SETUP.md` | Setup guide |
| `forensic_workflow.md` | Investigation procedures |
| `examples.md` | Usage examples |
| `PROJECT_SUMMARY.md` | This summary |

## ⚖️ Legal Checklist

Before ANY acquisition:
- [ ] Legal authorization obtained
- [ ] Written consent (if required)
- [ ] Case ID assigned
- [ ] Chain of custody form prepared
- [ ] Investigator identified
- [ ] Storage location secured
- [ ] Compliance with local laws verified

## 🔒 Security Checklist

During acquisition:
- [ ] Device photographed (all angles)
- [ ] Physical condition documented
- [ ] Serial numbers recorded
- [ ] Screen state documented
- [ ] Network isolation considered
- [ ] All commands logged
- [ ] Hashes calculated
- [ ] Metadata generated

After acquisition:
- [ ] Files write-protected
- [ ] Hashes verified
- [ ] Backup copies created
- [ ] Storage location documented
- [ ] Chain of custody updated
- [ ] Report started

## 💡 Pro Tips

1. **Always test first** with a practice device
2. **Document everything** - photos, notes, logs
3. **Calculate hashes** immediately after acquisition
4. **Work on copies** never on originals
5. **Keep device unlocked** during backup
6. **Monitor progress** - backups can take hours
7. **Verify extraction** - check TAR contents
8. **Use proper naming** - case_ID_description_date
9. **Secure storage** - encrypted, access-controlled
10. **Follow SOP** - consistency is key

## 📞 Quick Links

- **ADB Download**: https://developer.android.com/tools/releases/platform-tools
- **MCP SDK**: https://github.com/modelcontextprotocol/python-sdk
- **Project GitHub**: [Your repository]

## 🎯 Success Criteria

✅ ADB installed and in PATH
✅ Python 3.13+ installed
✅ Dependencies installed (`uv sync`)
✅ Test script passes all checks
✅ Device connected and authorized
✅ USB debugging enabled
✅ Legal authorization obtained
✅ Server running successfully

## 🆘 Emergency Commands

```powershell
# Restart ADB
adb kill-server
adb start-server

# Check device status
adb get-state

# Re-authorize device
adb kill-server
# Then accept prompt on device again

# Check if backup is still running
Get-Process adb

# Calculate file hash
certutil -hashfile backup.ab SHA256
```

## 📊 Expected File Sizes

| Type | Typical Size |
|------|--------------|
| Device backup (.ab) | 500 MB - 50 GB |
| Extracted TAR | Same as .ab |
| Call logs DB | 1-10 MB |
| SMS/MMS DB | 10-100 MB |
| WhatsApp folder | 100 MB - 10 GB |
| Photos folder | 1 GB - 100 GB |
| Logcat | 1-50 MB |

## 🕐 Expected Durations

| Operation | Duration |
|-----------|----------|
| Device info | < 5 seconds |
| Package list | 5-30 seconds |
| Shell command | 1-60 seconds |
| File pull (1 GB) | 1-5 minutes |
| Full backup (10 GB) | 30-120 minutes |
| Backup extraction | 5-30 minutes |
| Artifact collection | 2-10 minutes |

---

## 🎓 Training Scenario

**Practice Investigation Workflow:**

```
Scenario: Suspected data theft case
Device: Samsung Galaxy (unlocked, consented)
Objective: Collect evidence of file transfers

Step 1: System check
→ check_adb_status()

Step 2: Device discovery  
→ adb_devices()
→ Record serial: ABC123

Step 3: Document device
→ get_device_info(device_id="ABC123")
→ Save to case file

Step 4: List apps
→ list_installed_packages(device_id="ABC123")
→ Look for file transfer apps

Step 5: Create backup
→ adb_backup_device(
    output_file="case_001_backup.ab",
    device_id="ABC123",
    include_apk=True,
    all_apps=True
  )
→ User confirms on device

Step 6: Extract backup
→ extract_backup_to_tar(
    backup_file="case_001_backup.ab",
    output_tar="case_001_backup.tar"
  )

Step 7: Collect artifacts
→ collect_forensic_artifacts(
    output_dir="case_001_evidence",
    device_id="ABC123"
  )

Step 8: Pull specific data
→ adb_pull_data(
    remote_path="/sdcard/Download",
    local_path="case_001_downloads",
    device_id="ABC123"
  )

Step 9: Calculate hashes
→ certutil -hashfile case_001_backup.ab SHA256

Step 10: Document everything
→ Update chain of custody
→ Create technical report
→ Secure evidence
```

---

**Print this card for quick reference during investigations!**

**Remember: Authorization → Document → Acquire → Verify → Secure**

🔍 **Professional. Legal. Thorough.** 🔍
