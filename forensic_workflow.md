# Android Forensic Investigation Workflow

## Standard Operating Procedure for Android Device Forensics

### Pre-Acquisition Checklist

- [ ] Legal authorization obtained
- [ ] Written consent from device owner (if required)
- [ ] Case number/ID assigned
- [ ] Investigator credentials verified
- [ ] Photography equipment ready
- [ ] Write-blockers available (for storage devices)
- [ ] Faraday bag available (optional, for network isolation)
- [ ] ADB and tools installed and tested
- [ ] Evidence storage prepared

### Phase 1: Initial Documentation

#### 1.1 Physical Documentation
```
- Photograph device (all sides, ports, condition)
- Document make, model, IMEI, serial number
- Note any visible damage or modifications
- Document screen state (locked/unlocked)
- Record date, time, location of acquisition
```

#### 1.2 Device Information Collection
```python
# Using MCP tools in Claude
1. check_adb_status()
2. adb_devices()
3. adb_connect_device(device_id="SERIAL")
4. get_device_info(device_id="SERIAL")
```

**Save Output**: Document all device information to case file.

#### 1.3 Network Isolation (Optional)
- Enable Airplane Mode on device
- Or place in Faraday bag
- Prevents remote wipe, data modification

### Phase 2: Logical Acquisition

#### 2.1 Full Device Backup
```python
adb_backup_device(
    output_file="case_XXXX_device_backup.ab",
    device_id="DEVICE_SERIAL",
    include_apk=True,      # Include app data
    include_shared=True,   # Include SD card data
    all_apps=True         # Backup all apps
)
```

**Note**: User must confirm backup on device screen. Device must remain unlocked.

**Expected Time**: 30 minutes to 2+ hours depending on data size.

#### 2.2 Backup Integrity Verification
```powershell
# Calculate hash of backup file
certutil -hashfile case_XXXX_device_backup.ab SHA256

# Document hash in chain of custody log
```

#### 2.3 Installed Applications
```python
# List all packages including system apps
list_installed_packages(
    device_id="DEVICE_SERIAL",
    system_apps=True
)
```

**Save Output**: Complete list of installed applications with paths.

### Phase 3: Forensic Artifact Collection

#### 3.1 Automated Collection
```python
collect_forensic_artifacts(
    output_dir="./case_XXXX_artifacts",
    device_id="DEVICE_SERIAL"
)
```

This collects:
- Device information (JSON)
- Installed packages list
- System logs (logcat)
- Call logs (if accessible)
- SMS/MMS databases (if accessible)
- Browser history (if accessible)
- WiFi networks (if accessible)
- Account information (if accessible)

#### 3.2 Manual Artifact Collection

Common forensic artifact locations:

```python
# Call logs
adb_pull_data(
    remote_path="/data/data/com.android.providers.contacts/databases/calllog.db",
    local_path="./case_XXXX_artifacts/calllog.db",
    device_id="DEVICE_SERIAL"
)

# SMS/MMS
adb_pull_data(
    remote_path="/data/data/com.android.providers.telephony/databases/mmssms.db",
    local_path="./case_XXXX_artifacts/mmssms.db",
    device_id="DEVICE_SERIAL"
)

# Browser history (Chrome)
adb_pull_data(
    remote_path="/data/data/com.android.chrome/app_chrome/Default",
    local_path="./case_XXXX_artifacts/chrome_data",
    device_id="DEVICE_SERIAL"
)

# WhatsApp (requires root or backup)
adb_pull_data(
    remote_path="/data/data/com.whatsapp",
    local_path="./case_XXXX_artifacts/whatsapp",
    device_id="DEVICE_SERIAL"
)
```

**Note**: Most app data requires root access or can be obtained from backup extraction.

#### 3.3 System Logs
```python
# Capture current logcat
adb_shell_command(
    command="logcat -d",
    device_id="DEVICE_SERIAL"
)

# Capture system information
adb_shell_command(
    command="dumpsys",
    device_id="DEVICE_SERIAL"
)
```

### Phase 4: Backup Extraction and Analysis

#### 4.1 Extract Backup to TAR
```python
extract_backup_to_tar(
    backup_file="case_XXXX_device_backup.ab",
    output_tar="case_XXXX_device_backup.tar",
    password=None  # Or provide password if encrypted
)
```

#### 4.2 Verify TAR Extraction
```powershell
# Windows: List TAR contents
tar -tvf case_XXXX_device_backup.tar

# Extract TAR to examine
tar -xvf case_XXXX_device_backup.tar -C ./extracted_backup
```

#### 4.3 Calculate Hashes
```powershell
# Hash all extracted files
Get-ChildItem -Recurse ./extracted_backup | 
    ForEach-Object { 
        certutil -hashfile $_.FullName SHA256 
    } > hashes.txt
```

### Phase 5: Specialized Data Acquisition

#### 5.1 Screenshots
```python
adb_shell_command(
    command="screencap -p /sdcard/screenshot.png",
    device_id="DEVICE_SERIAL"
)

adb_pull_data(
    remote_path="/sdcard/screenshot.png",
    local_path="./case_XXXX_artifacts/screenshot.png",
    device_id="DEVICE_SERIAL"
)
```

#### 5.2 Screen Recording
```python
# Start recording (3 minute max by default)
adb_shell_command(
    command="screenrecord /sdcard/recording.mp4",
    device_id="DEVICE_SERIAL"
)

# Pull recording
adb_pull_data(
    remote_path="/sdcard/recording.mp4",
    local_path="./case_XXXX_artifacts/recording.mp4",
    device_id="DEVICE_SERIAL"
)
```

#### 5.3 File System Listing
```python
# List all files (may be slow)
adb_shell_command(
    command="find /sdcard -type f",
    device_id="DEVICE_SERIAL",
    timeout=300
)
```

### Phase 6: Documentation and Reporting

#### 6.1 Chain of Custody Log

Create file: `case_XXXX_chain_of_custody.txt`

```
================================================================================
CHAIN OF CUSTODY LOG
================================================================================
Case Number: XXXX
Investigator: [Name]
Date: [Date]
Time: [Time]
Location: [Location]

DEVICE INFORMATION
------------------
Make: [From get_device_info]
Model: [From get_device_info]
Serial: [From get_device_info]
IMEI: [From device or documentation]
Android Version: [From get_device_info]
Security Patch: [From get_device_info]

EVIDENCE COLLECTED
------------------
1. Full Device Backup
   File: case_XXXX_device_backup.ab
   Size: [size]
   SHA-256: [hash]
   Timestamp: [timestamp]

2. Extracted TAR Archive
   File: case_XXXX_device_backup.tar
   Size: [size]
   SHA-256: [hash]
   Timestamp: [timestamp]

3. Forensic Artifacts
   Directory: case_XXXX_artifacts/
   Files: [count]
   Total Size: [size]
   SHA-256 Hashes: See hashes.txt

ACQUISITION NOTES
-----------------
[Document any issues, user interactions, or special circumstances]

TRANSFER HISTORY
----------------
Date/Time | Transferred To | Purpose | Signature
----------|----------------|---------|----------
          |                |         |
          |                |         |

================================================================================
```

#### 6.2 Technical Report Template

```markdown
# Android Forensic Analysis Report

## Case Information
- Case Number: XXXX
- Investigator: [Name]
- Date of Analysis: [Date]
- Device Serial: [Serial]

## Executive Summary
[Brief overview of findings]

## Device Information
[From get_device_info output]

## Acquisition Methodology
- Tool Used: Android Forensics ADB MCP Server
- Method: Logical acquisition via ADB
- Backup Type: Full device backup (.ab format)
- Encryption: [Yes/No]
- Data Integrity: Verified via SHA-256 hashes

## Installed Applications
[From list_installed_packages output]
- Total Applications: [count]
- User-Installed Apps: [count]
- System Apps: [count]

## Artifacts Recovered
### Communications
- Call Logs: [Yes/No - location]
- SMS/MMS: [Yes/No - location]
- WhatsApp: [Yes/No - location]
- Email: [Yes/No - location]

### Internet Activity
- Browser History: [Yes/No - location]
- Downloads: [Yes/No - location]
- Cookies: [Yes/No - location]

### Media
- Photos: [count] - [location]
- Videos: [count] - [location]
- Audio: [count] - [location]

### Location Data
- GPS Logs: [Yes/No - location]
- WiFi Networks: [Yes/No - location]
- Cell Tower Data: [Yes/No - location]

## Timeline of Events
[Reconstruct timeline from logs and artifacts]

## Findings
[Detailed findings relevant to investigation]

## Limitations
[Document any access limitations, encrypted apps, etc.]

## Evidence Files
1. case_XXXX_device_backup.ab - [hash]
2. case_XXXX_device_backup.tar - [hash]
3. case_XXXX_artifacts/ - [directory hash]

## Conclusion
[Summary of analysis]

## Appendices
A. Complete device information
B. Application list
C. Hash verification log
D. Chain of custody
```

### Phase 7: Evidence Storage

#### 7.1 File Organization
```
case_XXXX/
├── acquisition/
│   ├── case_XXXX_device_backup.ab
│   ├── case_XXXX_device_backup.tar
│   └── acquisition_log.txt
├── artifacts/
│   ├── device_info.json
│   ├── installed_packages.json
│   ├── calllog.db
│   ├── mmssms.db
│   └── ...
├── analysis/
│   ├── parsed_calllog.csv
│   ├── parsed_sms.csv
│   └── ...
├── documentation/
│   ├── chain_of_custody.txt
│   ├── technical_report.md
│   ├── photos/
│   └── hashes.txt
└── working/
    └── [temporary analysis files]
```

#### 7.2 Write-Protection
```powershell
# Make files read-only
Get-ChildItem -Recurse case_XXXX/acquisition | 
    ForEach-Object { $_.IsReadOnly = $true }
```

#### 7.3 Backup Storage
- Create redundant copies (minimum 2)
- Store in secure, controlled environment
- Document storage location in case file
- Verify hashes periodically

### Phase 8: Analysis Tools

#### 8.1 SQLite Database Analysis
```powershell
# Install DB Browser for SQLite
# Open .db files from artifacts

# Or use command line
sqlite3 calllog.db "SELECT * FROM calls;"
```

#### 8.2 TAR Content Analysis
```powershell
# Extract and examine app data
tar -xvf case_XXXX_device_backup.tar

# Look for specific app data
cd apps/com.whatsapp/
```

#### 8.3 Timeline Generation
Use tools like:
- Autopsy (open source)
- Axiom (commercial)
- X-Ways Forensics (commercial)

### Common Issues and Solutions

#### Issue: Backup Fails
**Solution**: 
- Ensure device is unlocked
- User must tap "Back up my data" on device
- Check available storage
- Some apps block backup (use alternative methods)

#### Issue: Permission Denied for Artifacts
**Solution**:
- Requires root access for many system files
- Use `adb root` if device is rooted
- Or extract from full backup
- Consider TWRP custom recovery

#### Issue: Encrypted Backup
**Solution**:
- Obtain password from device owner
- Use `extract_backup_to_tar` with password parameter
- Document password handling in chain of custody

#### Issue: Device Locked
**Solution**:
- Obtain unlock code/pattern from owner
- Use specialized tools if legally authorized
- Document all attempts

### Legal Considerations

1. **Authorization**: Always have written authorization
2. **Consent**: Document consent when required
3. **Privacy**: Follow data protection regulations
4. **Chain of Custody**: Maintain detailed logs
5. **Reporting**: Document all procedures and findings
6. **Expert Testimony**: Be prepared to explain methods

### Best Practices Summary

✅ **DO:**
- Document everything
- Calculate and verify hashes
- Maintain chain of custody
- Use write-blockers when possible
- Create multiple backups
- Work on copies, not originals
- Keep detailed notes
- Follow legal requirements

❌ **DON'T:**
- Modify original evidence
- Skip documentation
- Rush the process
- Ignore device state changes
- Forget to photograph device
- Work without authorization
- Delete or modify collected data

---

**End of Forensic Workflow Document**

*This workflow is a guideline. Always follow your organization's specific procedures and legal requirements.*
