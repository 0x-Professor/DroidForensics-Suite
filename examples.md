# Android Forensics MCP Server - Usage Examples

## Quick Start Examples

### 1. Check System Readiness

```
Tool: check_adb_status
Parameters: None

Expected Output:
{
  "available": true,
  "version": "Android Debug Bridge version 1.0.41...",
  "message": "ADB is available and ready"
}
```

### 2. List Connected Devices

```
Tool: adb_devices
Parameters: None

Expected Output:
{
  "success": true,
  "count": 1,
  "devices": [
    {
      "serial": "ABC123XYZ",
      "state": "device",
      "details": "product:phone model:Pixel_6 device:pixel6"
    }
  ],
  "message": "Found 1 device(s)"
}
```

### 3. Connect to Specific Device

```
Tool: adb_connect_device
Parameters: {
  "device_id": "ABC123XYZ"
}

Expected Output:
{
  "success": true,
  "device_id": "ABC123XYZ",
  "state": "device",
  "message": "Connected to device ABC123XYZ"
}
```

## Device Information Collection

### 4. Get Comprehensive Device Info

```
Tool: get_device_info
Parameters: {
  "device_id": "ABC123XYZ"
}

Expected Output:
{
  "success": true,
  "serial": "ABC123XYZ",
  "manufacturer": "Google",
  "model": "Pixel 6",
  "brand": "google",
  "device": "pixel6",
  "android_version": "13",
  "sdk_version": "33",
  "build_id": "TP1A.220624.021",
  "build_fingerprint": "google/pixel6/pixel6:13/TP1A.220624.021/...",
  "security_patch": "2024-10-05",
  "timestamp": "2024-10-28T10:30:00"
}
```

### 5. List Installed Applications

```
Tool: list_installed_packages
Parameters: {
  "device_id": "ABC123XYZ",
  "system_apps": false
}

Expected Output:
{
  "success": true,
  "count": 45,
  "packages": [
    {
      "path": "/data/app/com.whatsapp-xxx/base.apk",
      "package_name": "com.whatsapp"
    },
    {
      "path": "/data/app/com.facebook.katana-xxx/base.apk",
      "package_name": "com.facebook.katana"
    }
  ],
  "system_apps_included": false
}
```

## Shell Command Execution

### 6. Execute Safe Shell Commands

```
Tool: adb_shell_command
Parameters: {
  "command": "pm list packages",
  "device_id": "ABC123XYZ"
}

Expected Output:
{
  "success": true,
  "output": "package:com.android.phone\npackage:com.whatsapp\n...",
  "error": "",
  "command": "pm list packages",
  "device_id": "ABC123XYZ"
}
```

### 7. Get System Properties

```
Tool: adb_shell_command
Parameters: {
  "command": "getprop ro.product.model",
  "device_id": "ABC123XYZ"
}

Expected Output:
{
  "success": true,
  "output": "Pixel 6",
  "error": "",
  "command": "getprop ro.product.model",
  "device_id": "ABC123XYZ"
}
```

### 8. Check Storage Space

```
Tool: adb_shell_command
Parameters: {
  "command": "df -h",
  "device_id": "ABC123XYZ"
}

Expected Output:
{
  "success": true,
  "output": "Filesystem      Size  Used Avail Use% Mounted on\n/data          120G   85G   35G  71% /data",
  "error": "",
  "command": "df -h",
  "device_id": "ABC123XYZ"
}
```

## Full Device Backup

### 9. Create Full Backup (Unencrypted)

```
Tool: adb_backup_device
Parameters: {
  "output_file": "forensic_backup_20241028.ab",
  "device_id": "ABC123XYZ",
  "include_apk": true,
  "include_shared": true,
  "all_apps": true
}

Expected Output:
{
  "success": true,
  "output_file": "U:\\adb-connect\\forensic_backup_20241028.ab",
  "file_size_bytes": 5368709120,
  "file_size_mb": 5120.0,
  "metadata": {
    "timestamp": "2024-10-28T10:45:00",
    "device_serial": "ABC123XYZ",
    "operation": "adb_backup"
  },
  "message": "Backup created successfully. Use extract_backup to convert to TAR format.",
  "note": "User may need to confirm backup on device screen"
}
```

### 10. Create Backup for Specific App

```
Tool: adb_backup_device
Parameters: {
  "output_file": "whatsapp_backup.ab",
  "device_id": "ABC123XYZ",
  "include_apk": true,
  "include_shared": false,
  "all_apps": false,
  "package_name": "com.whatsapp"
}

Expected Output:
{
  "success": true,
  "output_file": "U:\\adb-connect\\whatsapp_backup.ab",
  "file_size_bytes": 524288000,
  "file_size_mb": 500.0,
  "metadata": {...},
  "message": "Backup created successfully."
}
```

## Backup Extraction

### 11. Extract Unencrypted Backup

```
Tool: extract_backup_to_tar
Parameters: {
  "backup_file": "forensic_backup_20241028.ab",
  "output_tar": "forensic_backup_20241028.tar"
}

Expected Output:
{
  "success": true,
  "input_file": "forensic_backup_20241028.ab",
  "output_file": "U:\\adb-connect\\forensic_backup_20241028.tar",
  "size_bytes": 5368709120,
  "was_encrypted": false,
  "was_compressed": true,
  "message": "Successfully extracted backup to forensic_backup_20241028.tar"
}
```

### 12. Extract Encrypted Backup with Password

```
Tool: extract_backup_to_tar
Parameters: {
  "backup_file": "encrypted_backup.ab",
  "output_tar": "encrypted_backup.tar",
  "password": "MySecurePassword123"
}

Expected Output:
{
  "success": true,
  "input_file": "encrypted_backup.ab",
  "output_file": "U:\\adb-connect\\encrypted_backup.tar",
  "size_bytes": 4294967296,
  "was_encrypted": true,
  "was_compressed": true,
  "message": "Successfully extracted backup to encrypted_backup.tar"
}
```

### 13. Handle Encrypted Backup Without Password

```
Tool: extract_backup_to_tar
Parameters: {
  "backup_file": "encrypted_backup.ab",
  "output_tar": "encrypted_backup.tar"
}

Expected Output:
{
  "success": false,
  "error": "Backup is encrypted but no password provided",
  "encryption": "AES-256"
}
```

## Data Acquisition

### 14. Pull Specific File

```
Tool: adb_pull_data
Parameters: {
  "remote_path": "/sdcard/DCIM/Camera/IMG_20241028.jpg",
  "local_path": "./evidence/IMG_20241028.jpg",
  "device_id": "ABC123XYZ"
}

Expected Output:
{
  "success": true,
  "remote_path": "/sdcard/DCIM/Camera/IMG_20241028.jpg",
  "local_path": "U:\\adb-connect\\evidence\\IMG_20241028.jpg",
  "size_bytes": 2097152,
  "message": "Successfully pulled /sdcard/DCIM/Camera/IMG_20241028.jpg"
}
```

### 15. Pull Directory

```
Tool: adb_pull_data
Parameters: {
  "remote_path": "/sdcard/WhatsApp/Media",
  "local_path": "./evidence/whatsapp_media",
  "device_id": "ABC123XYZ"
}

Expected Output:
{
  "success": true,
  "remote_path": "/sdcard/WhatsApp/Media",
  "local_path": "U:\\adb-connect\\evidence\\whatsapp_media",
  "size_bytes": 524288000,
  "message": "Successfully pulled /sdcard/WhatsApp/Media"
}
```

## Automated Forensic Collection

### 16. Collect All Forensic Artifacts

```
Tool: collect_forensic_artifacts
Parameters: {
  "output_dir": "./case_2024_001_evidence",
  "device_id": "ABC123XYZ"
}

Expected Output:
{
  "success": true,
  "output_directory": "U:\\adb-connect\\case_2024_001_evidence",
  "artifacts_collected": 8,
  "artifacts": [
    {
      "name": "device_info",
      "file": "U:\\adb-connect\\case_2024_001_evidence\\device_info.json"
    },
    {
      "name": "installed_packages",
      "file": "U:\\adb-connect\\case_2024_001_evidence\\installed_packages.json"
    },
    {
      "name": "logcat",
      "file": "U:\\adb-connect\\case_2024_001_evidence\\logcat.txt"
    }
  ],
  "errors": [
    {
      "artifact": "call_logs",
      "error": "Permission denied - requires root access"
    }
  ],
  "metadata": {
    "timestamp": "2024-10-28T11:00:00",
    "device_serial": "ABC123XYZ",
    "operation": "collect_forensic_artifacts"
  },
  "note": "Some artifacts require root access or specific permissions"
}
```

## Error Handling Examples

### 17. Command Not in Whitelist

```
Tool: adb_shell_command
Parameters: {
  "command": "rm -rf /data",
  "device_id": "ABC123XYZ"
}

Expected Output:
{
  "success": false,
  "error": "Command not allowed: rm",
  "allowed_commands": [
    "am", "cat", "content", "date", "df", "du", "dumpsys",
    "find", "getprop", "id", "ifconfig", "ip", "logcat",
    "ls", "netstat", "pm", "ps", "pwd", "screencap",
    "settings", "top", "uname", "uptime", "wm"
  ]
}
```

### 18. Device Not Connected

```
Tool: adb_connect_device
Parameters: {
  "device_id": "NONEXISTENT"
}

Expected Output:
{
  "success": false,
  "error": "Cannot connect to device NONEXISTENT: error: device 'NONEXISTENT' not found"
}
```

### 19. Permission Denied

```
Tool: adb_pull_data
Parameters: {
  "remote_path": "/data/data/com.android.providers.telephony/databases/mmssms.db",
  "local_path": "./mmssms.db",
  "device_id": "ABC123XYZ"
}

Expected Output:
{
  "success": false,
  "error": "Failed to pull /data/data/com.android.providers.telephony/databases/mmssms.db",
  "output": "adb: error: failed to stat remote object '/data/data/com.android.providers.telephony/databases/mmssms.db': Permission denied",
  "stderr": ""
}
```

## Complete Investigation Workflow

### 20. Full Investigation Example

```
Step 1: Check ADB
Tool: check_adb_status

Step 2: List Devices
Tool: adb_devices

Step 3: Connect to Device
Tool: adb_connect_device
Parameters: {"device_id": "ABC123XYZ"}

Step 4: Document Device
Tool: get_device_info
Parameters: {"device_id": "ABC123XYZ"}

Step 5: List Applications
Tool: list_installed_packages
Parameters: {"device_id": "ABC123XYZ", "system_apps": true}

Step 6: Create Full Backup
Tool: adb_backup_device
Parameters: {
  "output_file": "case_001_backup.ab",
  "device_id": "ABC123XYZ",
  "include_apk": true,
  "include_shared": true,
  "all_apps": true
}

Step 7: Extract Backup
Tool: extract_backup_to_tar
Parameters: {
  "backup_file": "case_001_backup.ab",
  "output_tar": "case_001_backup.tar"
}

Step 8: Collect Artifacts
Tool: collect_forensic_artifacts
Parameters: {
  "output_dir": "./case_001_artifacts",
  "device_id": "ABC123XYZ"
}

Step 9: Pull Specific Data
Tool: adb_pull_data
Parameters: {
  "remote_path": "/sdcard/DCIM",
  "local_path": "./case_001_photos",
  "device_id": "ABC123XYZ"
}
```

## PowerShell Integration Examples

### 21. Verify File Hashes

```powershell
# After backup creation
certutil -hashfile case_001_backup.ab SHA256 > backup_hash.txt

# After extraction
certutil -hashfile case_001_backup.tar SHA256 >> backup_hash.txt

# Hash all artifacts
Get-ChildItem -Recurse case_001_artifacts | 
  Where-Object {!$_.PSIsContainer} |
  ForEach-Object {
    $hash = (certutil -hashfile $_.FullName SHA256)[1]
    "$($_.FullName) : $hash"
  } | Out-File -FilePath artifact_hashes.txt
```

### 22. Extract and Examine TAR

```powershell
# List TAR contents
tar -tvf case_001_backup.tar | Out-File tar_contents.txt

# Extract TAR
New-Item -ItemType Directory -Path extracted_backup
tar -xvf case_001_backup.tar -C extracted_backup

# Find specific files
Get-ChildItem -Recurse extracted_backup | 
  Where-Object {$_.Name -like "*.db"} |
  Select-Object FullName, Length
```

### 23. Create Evidence Package

```powershell
# Create organized evidence folder
$caseId = "2024_001"
$evidenceRoot = ".\case_$caseId"

New-Item -ItemType Directory -Path "$evidenceRoot\acquisition"
New-Item -ItemType Directory -Path "$evidenceRoot\artifacts"
New-Item -ItemType Directory -Path "$evidenceRoot\analysis"
New-Item -ItemType Directory -Path "$evidenceRoot\documentation"

# Move files to organized structure
Move-Item "case_001_backup.ab" "$evidenceRoot\acquisition\"
Move-Item "case_001_backup.tar" "$evidenceRoot\acquisition\"
Move-Item "case_001_artifacts\*" "$evidenceRoot\artifacts\"

# Make acquisition files read-only
Get-ChildItem "$evidenceRoot\acquisition" -Recurse | 
  ForEach-Object { $_.IsReadOnly = $true }

# Create ZIP archive
Compress-Archive -Path $evidenceRoot -DestinationPath "case_${caseId}_evidence.zip"
```

## Tips and Tricks

### Working with Multiple Devices

```
# First, list all devices
Tool: adb_devices

# Then specify device_id in all subsequent commands
Tool: get_device_info
Parameters: {"device_id": "DEVICE_SERIAL_1"}

# For second device
Tool: get_device_info
Parameters: {"device_id": "DEVICE_SERIAL_2"}
```

### Handling Large Backups

```
# Increase timeout for large backups
Tool: adb_backup_device
Parameters: {
  "output_file": "large_backup.ab",
  "device_id": "ABC123XYZ",
  "include_apk": true,
  "include_shared": true,
  "all_apps": true
}

# Note: Timeout is automatically set to 1 hour (3600 seconds)
# Monitor file size during creation:
# PowerShell: Get-Item large_backup.ab | Select-Object Length
```

### Capturing Live Logs

```
# Capture system logs before backup
Tool: adb_shell_command
Parameters: {
  "command": "logcat -d",
  "device_id": "ABC123XYZ",
  "timeout": 60
}

# Clear logs after capture
Tool: adb_shell_command
Parameters: {
  "command": "logcat -c",
  "device_id": "ABC123XYZ"
}
```

---

**Note**: All examples assume proper legal authorization and consent. Device must have USB debugging enabled and be unlocked for most operations.
