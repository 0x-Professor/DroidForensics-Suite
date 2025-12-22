# Android Forensics ADB MCP Server

A comprehensive Model Context Protocol (MCP) server for Android device forensic data acquisition using Android Debug Bridge (ADB). This tool is designed for forensic investigators with proper consent and authorization.

## ⚠️ Legal Notice

This tool is intended for **authorized forensic investigations only**. Users must have:
- Legal authorization to access the device
- Written consent from the device owner
- Compliance with local laws and regulations
- Proper chain of custody documentation

Unauthorized access to devices is illegal and unethical.

## Features

### Core Capabilities
- **Device Management**: Connect and manage Android devices via ADB
- **Secure Command Execution**: Whitelisted shell commands for safety
- **Full Device Backup**: Create complete device backups (.ab format)
- **Backup Extraction**: Convert Android Backup (.ab) to TAR format (Python port of adb-backup-extract)
- **Data Acquisition**: Pull specific files and directories
- **Forensic Artifact Collection**: Automated collection of common forensic artifacts
- **Metadata & Chain of Custody**: Automatic forensic metadata generation

### MCP Tools Available

1. **check_adb_status**: Verify ADB installation and availability
2. **adb_devices**: List all connected Android devices
3. **adb_connect_device**: Connect to specific device
4. **adb_shell_command**: Execute whitelisted shell commands
5. **get_device_info**: Get comprehensive device information
6. **list_installed_packages**: List all installed applications
7. **adb_backup_device**: Create full device backup
8. **adb_pull_data**: Pull files/folders from device
9. **extract_backup_to_tar**: Extract .ab backups to TAR format
10. **collect_forensic_artifacts**: Automated artifact collection

## Prerequisites

### Required Software
1. **Python 3.13+**: Required for the MCP server
2. **Android Platform Tools**: Install ADB
   - Download: https://developer.android.com/tools/releases/platform-tools
   - Add to system PATH

3. **UV Package Manager**: Already configured in your environment

### Android Device Requirements
- USB Debugging enabled (Settings → Developer Options → USB Debugging)
- Device unlocked during data acquisition
- USB cable connection or network ADB connection

## Installation

1. **Install Dependencies**:
```powershell
uv sync
```

2. **Verify ADB Installation**:
```powershell
adb version
```

3. **Test the Server**:
```powershell
uv run mcp dev main.py
```

## Usage

### Running the Server

#### Development Mode (with MCP Inspector)
```powershell
uv run mcp dev main.py
```

#### Production Mode (Claude Desktop Integration)
```powershell
uv run mcp install main.py --name "Android Forensics"
```

### Claude Desktop Configuration

Add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "android-forensics": {
      "command": "uv",
      "args": [
        "--directory",
        "u:\\adb-connect",
        "run",
        "main.py"
      ],
      "env": {
        "PYTHONUNBUFFERED": "1"
      }
    }
  }
}
```

### Example Workflows

#### 1. Basic Device Connection
```
1. Check ADB status: check_adb_status()
2. List devices: adb_devices()
3. Connect to device: adb_connect_device(device_id="DEVICE_SERIAL")
4. Get device info: get_device_info(device_id="DEVICE_SERIAL")
```

#### 2. Full Device Backup
```
1. Create backup:
   adb_backup_device(
       output_file="evidence_backup.ab",
       device_id="DEVICE_SERIAL",
       include_apk=True,
       include_shared=True,
       all_apps=True
   )

2. Extract backup:
   extract_backup_to_tar(
       backup_file="evidence_backup.ab",
       output_tar="evidence_backup.tar",
       password="optional_password"
   )
```

#### 3. Collect Forensic Artifacts
```
collect_forensic_artifacts(
    output_dir="./forensic_evidence",
    device_id="DEVICE_SERIAL"
)
```

#### 4. Execute Shell Commands
```
adb_shell_command(
    command="pm list packages",
    device_id="DEVICE_SERIAL"
)
```

## Security Features

### Command Whitelisting
Only the following shell commands are allowed:
- File operations: `ls`, `cat`, `pwd`, `find`, `du`, `df`
- System info: `getprop`, `dumpsys`, `uname`, `date`, `uptime`
- Package management: `pm`, `am`
- Process management: `ps`, `top`
- Network: `netstat`, `ip`, `ifconfig`
- Logs: `logcat`
- Settings: `settings`, `content`
- Screen: `screencap`, `wm`

### Validation
- Commands are validated before execution
- Shell operators (`;`, `&&`, `||`, `|`) are checked
- Timeout limits prevent hanging processes
- Error handling for all operations

## Backup Extraction Details

The `extract_backup_to_tar` tool is a Python implementation of the [adb-backup-extract](https://github.com/ParadoxEpoch/adb-backup-extract) project.

### Supported Features
- ✅ Unencrypted backups
- ✅ Encrypted backups (with password)
- ✅ Compressed backups (zlib)
- ✅ AES-256 decryption
- ✅ PBKDF2 key derivation

### Backup File Format
Android backups (.ab) have the following structure:
```
ANDROID BACKUP\n
version\n
compressed (0 or 1)\n
encryption (none or AES-256)\n
[encryption metadata if encrypted]
[compressed/encrypted data]
```

## Forensic Best Practices

### Chain of Custody
All operations generate metadata including:
- Timestamp (ISO 8601 format)
- Device serial number
- Operation performed
- Investigator information
- File hashes (where applicable)

### Evidence Collection
1. **Document Everything**: Use `get_device_info()` first
2. **Create Full Backup**: Use `adb_backup_device()` for complete acquisition
3. **Hash Evidence**: Calculate SHA-256 hashes of all collected files
4. **Maintain Logs**: Keep all command outputs and errors
5. **Write-Protect Evidence**: Store backups as read-only immediately

### Recommended Workflow
```
1. Connect device and verify connection
2. Document device information
3. Take screenshots of device state
4. Create full backup
5. Extract backup to TAR
6. Collect specific artifacts
7. Generate forensic report
8. Calculate and document all hashes
9. Store evidence securely
```

## Troubleshooting

### ADB Not Found
```powershell
# Windows: Add to PATH or use full path
$env:PATH += ";C:\path\to\platform-tools"

# Verify
adb version
```

### Device Not Detected
1. Enable USB Debugging on device
2. Accept RSA fingerprint on device
3. Try different USB cable/port
4. Check `adb devices` output

### Backup Fails
1. Ensure device is unlocked
2. Confirm backup on device screen
3. Check available storage
4. Some apps may block backup

### Permission Denied
- Many forensic artifacts require root access
- Use `adb root` if device is rooted
- Consider using TWRP recovery for full access

## Architecture

### Project Structure
```
adb-connect/
├── main.py              # MCP server implementation
├── pyproject.toml       # Dependencies and configuration
├── README.md           # This file
└── .python-version     # Python version specification
```

### Key Components

1. **MCP Server**: FastMCP-based server with tool registration
2. **ADB Wrapper**: Safe command execution with subprocess
3. **Backup Extractor**: Cryptography-based .ab to .tar converter
4. **Forensic Collectors**: Automated artifact acquisition
5. **Metadata Generator**: Chain of custody documentation

## Dependencies

- **mcp[cli]** >= 1.19.0: Model Context Protocol SDK
- **cryptography** >= 43.0.0: Backup decryption (AES-256, PBKDF2)
- **pydantic** >= 2.0.0: Data validation and serialization

## Contributing

This is a forensic tool - contributions should prioritize:
1. Security and safety
2. Legal compliance
3. Evidence integrity
4. Documentation quality

## References

- [MCP Python SDK](https://github.com/modelcontextprotocol/python-sdk)
- [MCP Shell Server](https://github.com/tumf/mcp-shell-server)
- [ADB Backup Extract](https://github.com/ParadoxEpoch/adb-backup-extract)
- [Android Backup Format](https://nelenkov.blogspot.com/2012/06/unpacking-android-backups.html)
- [Android Platform Tools](https://developer.android.com/tools/releases/platform-tools)

## License

MIT License - See LICENSE file for details.

## Disclaimer

This tool is provided for legitimate forensic investigations only. The authors and contributors are not responsible for any misuse or illegal activities. Always ensure you have proper authorization before accessing any device.

---

**For Forensic Investigation Departments**: This tool is designed to support your authorized investigations with full respect for legal requirements and chain of custody procedures.