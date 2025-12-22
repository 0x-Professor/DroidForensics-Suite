# Quick Setup Guide for Android Forensics MCP Server

## Step 1: Install Android Platform Tools (ADB)

### For Windows:

1. **Download Android Platform Tools**:
   - Visit: https://developer.android.com/tools/releases/platform-tools
   - Download the Windows ZIP file
   - Extract to a location like `C:\platform-tools`

2. **Add to System PATH**:
   ```powershell
   # Method 1: Temporary (current session only)
   $env:PATH += ";C:\platform-tools"
   
   # Method 2: Permanent (via System Properties)
   # 1. Open System Properties (Win + Pause/Break)
   # 2. Click "Advanced system settings"
   # 3. Click "Environment Variables"
   # 4. Under "System variables", find "Path"
   # 5. Click "Edit" → "New"
   # 6. Add: C:\platform-tools
   # 7. Click "OK" on all dialogs
   # 8. Restart PowerShell
   ```

3. **Verify Installation**:
   ```powershell
   adb version
   # Should show: Android Debug Bridge version 1.0.41...
   ```

### Alternative: Using Chocolatey

```powershell
# Install Chocolatey first (if not installed)
# Then install ADB
choco install adb
```

## Step 2: Verify Server Setup

```powershell
cd u:\adb-connect
uv run python test_server.py
```

All tests should pass:
```
✅ Python Version
✅ ADB Available
✅ Module Imports
✅ Server Syntax
```

## Step 3: Prepare Android Device

1. **Enable Developer Options**:
   - Go to Settings → About Phone
   - Tap "Build Number" 7 times
   - Developer Options now appears in Settings

2. **Enable USB Debugging**:
   - Go to Settings → Developer Options
   - Enable "USB Debugging"
   - (Optional) Enable "Stay Awake" to keep screen on

3. **Connect Device**:
   - Connect via USB cable
   - On device, tap "Allow" when prompted for USB debugging
   - Check "Always allow from this computer"

4. **Verify Connection**:
   ```powershell
   adb devices
   # Should show: ABC123XYZ    device
   ```

## Step 4: Run the MCP Server

### Option A: Development Mode (with Inspector)

```powershell
cd u:\adb-connect
uv run mcp dev main.py
```

This opens the MCP Inspector in your browser where you can test all tools.

### Option B: Integrate with Claude Desktop

1. **Locate Claude Desktop Config**:
   ```
   %APPDATA%\Claude\claude_desktop_config.json
   ```

2. **Add Server Configuration**:
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

3. **Restart Claude Desktop**

4. **Verify in Claude**:
   - Look for 🔌 icon (server connected)
   - Try: "Check if ADB is available"

### Option C: Direct Execution

```powershell
cd u:\adb-connect
uv run python main.py
```

## Step 5: First Forensic Acquisition

### Quick Test Workflow

```
In Claude Desktop or MCP Inspector:

1. "Check ADB status"
   → Tool: check_adb_status

2. "List connected devices"
   → Tool: adb_devices

3. "Get information about the device"
   → Tool: get_device_info

4. "List all installed applications"
   → Tool: list_installed_packages

5. "Create a full backup to backup.ab"
   → Tool: adb_backup_device
   → Parameters: output_file="test_backup.ab"

6. "Extract the backup to TAR format"
   → Tool: extract_backup_to_tar
   → Parameters: backup_file="test_backup.ab", output_tar="test_backup.tar"
```

## Available MCP Tools

Once the server is running, these tools are available:

1. **check_adb_status** - Verify ADB installation
2. **adb_devices** - List connected devices
3. **adb_connect_device** - Connect to specific device
4. **adb_shell_command** - Execute safe shell commands
5. **get_device_info** - Get device details
6. **list_installed_packages** - List apps
7. **adb_backup_device** - Create device backup
8. **adb_pull_data** - Pull files from device
9. **extract_backup_to_tar** - Convert .ab to .tar
10. **collect_forensic_artifacts** - Auto-collect evidence

## Troubleshooting

### "ADB not found"
- Install Android Platform Tools (Step 1)
- Restart PowerShell after adding to PATH
- Try full path: `C:\platform-tools\adb.exe version`

### "No devices found"
- Check USB cable connection
- Enable USB Debugging on device
- Accept RSA fingerprint on device
- Try: `adb kill-server` then `adb start-server`

### "Device unauthorized"
- Check device screen for authorization prompt
- Tap "Allow" and check "Always allow"
- Revoke and re-authorize: `adb kill-server`

### "Backup not created"
- User must confirm backup on device screen
- Tap "Back up my data" on device
- Ensure device stays unlocked during backup
- Check available storage space

### "Permission denied" for artifacts
- Most system files require root access
- Use full backup method instead
- Or use `adb root` if device is rooted

## Security Notes

### Legal Requirements
✅ **ALWAYS REQUIRED**:
- Written authorization to access device
- Consent from device owner (if applicable)
- Compliance with local laws
- Proper case documentation

❌ **NEVER**:
- Access devices without authorization
- Modify evidence files
- Skip chain of custody documentation
- Use for illegal purposes

### Data Protection
- Store backups securely
- Calculate and verify SHA-256 hashes
- Use write-blockers when possible
- Maintain access logs
- Follow your organization's procedures

## Next Steps

1. ✅ Complete this setup guide
2. ✅ Test with a test device first
3. ✅ Read `forensic_workflow.md` for detailed procedures
4. ✅ Review `examples.md` for usage examples
5. ✅ Create your investigation templates
6. ✅ Practice on test cases before live investigations

## Support Resources

- **Documentation**: See README.md
- **Examples**: See examples.md
- **Workflows**: See forensic_workflow.md
- **MCP SDK**: https://github.com/modelcontextprotocol/python-sdk
- **ADB Docs**: https://developer.android.com/tools/adb

## File Structure

```
u:\adb-connect\
├── main.py                    # MCP Server (main file)
├── test_server.py            # System check script
├── pyproject.toml            # Dependencies
├── README.md                 # Full documentation
├── forensic_workflow.md      # Investigation procedures
├── examples.md               # Usage examples
├── SETUP.md                  # This file
├── LICENSE                   # MIT License
└── .python-version          # Python 3.13
```

---

**You're Ready!** The server is set up and ready for forensic investigations.

For detailed workflows and examples, see:
- `forensic_workflow.md` - Complete investigation procedures
- `examples.md` - Tool usage examples with expected outputs
- `README.md` - Full technical documentation
