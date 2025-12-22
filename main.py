"""
MCP Server for Android Forensic Data Acquisition
Provides tools for ADB device management, shell execution, and data extraction
for forensic investigations with full consent.
"""

import asyncio
import json
import os
import struct
import subprocess
import zlib
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel, Field

# Initialize FastMCP server
mcp = FastMCP(
    "Android Forensics ADB Server",
    instructions="Secure MCP server for Android device forensic data acquisition via ADB. "
    "Supports device connection, shell commands, backups, and data extraction.",
)


class DeviceInfo(BaseModel):
    """Model for device information"""
    serial: str
    state: str
    model: Optional[str] = None
    android_version: Optional[str] = None
    sdk_version: Optional[str] = None


class ForensicMetadata(BaseModel):
    """Forensic chain of custody metadata"""
    timestamp: str
    investigator: str = Field(default="system")
    case_id: Optional[str] = None
    device_serial: Optional[str] = None
    operation: str
    hash_sha256: Optional[str] = None


# Whitelisted safe ADB shell commands for forensic operations
ALLOWED_SHELL_COMMANDS = {
    "ls", "cat", "pwd", "getprop", "dumpsys", "pm", "am", "df", "du",
    "ps", "top", "logcat", "id", "uname", "date", "uptime", "netstat",
    "ip", "ifconfig", "settings", "content", "screencap", "wm", "find"
}


def check_adb_available() -> bool:
    """Check if ADB is available in system PATH"""
    try:
        result = subprocess.run(
            ["adb", "version"],
            capture_output=True,
            text=True,
            timeout=5
        )
        return result.returncode == 0
    except (subprocess.SubprocessError, FileNotFoundError):
        return False


def execute_adb_command(args: list[str], timeout: int = 30, input_data: Optional[str] = None) -> dict[str, Any]:
    """Execute ADB command safely"""
    try:
        cmd = ["adb"] + args
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            input=input_data
        )
        
        return {
            "stdout": result.stdout,
            "stderr": result.stderr,
            "returncode": result.returncode,
            "success": result.returncode == 0,
            "command": " ".join(cmd)
        }
    except subprocess.TimeoutExpired:
        return {
            "stdout": "",
            "stderr": f"Command timed out after {timeout} seconds",
            "returncode": -1,
            "success": False,
            "command": " ".join(["adb"] + args)
        }
    except Exception as e:
        return {
            "stdout": "",
            "stderr": str(e),
            "returncode": -1,
            "success": False,
            "command": " ".join(["adb"] + args)
        }


def is_command_allowed(command: str) -> tuple[bool, str]:
    """Check if shell command is in whitelist"""
    # Split by common shell operators
    parts = command.replace("&&", ";").replace("||", ";").replace("|", ";").split(";")
    
    for part in parts:
        cmd = part.strip().split()[0] if part.strip() else ""
        if cmd and cmd not in ALLOWED_SHELL_COMMANDS:
            return False, f"Command not allowed: {cmd}"
    
    return True, "Command allowed"


@mcp.tool()
def check_adb_status() -> dict[str, Any]:
    """Check if ADB is installed and accessible"""
    if not check_adb_available():
        return {
            "available": False,
            "message": "ADB not found. Please install Android Platform Tools.",
            "install_url": "https://developer.android.com/tools/releases/platform-tools"
        }
    
    result = execute_adb_command(["version"])
    return {
        "available": True,
        "version": result["stdout"].strip(),
        "message": "ADB is available and ready"
    }


@mcp.tool()
def adb_devices() -> dict[str, Any]:
    """List all connected Android devices via ADB"""
    result = execute_adb_command(["devices", "-l"])
    
    if not result["success"]:
        return {
            "error": result["stderr"],
            "devices": []
        }
    
    # Parse device list
    lines = result["stdout"].strip().split("\n")[1:]  # Skip header
    devices = []
    
    for line in lines:
        if line.strip():
            parts = line.split()
            if len(parts) >= 2:
                device = {
                    "serial": parts[0],
                    "state": parts[1],
                    "details": " ".join(parts[2:]) if len(parts) > 2 else ""
                }
                devices.append(device)
    
    return {
        "success": True,
        "count": len(devices),
        "devices": devices,
        "message": f"Found {len(devices)} device(s)"
    }


@mcp.tool()
def adb_connect_device(device_id: Optional[str] = None) -> dict[str, Any]:
    """
    Connect to a specific device or verify connection.
    If device_id is None, uses the first available device.
    """
    if device_id:
        # Test connection to specific device
        result = execute_adb_command(["-s", device_id, "get-state"])
        if result["success"]:
            return {
                "success": True,
                "device_id": device_id,
                "state": result["stdout"].strip(),
                "message": f"Connected to device {device_id}"
            }
        else:
            return {
                "success": False,
                "error": f"Cannot connect to device {device_id}: {result['stderr']}"
            }
    else:
        # Check for any connected device
        devices_result = adb_devices()
        if devices_result["count"] > 0:
            first_device = devices_result["devices"][0]
            return {
                "success": True,
                "device_id": first_device["serial"],
                "state": first_device["state"],
                "message": f"Using device {first_device['serial']}"
            }
        else:
            return {
                "success": False,
                "error": "No devices connected. Please connect a device with USB debugging enabled."
            }


@mcp.tool()
def adb_shell_command(command: str, device_id: Optional[str] = None, timeout: int = 30) -> dict[str, Any]:
    """
    Execute a whitelisted shell command on the Android device.
    Only safe, predefined commands are allowed for security.
    """
    # Validate command
    allowed, message = is_command_allowed(command)
    if not allowed:
        return {
            "success": False,
            "error": message,
            "allowed_commands": sorted(list(ALLOWED_SHELL_COMMANDS))
        }
    
    # Build ADB shell command
    args = ["-s", device_id, "shell", command] if device_id else ["shell", command]
    result = execute_adb_command(args, timeout=timeout)
    
    return {
        "success": result["success"],
        "output": result["stdout"],
        "error": result["stderr"],
        "command": command,
        "device_id": device_id
    }


@mcp.tool()
def get_device_info(device_id: Optional[str] = None) -> dict[str, Any]:
    """Get comprehensive device information for forensic documentation"""
    
    # Get device properties
    args = ["-s", device_id, "shell", "getprop"] if device_id else ["shell", "getprop"]
    result = execute_adb_command(args)
    
    if not result["success"]:
        return {"success": False, "error": result["stderr"]}
    
    # Parse properties
    properties = {}
    for line in result["stdout"].split("\n"):
        if ":" in line and "[" in line:
            try:
                key = line.split("[")[0].strip("[] ")
                value = line.split("[")[1].split("]")[0]
                properties[key] = value
            except:
                continue
    
    device_info = {
        "success": True,
        "serial": device_id or "default",
        "manufacturer": properties.get("ro.product.manufacturer", "unknown"),
        "model": properties.get("ro.product.model", "unknown"),
        "brand": properties.get("ro.product.brand", "unknown"),
        "device": properties.get("ro.product.device", "unknown"),
        "android_version": properties.get("ro.build.version.release", "unknown"),
        "sdk_version": properties.get("ro.build.version.sdk", "unknown"),
        "build_id": properties.get("ro.build.id", "unknown"),
        "build_fingerprint": properties.get("ro.build.fingerprint", "unknown"),
        "security_patch": properties.get("ro.build.version.security_patch", "unknown"),
        "timestamp": datetime.now().isoformat()
    }
    
    return device_info


@mcp.tool()
def list_installed_packages(device_id: Optional[str] = None, system_apps: bool = False) -> dict[str, Any]:
    """List all installed packages on the device"""
    
    cmd = "pm list packages -f"
    if not system_apps:
        cmd += " -3"  # Third-party apps only
    
    args = ["-s", device_id, "shell", cmd] if device_id else ["shell", cmd]
    result = execute_adb_command(args)
    
    if not result["success"]:
        return {"success": False, "error": result["stderr"]}
    
    packages = []
    for line in result["stdout"].split("\n"):
        if line.startswith("package:"):
            parts = line.replace("package:", "").split("=")
            if len(parts) == 2:
                packages.append({
                    "path": parts[0],
                    "package_name": parts[1]
                })
    
    return {
        "success": True,
        "count": len(packages),
        "packages": packages,
        "system_apps_included": system_apps
    }


@mcp.tool()
def adb_backup_device(
    output_file: str,
    device_id: Optional[str] = None,
    include_apk: bool = True,
    include_shared: bool = True,
    all_apps: bool = True,
    package_name: Optional[str] = None
) -> dict[str, Any]:
    """
    Create a full backup of device data using ADB backup.
    This creates an .ab (Android Backup) file.
    """
    
    # Ensure output file has .ab extension
    if not output_file.endswith(".ab"):
        output_file += ".ab"
    
    # Build backup command
    backup_args = ["backup", "-f", output_file]
    
    if include_apk:
        backup_args.append("-apk")
    else:
        backup_args.append("-noapk")
    
    if include_shared:
        backup_args.append("-shared")
    else:
        backup_args.append("-noshared")
    
    if all_apps:
        backup_args.append("-all")
    elif package_name:
        backup_args.append(package_name)
    
    if device_id:
        backup_args = ["-s", device_id] + backup_args
    
    # Execute backup (this may take a long time)
    result = execute_adb_command(backup_args, timeout=3600)  # 1 hour timeout
    
    # Check if file was created
    backup_path = Path(output_file)
    if backup_path.exists():
        file_size = backup_path.stat().st_size
        
        metadata = ForensicMetadata(
            timestamp=datetime.now().isoformat(),
            device_serial=device_id or "unknown",
            operation="adb_backup",
        )
        
        return {
            "success": True,
            "output_file": str(backup_path.absolute()),
            "file_size_bytes": file_size,
            "file_size_mb": round(file_size / (1024 * 1024), 2),
            "metadata": metadata.dict(),
            "message": "Backup created successfully. Use extract_backup to convert to TAR format.",
            "note": "User may need to confirm backup on device screen"
        }
    else:
        return {
            "success": False,
            "error": "Backup file was not created. User may have cancelled on device.",
            "command_output": result["stdout"],
            "command_error": result["stderr"]
        }


@mcp.tool()
def adb_pull_data(
    remote_path: str,
    local_path: str,
    device_id: Optional[str] = None
) -> dict[str, Any]:
    """
    Pull files or directories from the device to local storage.
    Useful for extracting specific forensic artifacts.
    """
    
    args = ["pull", remote_path, local_path]
    if device_id:
        args = ["-s", device_id] + args
    
    result = execute_adb_command(args, timeout=600)  # 10 minute timeout
    
    pulled_path = Path(local_path)
    if pulled_path.exists():
        if pulled_path.is_file():
            size = pulled_path.stat().st_size
        else:
            size = sum(f.stat().st_size for f in pulled_path.rglob("*") if f.is_file())
        
        return {
            "success": True,
            "remote_path": remote_path,
            "local_path": str(pulled_path.absolute()),
            "size_bytes": size,
            "message": f"Successfully pulled {remote_path}"
        }
    else:
        return {
            "success": False,
            "error": f"Failed to pull {remote_path}",
            "output": result["stdout"],
            "stderr": result["stderr"]
        }


@mcp.tool()
def extract_backup_to_tar(
    backup_file: str,
    output_tar: str,
    password: Optional[str] = None
) -> dict[str, Any]:
    """
    Extract Android Backup (.ab) file to TAR format.
    Python implementation of adb-backup-extract functionality.
    Supports both encrypted and unencrypted backups.
    """
    
    try:
        backup_path = Path(backup_file)
        if not backup_path.exists():
            return {"success": False, "error": f"Backup file not found: {backup_file}"}
        
        # Ensure output has .tar extension
        if not output_tar.endswith(".tar"):
            output_tar += ".tar"
        
        with open(backup_file, "rb") as f:
            # Read header
            header = f.read(24)
            
            # Verify magic bytes
            if not header.startswith(b"ANDROID BACKUP"):
                return {"success": False, "error": "Invalid backup file format"}
            
            # Parse header
            lines = header.decode("utf-8", errors="ignore").split("\n")
            version = lines[1] if len(lines) > 1 else "1"
            compressed = lines[2] if len(lines) > 2 else "1"
            encryption = lines[3] if len(lines) > 3 else "none"
            
            is_encrypted = encryption != "none"
            is_compressed = compressed == "1"
            
            if is_encrypted and not password:
                return {
                    "success": False,
                    "error": "Backup is encrypted but no password provided",
                    "encryption": encryption
                }
            
            # Read backup data
            data = f.read()
            
            if is_encrypted:
                # Decrypt data
                try:
                    data = decrypt_backup(data, password, encryption)
                except Exception as e:
                    return {
                        "success": False,
                        "error": f"Decryption failed: {str(e)}",
                        "hint": "Check if password is correct"
                    }
            
            if is_compressed:
                # Decompress
                try:
                    data = zlib.decompress(data)
                except Exception as e:
                    return {
                        "success": False,
                        "error": f"Decompression failed: {str(e)}"
                    }
            
            # Write TAR file
            with open(output_tar, "wb") as tar_file:
                tar_file.write(data)
            
            output_path = Path(output_tar)
            return {
                "success": True,
                "input_file": backup_file,
                "output_file": str(output_path.absolute()),
                "size_bytes": output_path.stat().st_size,
                "was_encrypted": is_encrypted,
                "was_compressed": is_compressed,
                "message": f"Successfully extracted backup to {output_tar}"
            }
    
    except Exception as e:
        return {
            "success": False,
            "error": f"Extraction failed: {str(e)}"
        }


def decrypt_backup(data: bytes, password: str, encryption: str) -> bytes:
    """Decrypt Android backup data"""
    
    # Read encryption metadata
    user_salt = data[:64]
    checksum_salt = data[64:128]
    rounds = struct.unpack(">I", data[128:132])[0]
    user_iv = data[132:148]
    master_key_blob = data[148:246]  # 98 bytes
    
    # Derive key from password
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA1(),
        length=32,
        salt=user_salt,
        iterations=rounds,
        backend=default_backend()
    )
    user_key = kdf.derive(password.encode())
    
    # Decrypt master key
    cipher = Cipher(
        algorithms.AES(user_key),
        modes.CBC(user_iv),
        backend=default_backend()
    )
    decryptor = cipher.decryptor()
    master_key = decryptor.update(master_key_blob) + decryptor.finalize()
    
    # Remove padding
    padding_length = master_key[-1]
    master_key = master_key[:-padding_length]
    
    # Decrypt actual data
    iv = master_key[32:48]
    key = master_key[:32]
    
    encrypted_data = data[246:]
    
    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend()
    )
    decryptor = cipher.decryptor()
    decrypted = decryptor.update(encrypted_data) + decryptor.finalize()
    
    return decrypted


@mcp.tool()
def collect_forensic_artifacts(
    output_dir: str,
    device_id: Optional[str] = None
) -> dict[str, Any]:
    """
    Collect common forensic artifacts from Android device.
    Includes logs, databases, and system information.
    """
    
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    
    artifacts = []
    errors = []
    
    # Artifact locations (requires root or specific permissions)
    artifact_paths = {
        "system_logs": "/data/system/dropbox",
        "call_logs": "/data/data/com.android.providers.contacts/databases/calllog.db",
        "sms_mms": "/data/data/com.android.providers.telephony/databases/mmssms.db",
        "browser_history": "/data/data/com.android.browser/databases/browser2.db",
        "wifi_networks": "/data/misc/wifi/wpa_supplicant.conf",
        "accounts": "/data/system/accounts.db"
    }
    
    # Collect device info first
    device_info = get_device_info(device_id)
    if device_info.get("success"):
        info_file = output_path / "device_info.json"
        with open(info_file, "w") as f:
            json.dump(device_info, f, indent=2)
        artifacts.append({"name": "device_info", "file": str(info_file)})
    
    # Collect installed packages
    packages = list_installed_packages(device_id, system_apps=True)
    if packages.get("success"):
        packages_file = output_path / "installed_packages.json"
        with open(packages_file, "w") as f:
            json.dump(packages, f, indent=2)
        artifacts.append({"name": "installed_packages", "file": str(packages_file)})
    
    # Try to pull artifact files
    for artifact_name, remote_path in artifact_paths.items():
        local_path = output_path / artifact_name
        result = adb_pull_data(remote_path, str(local_path), device_id)
        
        if result.get("success"):
            artifacts.append({
                "name": artifact_name,
                "remote_path": remote_path,
                "local_path": result["local_path"]
            })
        else:
            errors.append({
                "artifact": artifact_name,
                "error": result.get("error", "Unknown error")
            })
    
    # Collect logcat
    logcat_result = adb_shell_command("logcat -d", device_id, timeout=60)
    if logcat_result.get("success"):
        logcat_file = output_path / "logcat.txt"
        with open(logcat_file, "w") as f:
            f.write(logcat_result["output"])
        artifacts.append({"name": "logcat", "file": str(logcat_file)})
    
    metadata = ForensicMetadata(
        timestamp=datetime.now().isoformat(),
        device_serial=device_id or "unknown",
        operation="collect_forensic_artifacts"
    )
    
    metadata_file = output_path / "metadata.json"
    with open(metadata_file, "w") as f:
        json.dump(metadata.dict(), f, indent=2)
    
    return {
        "success": True,
        "output_directory": str(output_path.absolute()),
        "artifacts_collected": len(artifacts),
        "artifacts": artifacts,
        "errors": errors,
        "metadata": metadata.dict(),
        "note": "Some artifacts require root access or specific permissions"
    }


def main():
    """Run the MCP server"""
    mcp.run()


if __name__ == "__main__":
    main()
