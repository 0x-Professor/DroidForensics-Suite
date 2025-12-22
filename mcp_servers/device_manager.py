"""
Device Manager MCP Server
Federal Investigation Agency (FIA) - Android Forensics Framework

Provides tools for Android device connection, management, and information gathering.
"""

import asyncio
import json
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel, Field

# Initialize FastMCP server
mcp = FastMCP(
    "FIA Device Manager",
    instructions="""
    Secure MCP server for Android device management in forensic investigations.
    Handles device connection, status checking, and detailed device information gathering.
    All operations maintain chain of custody and forensic integrity.
    """
)


class DeviceInfo(BaseModel):
    """Comprehensive device information model"""
    serial: str
    state: str
    manufacturer: Optional[str] = None
    model: Optional[str] = None
    brand: Optional[str] = None
    android_version: Optional[str] = None
    sdk_version: Optional[str] = None
    build_id: Optional[str] = None
    security_patch: Optional[str] = None
    kernel_version: Optional[str] = None
    baseband_version: Optional[str] = None
    imei: Optional[str] = None
    serial_number: Optional[str] = None
    wifi_mac: Optional[str] = None
    bluetooth_mac: Optional[str] = None
    screen_resolution: Optional[str] = None
    battery_level: Optional[str] = None
    storage_info: Optional[dict] = None
    is_rooted: Optional[bool] = None
    encryption_state: Optional[str] = None
    usb_debugging: Optional[bool] = None
    oem_unlock: Optional[bool] = None


class ForensicMetadata(BaseModel):
    """Forensic chain of custody metadata"""
    timestamp: str = Field(default_factory=lambda: datetime.now().isoformat())
    investigator: str = Field(default="FIA Officer")
    case_id: Optional[str] = None
    device_serial: Optional[str] = None
    operation: str
    notes: Optional[str] = None


def execute_adb_command(args: list[str], timeout: int = 30) -> dict[str, Any]:
    """Execute ADB command safely with timeout"""
    try:
        cmd = ["adb"] + args
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            encoding='utf-8',
            errors='replace'
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


def check_adb_available() -> bool:
    """Check if ADB is available in system PATH"""
    try:
        result = subprocess.run(
            ["adb", "version"],
            capture_output=True,
            text=True,
            timeout=5,
            encoding='utf-8',
            errors='replace'
        )
        return result.returncode == 0
    except (subprocess.SubprocessError, FileNotFoundError):
        return False


@mcp.tool()
def check_adb_status() -> dict[str, Any]:
    """
    Check if ADB (Android Debug Bridge) is installed and accessible.
    Returns version information and availability status.
    """
    if not check_adb_available():
        return {
            "available": False,
            "message": "ADB not found. Please install Android Platform Tools.",
            "install_url": "https://developer.android.com/tools/releases/platform-tools",
            "instructions": [
                "1. Download Android Platform Tools",
                "2. Extract to a folder (e.g., C:\\platform-tools)",
                "3. Add the folder to your system PATH",
                "4. Restart your terminal and try again"
            ]
        }
    
    result = execute_adb_command(["version"])
    return {
        "available": True,
        "version": result["stdout"].strip(),
        "message": "ADB is available and ready for forensic operations"
    }


@mcp.tool()
def list_connected_devices() -> dict[str, Any]:
    """
    List all Android devices connected via USB or wireless ADB.
    Returns detailed information about each connected device.
    """
    result = execute_adb_command(["devices", "-l"])
    
    if not result["success"]:
        return {
            "success": False,
            "error": result["stderr"],
            "devices": []
        }
    
    lines = result["stdout"].strip().split("\n")[1:]  # Skip header
    devices = []
    
    for line in lines:
        if line.strip():
            parts = line.split()
            if len(parts) >= 2:
                device = {
                    "serial": parts[0],
                    "state": parts[1],
                    "details": {}
                }
                # Parse additional details (model:xxx device:xxx etc.)
                for part in parts[2:]:
                    if ":" in part:
                        key, value = part.split(":", 1)
                        device["details"][key] = value
                devices.append(device)
    
    return {
        "success": True,
        "count": len(devices),
        "devices": devices,
        "timestamp": datetime.now().isoformat(),
        "message": f"Found {len(devices)} device(s) connected"
    }


@mcp.tool()
def connect_to_device(device_id: Optional[str] = None) -> dict[str, Any]:
    """
    Connect to a specific Android device or the first available device.
    Verifies connection state and returns device status.
    
    Args:
        device_id: Optional specific device serial number. If None, uses first available.
    """
    if device_id:
        result = execute_adb_command(["-s", device_id, "get-state"])
        if result["success"]:
            return {
                "success": True,
                "device_id": device_id,
                "state": result["stdout"].strip(),
                "message": f"Successfully connected to device {device_id}"
            }
        else:
            return {
                "success": False,
                "error": f"Cannot connect to device {device_id}: {result['stderr']}"
            }
    else:
        devices_result = list_connected_devices()
        if devices_result["count"] > 0:
            first_device = devices_result["devices"][0]
            return {
                "success": True,
                "device_id": first_device["serial"],
                "state": first_device["state"],
                "message": f"Connected to first available device: {first_device['serial']}"
            }
        else:
            return {
                "success": False,
                "error": "No devices connected. Please connect a device with USB debugging enabled."
            }


@mcp.tool()
def get_comprehensive_device_info(device_id: Optional[str] = None) -> dict[str, Any]:
    """
    Get comprehensive device information for forensic documentation.
    Collects all available device properties including hardware and software details.
    
    Args:
        device_id: Optional device serial number
    """
    args = ["-s", device_id, "shell", "getprop"] if device_id else ["shell", "getprop"]
    result = execute_adb_command(args, timeout=60)
    
    if not result["success"]:
        return {"success": False, "error": result["stderr"]}
    
    # Parse all properties
    properties = {}
    for line in result["stdout"].split("\n"):
        if ":" in line and "[" in line:
            try:
                key = line.split("]")[0].replace("[", "").strip()
                value = line.split("]: [")[1].rstrip("]") if "]: [" in line else ""
                properties[key] = value
            except:
                continue
    
    # Get additional info
    storage_result = execute_adb_command(
        ["-s", device_id, "shell", "df -h /data"] if device_id else ["shell", "df -h /data"]
    )
    
    battery_result = execute_adb_command(
        ["-s", device_id, "shell", "dumpsys battery"] if device_id else ["shell", "dumpsys battery"]
    )
    
    # Check root status
    root_result = execute_adb_command(
        ["-s", device_id, "shell", "su -c 'id'"] if device_id else ["shell", "su -c 'id'"],
        timeout=5
    )
    is_rooted = "uid=0" in root_result.get("stdout", "")
    
    # Parse battery info
    battery_level = None
    if battery_result["success"]:
        for line in battery_result["stdout"].split("\n"):
            if "level:" in line.lower():
                try:
                    battery_level = line.split(":")[1].strip()
                except:
                    pass
    
    device_info = {
        "success": True,
        "serial": device_id or "default",
        "manufacturer": properties.get("ro.product.manufacturer", "unknown"),
        "model": properties.get("ro.product.model", "unknown"),
        "brand": properties.get("ro.product.brand", "unknown"),
        "device_name": properties.get("ro.product.device", "unknown"),
        "android_version": properties.get("ro.build.version.release", "unknown"),
        "sdk_version": properties.get("ro.build.version.sdk", "unknown"),
        "build_id": properties.get("ro.build.id", "unknown"),
        "build_fingerprint": properties.get("ro.build.fingerprint", "unknown"),
        "security_patch": properties.get("ro.build.version.security_patch", "unknown"),
        "kernel_version": properties.get("ro.build.kernel", "unknown"),
        "baseband_version": properties.get("gsm.version.baseband", "unknown"),
        "bootloader": properties.get("ro.bootloader", "unknown"),
        "hardware": properties.get("ro.hardware", "unknown"),
        "board": properties.get("ro.product.board", "unknown"),
        "cpu_abi": properties.get("ro.product.cpu.abi", "unknown"),
        "first_api_level": properties.get("ro.product.first_api_level", "unknown"),
        "encryption_state": properties.get("ro.crypto.state", "unknown"),
        "selinux_status": properties.get("ro.boot.selinux", "unknown"),
        "wifi_mac": properties.get("ro.boot.wifimacaddr", "unknown"),
        "bluetooth_mac": properties.get("ro.boot.btmacaddr", "unknown"),
        "is_rooted": is_rooted,
        "battery_level": battery_level,
        "storage_info": storage_result["stdout"] if storage_result["success"] else None,
        "all_properties": properties,
        "timestamp": datetime.now().isoformat(),
        "forensic_note": "Device information collected for forensic investigation"
    }
    
    return device_info


@mcp.tool()
def get_device_identifiers(device_id: Optional[str] = None) -> dict[str, Any]:
    """
    Get all device identifiers for forensic tracking (IMEI, serial, etc.).
    These are critical for chain of custody documentation.
    
    Args:
        device_id: Optional device serial number
    """
    identifiers = {}
    
    # Get IMEI (requires phone permission or root)
    imei_result = execute_adb_command(
        ["-s", device_id, "shell", "service call iphonesubinfo 1"] if device_id 
        else ["shell", "service call iphonesubinfo 1"],
        timeout=10
    )
    
    # Get Android ID
    android_id_result = execute_adb_command(
        ["-s", device_id, "shell", "settings get secure android_id"] if device_id
        else ["shell", "settings get secure android_id"]
    )
    
    # Get device serial
    serial_result = execute_adb_command(
        ["-s", device_id, "shell", "getprop ro.serialno"] if device_id
        else ["shell", "getprop ro.serialno"]
    )
    
    # Get SIM info
    sim_result = execute_adb_command(
        ["-s", device_id, "shell", "getprop gsm.sim.operator.alpha"] if device_id
        else ["shell", "getprop gsm.sim.operator.alpha"]
    )
    
    sim_country = execute_adb_command(
        ["-s", device_id, "shell", "getprop gsm.operator.iso-country"] if device_id
        else ["shell", "getprop gsm.operator.iso-country"]
    )
    
    return {
        "success": True,
        "identifiers": {
            "adb_serial": device_id or "default",
            "device_serial": serial_result["stdout"].strip() if serial_result["success"] else None,
            "android_id": android_id_result["stdout"].strip() if android_id_result["success"] else None,
            "sim_operator": sim_result["stdout"].strip() if sim_result["success"] else None,
            "sim_country": sim_country["stdout"].strip() if sim_country["success"] else None,
        },
        "timestamp": datetime.now().isoformat(),
        "note": "Some identifiers may require root access or specific permissions"
    }


@mcp.tool()
def get_device_security_status(device_id: Optional[str] = None) -> dict[str, Any]:
    """
    Get device security configuration and status.
    Important for understanding what data can be accessed.
    
    Args:
        device_id: Optional device serial number
    """
    prefix = ["-s", device_id] if device_id else []
    
    # Check various security settings
    checks = {
        "usb_debugging": "settings get global adb_enabled",
        "unknown_sources": "settings get secure install_non_market_apps",
        "screen_lock_type": "settings get secure lockscreen.password_type",
        "device_encrypted": "getprop ro.crypto.state",
        "selinux": "getenforce",
        "dm_verity": "getprop ro.boot.veritymode",
        "oem_unlock": "getprop ro.oem_unlock_supported",
        "bootloader_locked": "getprop ro.boot.flash.locked",
        "secure_boot": "getprop ro.boot.secureboot",
        "developer_options": "settings get global development_settings_enabled",
    }
    
    security_status = {}
    for check_name, command in checks.items():
        result = execute_adb_command(prefix + ["shell", command], timeout=10)
        security_status[check_name] = result["stdout"].strip() if result["success"] else "unknown"
    
    return {
        "success": True,
        "device_id": device_id or "default",
        "security_status": security_status,
        "timestamp": datetime.now().isoformat(),
        "forensic_implications": {
            "encrypted": "Device encryption may limit data access" if security_status.get("device_encrypted") == "encrypted" else "Device not encrypted - full access possible",
            "root_available": "Check root status for elevated access",
            "bootloader": "Locked bootloader limits custom recovery options"
        }
    }


@mcp.tool()
def get_device_accounts(device_id: Optional[str] = None) -> dict[str, Any]:
    """
    Get list of accounts configured on the device.
    Useful for identifying user accounts and linked services.
    
    Args:
        device_id: Optional device serial number
    """
    args = ["-s", device_id, "shell", "dumpsys account"] if device_id else ["shell", "dumpsys account"]
    result = execute_adb_command(args, timeout=30)
    
    if not result["success"]:
        return {"success": False, "error": result["stderr"]}
    
    # Parse account information
    accounts = []
    current_account = None
    
    for line in result["stdout"].split("\n"):
        if "Account {" in line:
            # Extract account info
            try:
                name_part = line.split("name=")[1].split(",")[0] if "name=" in line else ""
                type_part = line.split("type=")[1].split("}")[0] if "type=" in line else ""
                accounts.append({
                    "name": name_part,
                    "type": type_part
                })
            except:
                pass
    
    return {
        "success": True,
        "device_id": device_id or "default",
        "account_count": len(accounts),
        "accounts": accounts,
        "timestamp": datetime.now().isoformat(),
        "note": "Account details useful for user identification"
    }


@mcp.tool()
def get_device_users(device_id: Optional[str] = None) -> dict[str, Any]:
    """
    Get list of user profiles on the device (Android multi-user).
    Important for devices with work profiles or multiple users.
    
    Args:
        device_id: Optional device serial number
    """
    args = ["-s", device_id, "shell", "pm list users"] if device_id else ["shell", "pm list users"]
    result = execute_adb_command(args, timeout=10)
    
    if not result["success"]:
        return {"success": False, "error": result["stderr"]}
    
    users = []
    for line in result["stdout"].split("\n"):
        if "UserInfo{" in line:
            try:
                # Parse UserInfo{0:Owner:c13}
                info = line.split("UserInfo{")[1].split("}")[0]
                parts = info.split(":")
                users.append({
                    "user_id": parts[0],
                    "name": parts[1] if len(parts) > 1 else "",
                    "flags": parts[2] if len(parts) > 2 else ""
                })
            except:
                pass
    
    return {
        "success": True,
        "device_id": device_id or "default",
        "user_count": len(users),
        "users": users,
        "timestamp": datetime.now().isoformat()
    }


@mcp.tool()
def take_device_screenshot(
    device_id: Optional[str] = None,
    output_path: str = "./screenshots"
) -> dict[str, Any]:
    """
    Capture current screen of the device.
    Useful for documenting device state during investigation.
    
    Args:
        device_id: Optional device serial number
        output_path: Directory to save screenshot
    """
    output_dir = Path(output_path)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    device_suffix = device_id.replace(":", "_") if device_id else "default"
    filename = f"screenshot_{device_suffix}_{timestamp}.png"
    local_path = output_dir / filename
    
    # Capture on device
    prefix = ["-s", device_id] if device_id else []
    capture_result = execute_adb_command(
        prefix + ["shell", "screencap", "-p", "/sdcard/screenshot_temp.png"],
        timeout=10
    )
    
    if not capture_result["success"]:
        return {"success": False, "error": f"Failed to capture: {capture_result['stderr']}"}
    
    # Pull to local
    pull_result = execute_adb_command(
        prefix + ["pull", "/sdcard/screenshot_temp.png", str(local_path)],
        timeout=30
    )
    
    # Clean up on device
    execute_adb_command(prefix + ["shell", "rm", "/sdcard/screenshot_temp.png"])
    
    if pull_result["success"] and local_path.exists():
        return {
            "success": True,
            "file_path": str(local_path.absolute()),
            "file_size": local_path.stat().st_size,
            "timestamp": datetime.now().isoformat()
        }
    else:
        return {"success": False, "error": f"Failed to pull screenshot: {pull_result['stderr']}"}


@mcp.tool()
def reboot_device(
    device_id: Optional[str] = None,
    mode: str = "normal"
) -> dict[str, Any]:
    """
    Reboot the device into specified mode.
    Use with caution - may affect evidence state.
    
    Args:
        device_id: Optional device serial number
        mode: Reboot mode - 'normal', 'recovery', 'bootloader', 'fastboot'
    """
    valid_modes = ["normal", "recovery", "bootloader", "fastboot"]
    if mode not in valid_modes:
        return {"success": False, "error": f"Invalid mode. Use one of: {valid_modes}"}
    
    prefix = ["-s", device_id] if device_id else []
    
    if mode == "normal":
        args = prefix + ["reboot"]
    else:
        args = prefix + ["reboot", mode]
    
    result = execute_adb_command(args, timeout=10)
    
    return {
        "success": result["success"],
        "mode": mode,
        "message": f"Device rebooting into {mode} mode" if result["success"] else result["stderr"],
        "warning": "Device reboot may affect evidence state. Document reason for reboot.",
        "timestamp": datetime.now().isoformat()
    }


def main():
    """Run the Device Manager MCP server"""
    mcp.run()


if __name__ == "__main__":
    main()
