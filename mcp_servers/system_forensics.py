"""
System Forensics MCP Server
Federal Investigation Agency (FIA) - Android Forensics Framework

Provides tools for system-level forensic analysis including:
- System logs (logcat, dmesg, kernel logs)
- Root/privilege escalation detection
- Security bypass techniques for data extraction
- Partition and filesystem analysis
- Installed package analysis
- System configuration and settings
"""

import hashlib
import json
import os
import re
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel, Field

# Initialize FastMCP server
mcp = FastMCP(
    "FIA System Forensics",
    instructions="""
    Secure MCP server for Android system-level forensic analysis.
    Handles logs, root detection, security analysis, and system artifacts.
    Supports advanced data extraction techniques for forensic investigations.
    """
)


def execute_adb_command(args: list[str], device_id: Optional[str] = None, timeout: int = 60) -> dict[str, Any]:
    """Execute ADB command safely with timeout"""
    try:
        cmd = ["adb"]
        if device_id:
            cmd.extend(["-s", device_id])
        cmd.extend(args)
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return {
            "stdout": result.stdout,
            "stderr": result.stderr,
            "returncode": result.returncode,
            "success": result.returncode == 0,
            "command": " ".join(cmd)
        }
    except subprocess.TimeoutExpired:
        return {"stdout": "", "stderr": f"Timeout after {timeout}s", "returncode": -1, "success": False}
    except Exception as e:
        return {"stdout": "", "stderr": str(e), "returncode": -1, "success": False}


def calculate_file_hash(file_path: Path) -> str:
    """Calculate SHA-256 hash of a file"""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256_hash.update(chunk)
    return sha256_hash.hexdigest()


@mcp.tool()
def capture_logcat(
    output_file: str,
    device_id: Optional[str] = None,
    lines: int = 10000,
    filter_spec: Optional[str] = None,
    include_timestamps: bool = True
) -> dict[str, Any]:
    """
    Capture Android system logs (logcat).
    Critical for understanding device activity and app behavior.
    
    Args:
        output_file: Path to save the logcat output
        device_id: Optional device serial number
        lines: Number of log lines to capture (default 10000)
        filter_spec: Optional logcat filter (e.g., "*:W" for warnings+)
        include_timestamps: Include timestamps in output
    """
    output_path = Path(output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    args = ["logcat", "-d"]
    
    if include_timestamps:
        args.extend(["-v", "threadtime"])
    
    if lines:
        args.extend(["-t", str(lines)])
    
    if filter_spec:
        args.append(filter_spec)
    
    result = execute_adb_command(["shell"] + args, device_id, timeout=120)
    
    if result["success"]:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(result["stdout"])
        
        file_hash = calculate_file_hash(output_path)
        line_count = len(result["stdout"].split("\n"))
        
        return {
            "success": True,
            "output_file": str(output_path.absolute()),
            "line_count": line_count,
            "file_size_bytes": output_path.stat().st_size,
            "sha256_hash": file_hash,
            "timestamp": datetime.now().isoformat()
        }
    else:
        return {"success": False, "error": result["stderr"]}


@mcp.tool()
def capture_dmesg(
    output_file: str,
    device_id: Optional[str] = None
) -> dict[str, Any]:
    """
    Capture kernel ring buffer (dmesg).
    Contains hardware events, driver messages, and security-related logs.
    
    Args:
        output_file: Path to save dmesg output
        device_id: Optional device serial number
    
    Note: May require root access on some devices.
    """
    output_path = Path(output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    # Try without root first
    result = execute_adb_command(["shell", "dmesg"], device_id, timeout=60)
    
    if not result["success"] or not result["stdout"].strip():
        # Try with root
        result = execute_adb_command(["shell", "su -c 'dmesg'"], device_id, timeout=60)
    
    if result["stdout"].strip():
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(result["stdout"])
        
        return {
            "success": True,
            "output_file": str(output_path.absolute()),
            "line_count": len(result["stdout"].split("\n")),
            "sha256_hash": calculate_file_hash(output_path),
            "timestamp": datetime.now().isoformat()
        }
    else:
        return {
            "success": False,
            "error": "Could not capture dmesg",
            "note": "Root access may be required"
        }


@mcp.tool()
def check_root_status(
    device_id: Optional[str] = None
) -> dict[str, Any]:
    """
    Comprehensive root/jailbreak detection.
    Checks multiple indicators of device rooting.
    
    Args:
        device_id: Optional device serial number
    """
    root_indicators = {
        "su_binary": False,
        "supersu_app": False,
        "magisk": False,
        "busybox": False,
        "root_management_apps": [],
        "dangerous_props": [],
        "selinux_permissive": False,
        "test_keys": False,
        "root_verified": False
    }
    
    # Check for su binary
    result = execute_adb_command(["shell", "which su"], device_id, timeout=10)
    if result["success"] and result["stdout"].strip():
        root_indicators["su_binary"] = True
    
    # Try to get root
    result = execute_adb_command(["shell", "su -c 'id'"], device_id, timeout=10)
    if result["success"] and "uid=0" in result["stdout"]:
        root_indicators["root_verified"] = True
    
    # Check for Magisk
    result = execute_adb_command(["shell", "ls /data/adb/magisk"], device_id, timeout=10)
    if result["success"] and result["returncode"] == 0:
        root_indicators["magisk"] = True
    
    # Check for SuperSU
    result = execute_adb_command(
        ["shell", "pm list packages | grep -i supersu"], 
        device_id, timeout=10
    )
    if result["success"] and result["stdout"].strip():
        root_indicators["supersu_app"] = True
    
    # Check for busybox
    result = execute_adb_command(["shell", "which busybox"], device_id, timeout=10)
    if result["success"] and result["stdout"].strip():
        root_indicators["busybox"] = True
    
    # Check root management apps
    root_apps = ["supersu", "magisk", "kingroot", "kingoroot", "rootmaster", "towelroot"]
    result = execute_adb_command(["shell", "pm list packages"], device_id, timeout=30)
    if result["success"]:
        packages = result["stdout"].lower()
        for app in root_apps:
            if app in packages:
                root_indicators["root_management_apps"].append(app)
    
    # Check SELinux status
    result = execute_adb_command(["shell", "getenforce"], device_id, timeout=10)
    if result["success"] and "permissive" in result["stdout"].lower():
        root_indicators["selinux_permissive"] = True
    
    # Check for test-keys
    result = execute_adb_command(["shell", "getprop ro.build.tags"], device_id, timeout=10)
    if result["success"] and "test-keys" in result["stdout"]:
        root_indicators["test_keys"] = True
    
    # Check dangerous properties
    dangerous_props = ["ro.debuggable", "ro.secure"]
    for prop in dangerous_props:
        result = execute_adb_command(["shell", f"getprop {prop}"], device_id, timeout=10)
        if result["success"]:
            value = result["stdout"].strip()
            if prop == "ro.debuggable" and value == "1":
                root_indicators["dangerous_props"].append(f"{prop}={value}")
            elif prop == "ro.secure" and value == "0":
                root_indicators["dangerous_props"].append(f"{prop}={value}")
    
    is_rooted = any([
        root_indicators["su_binary"],
        root_indicators["root_verified"],
        root_indicators["magisk"],
        root_indicators["supersu_app"],
        root_indicators["selinux_permissive"],
        root_indicators["test_keys"],
        len(root_indicators["root_management_apps"]) > 0
    ])
    
    return {
        "success": True,
        "is_rooted": is_rooted,
        "root_confidence": "high" if root_indicators["root_verified"] else ("medium" if is_rooted else "low"),
        "indicators": root_indicators,
        "forensic_implications": {
            "can_access_all_data": root_indicators["root_verified"],
            "bypass_encryption": root_indicators["root_verified"] and root_indicators["selinux_permissive"],
            "trust_level": "low" if is_rooted else "normal"
        },
        "timestamp": datetime.now().isoformat()
    }


@mcp.tool()
def get_installed_packages(
    device_id: Optional[str] = None,
    include_system: bool = False,
    output_file: Optional[str] = None
) -> dict[str, Any]:
    """
    Get list of all installed packages with details.
    Essential for identifying installed applications.
    
    Args:
        device_id: Optional device serial number
        include_system: Include system apps
        output_file: Optional path to save results as JSON
    """
    flag = "" if include_system else "-3"  # -3 = third-party only
    
    result = execute_adb_command(
        ["shell", f"pm list packages -f {flag}".strip()],
        device_id, timeout=60
    )
    
    if not result["success"]:
        return {"success": False, "error": result["stderr"]}
    
    packages = []
    for line in result["stdout"].strip().split("\n"):
        if line.startswith("package:"):
            # Format: package:/path/to/apk=package.name
            try:
                path_and_name = line[8:]  # Remove "package:"
                if "=" in path_and_name:
                    apk_path, pkg_name = path_and_name.rsplit("=", 1)
                    packages.append({
                        "package_name": pkg_name,
                        "apk_path": apk_path
                    })
            except:
                continue
    
    # Get additional info for each package
    for pkg in packages[:100]:  # Limit for performance
        # Get version
        ver_result = execute_adb_command(
            ["shell", f"dumpsys package {pkg['package_name']} | grep versionName"],
            device_id, timeout=10
        )
        if ver_result["success"]:
            match = re.search(r'versionName=([^\s]+)', ver_result["stdout"])
            if match:
                pkg["version"] = match.group(1)
        
        # Get installer
        inst_result = execute_adb_command(
            ["shell", f"pm get-install-location {pkg['package_name']}"],
            device_id, timeout=10
        )
        if inst_result["success"]:
            pkg["install_location"] = inst_result["stdout"].strip()
    
    # Categorize suspicious apps
    suspicious_keywords = ["vpn", "proxy", "tor", "hide", "vault", "secret", "privacy", "secure", "encrypt"]
    suspicious_apps = [p for p in packages if any(kw in p["package_name"].lower() for kw in suspicious_keywords)]
    
    result_data = {
        "success": True,
        "total_packages": len(packages),
        "third_party_only": not include_system,
        "suspicious_apps": suspicious_apps,
        "suspicious_count": len(suspicious_apps),
        "packages": packages,
        "timestamp": datetime.now().isoformat()
    }
    
    if output_file:
        output_path = Path(output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(result_data, f, indent=2)
        result_data["output_file"] = str(output_path.absolute())
    
    return result_data


@mcp.tool()
def dump_system_settings(
    device_id: Optional[str] = None,
    output_file: Optional[str] = None
) -> dict[str, Any]:
    """
    Dump all system settings (secure, system, global).
    Reveals device configuration, security settings, and user preferences.
    
    Args:
        device_id: Optional device serial number
        output_file: Optional path to save results as JSON
    """
    settings = {}
    
    for namespace in ["secure", "system", "global"]:
        result = execute_adb_command(
            ["shell", f"settings list {namespace}"],
            device_id, timeout=30
        )
        
        if result["success"]:
            namespace_settings = {}
            for line in result["stdout"].strip().split("\n"):
                if "=" in line:
                    key, value = line.split("=", 1)
                    namespace_settings[key] = value
            settings[namespace] = namespace_settings
    
    # Highlight forensically interesting settings
    interesting_settings = {
        "usb_debugging": settings.get("global", {}).get("adb_enabled"),
        "unknown_sources": settings.get("secure", {}).get("install_non_market_apps"),
        "developer_mode": settings.get("global", {}).get("development_settings_enabled"),
        "location_mode": settings.get("secure", {}).get("location_mode"),
        "screen_lock": settings.get("secure", {}).get("lockscreen.password_type"),
        "bluetooth_name": settings.get("secure", {}).get("bluetooth_name"),
        "android_id": settings.get("secure", {}).get("android_id"),
    }
    
    result_data = {
        "success": True,
        "interesting_settings": interesting_settings,
        "all_settings": settings,
        "setting_counts": {ns: len(s) for ns, s in settings.items()},
        "timestamp": datetime.now().isoformat()
    }
    
    if output_file:
        output_path = Path(output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(result_data, f, indent=2)
        result_data["output_file"] = str(output_path.absolute())
    
    return result_data


@mcp.tool()
def analyze_network_connections(
    device_id: Optional[str] = None,
    output_file: Optional[str] = None
) -> dict[str, Any]:
    """
    Analyze active network connections and configuration.
    Identifies connected networks, open ports, and suspicious connections.
    
    Args:
        device_id: Optional device serial number
        output_file: Optional path to save results as JSON
    """
    network_info = {}
    
    # Get netstat info
    result = execute_adb_command(["shell", "netstat -an"], device_id, timeout=30)
    if result["success"]:
        connections = []
        for line in result["stdout"].strip().split("\n")[2:]:  # Skip header
            parts = line.split()
            if len(parts) >= 4:
                connections.append({
                    "protocol": parts[0] if parts else None,
                    "local_address": parts[3] if len(parts) > 3 else None,
                    "foreign_address": parts[4] if len(parts) > 4 else None,
                    "state": parts[5] if len(parts) > 5 else None
                })
        network_info["connections"] = connections
    
    # Get IP configuration
    result = execute_adb_command(["shell", "ip addr"], device_id, timeout=30)
    if result["success"]:
        network_info["ip_config"] = result["stdout"]
    
    # Get WiFi info
    result = execute_adb_command(["shell", "dumpsys wifi | head -100"], device_id, timeout=30)
    if result["success"]:
        network_info["wifi_info"] = result["stdout"]
    
    # Get saved WiFi networks
    result = execute_adb_command(
        ["shell", "cat /data/misc/wifi/WifiConfigStore.xml 2>/dev/null || cat /data/misc/wifi/wpa_supplicant.conf 2>/dev/null"],
        device_id, timeout=30
    )
    if result["success"] and result["stdout"].strip():
        # Extract SSIDs
        ssids = re.findall(r'ssid["\s:=]+([^\s"<>]+)', result["stdout"], re.IGNORECASE)
        network_info["saved_networks"] = list(set(ssids))
    
    # Get DNS settings
    result = execute_adb_command(["shell", "getprop net.dns1"], device_id, timeout=10)
    if result["success"]:
        network_info["dns1"] = result["stdout"].strip()
    
    result = execute_adb_command(["shell", "getprop net.dns2"], device_id, timeout=10)
    if result["success"]:
        network_info["dns2"] = result["stdout"].strip()
    
    result_data = {
        "success": True,
        "network_info": network_info,
        "connection_count": len(network_info.get("connections", [])),
        "saved_network_count": len(network_info.get("saved_networks", [])),
        "timestamp": datetime.now().isoformat()
    }
    
    if output_file:
        output_path = Path(output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(result_data, f, indent=2)
        result_data["output_file"] = str(output_path.absolute())
    
    return result_data


@mcp.tool()
def get_running_processes(
    device_id: Optional[str] = None,
    output_file: Optional[str] = None
) -> dict[str, Any]:
    """
    Get list of running processes.
    Identifies active applications and background services.
    
    Args:
        device_id: Optional device serial number
        output_file: Optional path to save results as JSON
    """
    result = execute_adb_command(["shell", "ps -A"], device_id, timeout=30)
    
    if not result["success"]:
        # Try alternative
        result = execute_adb_command(["shell", "ps"], device_id, timeout=30)
    
    if not result["success"]:
        return {"success": False, "error": result["stderr"]}
    
    processes = []
    lines = result["stdout"].strip().split("\n")
    
    # Parse header to get column positions
    if lines:
        header = lines[0].split()
        for line in lines[1:]:
            parts = line.split()
            if len(parts) >= 4:
                processes.append({
                    "user": parts[0],
                    "pid": parts[1],
                    "name": parts[-1]
                })
    
    # Identify suspicious processes
    suspicious_keywords = ["su", "supersu", "magisk", "daemon", "root", "inject", "hook", "xposed", "frida"]
    suspicious = [p for p in processes if any(kw in p["name"].lower() for kw in suspicious_keywords)]
    
    result_data = {
        "success": True,
        "process_count": len(processes),
        "suspicious_processes": suspicious,
        "suspicious_count": len(suspicious),
        "processes": processes,
        "timestamp": datetime.now().isoformat()
    }
    
    if output_file:
        output_path = Path(output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(result_data, f, indent=2)
        result_data["output_file"] = str(output_path.absolute())
    
    return result_data


@mcp.tool()
def extract_with_root(
    remote_path: str,
    local_path: str,
    device_id: Optional[str] = None
) -> dict[str, Any]:
    """
    Extract files using root privileges.
    Bypasses Android security restrictions for forensic acquisition.
    
    Args:
        remote_path: Path on device (e.g., /data/data/com.whatsapp)
        local_path: Local destination path
        device_id: Optional device serial number
    
    Warning: Requires rooted device. May trigger security alerts.
    """
    # First check if root is available
    root_check = execute_adb_command(["shell", "su -c 'id'"], device_id, timeout=10)
    
    if not root_check["success"] or "uid=0" not in root_check["stdout"]:
        return {
            "success": False,
            "error": "Root access not available",
            "note": "Device must be rooted for this operation"
        }
    
    local_dir = Path(local_path)
    local_dir.mkdir(parents=True, exist_ok=True)
    
    # Use root to copy files to accessible location first
    temp_path = f"/sdcard/forensic_temp_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    
    # Create temp directory
    execute_adb_command(["shell", f"su -c 'mkdir -p {temp_path}'"], device_id)
    
    # Copy with root
    copy_result = execute_adb_command(
        ["shell", f"su -c 'cp -r {remote_path} {temp_path}/'"],
        device_id, timeout=300
    )
    
    if not copy_result["success"]:
        return {"success": False, "error": f"Root copy failed: {copy_result['stderr']}"}
    
    # Pull from temp location
    pull_result = execute_adb_command(
        ["pull", temp_path, str(local_dir)],
        device_id, timeout=600
    )
    
    # Cleanup temp
    execute_adb_command(["shell", f"su -c 'rm -rf {temp_path}'"], device_id)
    
    if local_dir.exists():
        # Calculate stats
        file_count = sum(1 for f in local_dir.rglob("*") if f.is_file())
        total_size = sum(f.stat().st_size for f in local_dir.rglob("*") if f.is_file())
        
        return {
            "success": True,
            "remote_path": remote_path,
            "local_path": str(local_dir.absolute()),
            "file_count": file_count,
            "total_size_bytes": total_size,
            "total_size_mb": round(total_size / (1024 * 1024), 2),
            "method": "root_extraction",
            "timestamp": datetime.now().isoformat()
        }
    else:
        return {"success": False, "error": "Pull operation failed"}


@mcp.tool()
def analyze_partition_info(
    device_id: Optional[str] = None,
    output_file: Optional[str] = None
) -> dict[str, Any]:
    """
    Analyze device partitions and mount points.
    Essential for understanding device storage layout.
    
    Args:
        device_id: Optional device serial number
        output_file: Optional path to save results as JSON
    """
    partition_info = {}
    
    # Get mount info
    result = execute_adb_command(["shell", "mount"], device_id, timeout=30)
    if result["success"]:
        mounts = []
        for line in result["stdout"].strip().split("\n"):
            parts = line.split()
            if len(parts) >= 3:
                mounts.append({
                    "device": parts[0],
                    "mount_point": parts[2] if len(parts) > 2 else parts[1],
                    "type": parts[4] if len(parts) > 4 else "unknown",
                    "options": parts[5] if len(parts) > 5 else ""
                })
        partition_info["mounts"] = mounts
    
    # Get disk usage
    result = execute_adb_command(["shell", "df -h"], device_id, timeout=30)
    if result["success"]:
        partition_info["disk_usage"] = result["stdout"]
    
    # Get block devices
    result = execute_adb_command(["shell", "ls -la /dev/block/by-name/"], device_id, timeout=30)
    if result["success"]:
        partition_info["block_devices"] = result["stdout"]
    
    # Get proc partitions
    result = execute_adb_command(["shell", "cat /proc/partitions"], device_id, timeout=30)
    if result["success"]:
        partition_info["proc_partitions"] = result["stdout"]
    
    result_data = {
        "success": True,
        "partition_info": partition_info,
        "mount_count": len(partition_info.get("mounts", [])),
        "timestamp": datetime.now().isoformat()
    }
    
    if output_file:
        output_path = Path(output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(result_data, f, indent=2)
        result_data["output_file"] = str(output_path.absolute())
    
    return result_data


@mcp.tool()
def get_account_info(
    device_id: Optional[str] = None,
    output_file: Optional[str] = None
) -> dict[str, Any]:
    """
    Get registered accounts on the device.
    Identifies Google, social media, and other linked accounts.
    
    Args:
        device_id: Optional device serial number
        output_file: Optional path to save results as JSON
    """
    result = execute_adb_command(
        ["shell", "dumpsys account"],
        device_id, timeout=30
    )
    
    if not result["success"]:
        return {"success": False, "error": result["stderr"]}
    
    accounts = []
    current_account = None
    
    for line in result["stdout"].split("\n"):
        if "Account {" in line:
            # Parse account info
            match = re.search(r'Account \{name=([^,]+), type=([^}]+)\}', line)
            if match:
                accounts.append({
                    "name": match.group(1),
                    "type": match.group(2)
                })
    
    # Categorize accounts
    account_types = {}
    for acc in accounts:
        acc_type = acc["type"]
        if acc_type not in account_types:
            account_types[acc_type] = []
        account_types[acc_type].append(acc["name"])
    
    result_data = {
        "success": True,
        "total_accounts": len(accounts),
        "account_types": list(account_types.keys()),
        "accounts_by_type": account_types,
        "accounts": accounts,
        "timestamp": datetime.now().isoformat()
    }
    
    if output_file:
        output_path = Path(output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(result_data, f, indent=2)
        result_data["output_file"] = str(output_path.absolute())
    
    return result_data


# Run server
if __name__ == "__main__":
    mcp.run(transport="stdio")
