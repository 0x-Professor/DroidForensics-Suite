"""
Data Acquisition MCP Server
Federal Investigation Agency (FIA) - Android Forensics Framework

Provides tools for forensic data acquisition including:
- Full device backups
- Selective file/folder extraction
- Logical and physical acquisition
- Backup extraction and decryption
"""

import asyncio
import hashlib
import json
import shutil
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
    "FIA Data Acquisition",
    instructions="""
    Secure MCP server for Android forensic data acquisition.
    Handles device backups, file extraction, and evidence collection.
    Maintains chain of custody with SHA-256 hashing and metadata.
    """
)


class AcquisitionMetadata(BaseModel):
    """Metadata for forensic acquisition"""
    timestamp: str = Field(default_factory=lambda: datetime.now().isoformat())
    investigator: str = Field(default="FIA Officer")
    case_id: Optional[str] = None
    device_serial: Optional[str] = None
    acquisition_type: str
    source_path: Optional[str] = None
    destination_path: Optional[str] = None
    file_count: int = 0
    total_size_bytes: int = 0
    hash_sha256: Optional[str] = None
    notes: Optional[str] = None


def execute_adb_command(args: list[str], timeout: int = 30) -> dict[str, Any]:
    """Execute ADB command safely with timeout"""
    try:
        cmd = ["adb"] + args
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, encoding='utf-8', errors='replace')
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


def calculate_directory_hash(directory: Path) -> str:
    """Calculate combined hash of all files in directory"""
    sha256_hash = hashlib.sha256()
    for file_path in sorted(directory.rglob("*")):
        if file_path.is_file():
            sha256_hash.update(file_path.name.encode())
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    sha256_hash.update(chunk)
    return sha256_hash.hexdigest()


@mcp.tool()
def create_full_backup(
    output_path: str,
    device_id: Optional[str] = None,
    include_apk: bool = True,
    include_shared: bool = True,
    include_system: bool = False,
    password: Optional[str] = None
) -> dict[str, Any]:
    """
    Create a full ADB backup of the Android device.
    Creates an .ab file containing all user data and optionally APKs.
    
    Args:
        output_path: Path for the backup file (.ab)
        device_id: Optional device serial number
        include_apk: Include APK files in backup
        include_shared: Include shared storage (/sdcard)
        include_system: Include system apps (may require root)
        password: Optional encryption password for backup
    
    Note: User must confirm backup on device screen.
    """
    if not output_path.endswith(".ab"):
        output_path += ".ab"
    
    output_file = Path(output_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)
    
    # Build backup command
    backup_args = ["backup", "-f", str(output_file)]
    
    if include_apk:
        backup_args.append("-apk")
    else:
        backup_args.append("-noapk")
    
    if include_shared:
        backup_args.append("-shared")
    else:
        backup_args.append("-noshared")
    
    if include_system:
        backup_args.append("-system")
    else:
        backup_args.append("-nosystem")
    
    backup_args.append("-all")
    
    if device_id:
        backup_args = ["-s", device_id] + backup_args
    
    # Execute backup (long timeout for large devices)
    result = execute_adb_command(backup_args, timeout=7200)  # 2 hours
    
    if output_file.exists() and output_file.stat().st_size > 0:
        file_hash = calculate_file_hash(output_file)
        file_size = output_file.stat().st_size
        
        metadata = AcquisitionMetadata(
            device_serial=device_id,
            acquisition_type="full_adb_backup",
            destination_path=str(output_file.absolute()),
            total_size_bytes=file_size,
            hash_sha256=file_hash
        )
        
        # Save metadata alongside backup
        metadata_file = output_file.with_suffix(".ab.metadata.json")
        with open(metadata_file, "w") as f:
            json.dump(metadata.model_dump(), f, indent=2)
        
        return {
            "success": True,
            "backup_file": str(output_file.absolute()),
            "metadata_file": str(metadata_file.absolute()),
            "file_size_bytes": file_size,
            "file_size_mb": round(file_size / (1024 * 1024), 2),
            "sha256_hash": file_hash,
            "encrypted": password is not None,
            "timestamp": datetime.now().isoformat(),
            "note": "Use extract_backup to convert to TAR format for analysis"
        }
    else:
        return {
            "success": False,
            "error": "Backup file was not created or is empty",
            "details": result["stderr"],
            "note": "User may have cancelled backup on device screen"
        }


@mcp.tool()
def create_package_backup(
    package_name: str,
    output_path: str,
    device_id: Optional[str] = None,
    include_apk: bool = True
) -> dict[str, Any]:
    """
    Create backup of a specific application package.
    
    Args:
        package_name: Application package name (e.g., 'com.whatsapp')
        output_path: Path for the backup file
        device_id: Optional device serial number
        include_apk: Include the APK file
    """
    if not output_path.endswith(".ab"):
        output_path += ".ab"
    
    output_file = Path(output_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)
    
    backup_args = ["backup", "-f", str(output_file)]
    
    if include_apk:
        backup_args.append("-apk")
    else:
        backup_args.append("-noapk")
    
    backup_args.append(package_name)
    
    if device_id:
        backup_args = ["-s", device_id] + backup_args
    
    result = execute_adb_command(backup_args, timeout=1800)
    
    if output_file.exists() and output_file.stat().st_size > 0:
        file_hash = calculate_file_hash(output_file)
        
        return {
            "success": True,
            "package": package_name,
            "backup_file": str(output_file.absolute()),
            "file_size_bytes": output_file.stat().st_size,
            "sha256_hash": file_hash,
            "timestamp": datetime.now().isoformat()
        }
    else:
        return {
            "success": False,
            "package": package_name,
            "error": "Backup failed or user cancelled"
        }


@mcp.tool()
def pull_file(
    remote_path: str,
    local_path: str,
    device_id: Optional[str] = None,
    preserve_timestamps: bool = True
) -> dict[str, Any]:
    """
    Pull a specific file from the device.
    
    Args:
        remote_path: Path on the Android device
        local_path: Local destination path
        device_id: Optional device serial number
        preserve_timestamps: Preserve file modification times
    """
    local_file = Path(local_path)
    local_file.parent.mkdir(parents=True, exist_ok=True)
    
    args = ["pull"]
    if preserve_timestamps:
        args.append("-a")  # Preserve file attributes
    args.extend([remote_path, str(local_file)])
    
    if device_id:
        args = ["-s", device_id] + args
    
    result = execute_adb_command(args, timeout=600)
    
    if local_file.exists():
        file_hash = calculate_file_hash(local_file)
        
        return {
            "success": True,
            "remote_path": remote_path,
            "local_path": str(local_file.absolute()),
            "file_size_bytes": local_file.stat().st_size,
            "sha256_hash": file_hash,
            "timestamp": datetime.now().isoformat()
        }
    else:
        return {
            "success": False,
            "error": f"Failed to pull file: {result['stderr']}",
            "note": "File may require root access or may not exist"
        }


@mcp.tool()
def pull_directory(
    remote_path: str,
    local_path: str,
    device_id: Optional[str] = None
) -> dict[str, Any]:
    """
    Pull an entire directory from the device recursively.
    
    Args:
        remote_path: Directory path on the Android device
        local_path: Local destination directory
        device_id: Optional device serial number
    """
    local_dir = Path(local_path)
    local_dir.mkdir(parents=True, exist_ok=True)
    
    args = ["pull", remote_path, str(local_dir)]
    if device_id:
        args = ["-s", device_id] + args
    
    result = execute_adb_command(args, timeout=3600)
    
    if local_dir.exists():
        # Count files and calculate total size
        file_count = sum(1 for f in local_dir.rglob("*") if f.is_file())
        total_size = sum(f.stat().st_size for f in local_dir.rglob("*") if f.is_file())
        dir_hash = calculate_directory_hash(local_dir)
        
        return {
            "success": True,
            "remote_path": remote_path,
            "local_path": str(local_dir.absolute()),
            "file_count": file_count,
            "total_size_bytes": total_size,
            "total_size_mb": round(total_size / (1024 * 1024), 2),
            "directory_hash": dir_hash,
            "timestamp": datetime.now().isoformat()
        }
    else:
        return {"success": False, "error": result["stderr"]}


@mcp.tool()
def pull_sdcard(
    local_path: str,
    device_id: Optional[str] = None
) -> dict[str, Any]:
    """
    Pull entire SD card / internal storage content.
    This is essential for collecting user files, media, downloads, etc.
    
    Args:
        local_path: Local destination directory
        device_id: Optional device serial number
    """
    return pull_directory("/sdcard", local_path, device_id)


@mcp.tool()
def list_remote_directory(
    remote_path: str,
    device_id: Optional[str] = None,
    detailed: bool = True
) -> dict[str, Any]:
    """
    List contents of a directory on the device.
    
    Args:
        remote_path: Path on the Android device
        device_id: Optional device serial number
        detailed: Include file sizes and permissions
    """
    cmd = f"ls -la {remote_path}" if detailed else f"ls {remote_path}"
    args = ["shell", cmd]
    if device_id:
        args = ["-s", device_id] + args
    
    result = execute_adb_command(args, timeout=30)
    
    if result["success"]:
        entries = []
        for line in result["stdout"].strip().split("\n"):
            if line and not line.startswith("total"):
                entries.append(line)
        
        return {
            "success": True,
            "path": remote_path,
            "entries": entries,
            "count": len(entries)
        }
    else:
        return {"success": False, "error": result["stderr"]}


@mcp.tool()
def extract_backup_to_tar(
    backup_file: str,
    output_tar: str,
    password: Optional[str] = None
) -> dict[str, Any]:
    """
    Extract Android Backup (.ab) file to TAR format.
    Supports both encrypted and unencrypted backups.
    
    Args:
        backup_file: Path to .ab backup file
        output_tar: Output path for .tar file
        password: Password for encrypted backups
    """
    backup_path = Path(backup_file)
    if not backup_path.exists():
        return {"success": False, "error": f"Backup file not found: {backup_file}"}
    
    if not output_tar.endswith(".tar"):
        output_tar += ".tar"
    
    output_path = Path(output_tar)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    try:
        with open(backup_file, "rb") as f:
            # Read and parse header
            header_line = f.readline()
            if not header_line.startswith(b"ANDROID BACKUP"):
                return {"success": False, "error": "Invalid backup file format"}
            
            version = f.readline().decode().strip()
            compressed = f.readline().decode().strip()
            encryption = f.readline().decode().strip()
            
            is_encrypted = encryption != "none"
            is_compressed = compressed == "1"
            
            if is_encrypted and not password:
                return {
                    "success": False,
                    "error": "Backup is encrypted but no password provided",
                    "encryption_type": encryption
                }
            
            # Read the actual backup data
            data = f.read()
            
            if is_encrypted:
                data = _decrypt_backup_data(data, password)
            
            if is_compressed:
                data = zlib.decompress(data)
            
            # Write TAR file
            with open(output_tar, "wb") as tar_file:
                tar_file.write(data)
            
            tar_hash = calculate_file_hash(output_path)
            
            return {
                "success": True,
                "input_file": backup_file,
                "output_file": str(output_path.absolute()),
                "file_size_bytes": output_path.stat().st_size,
                "sha256_hash": tar_hash,
                "was_encrypted": is_encrypted,
                "was_compressed": is_compressed,
                "backup_version": version,
                "timestamp": datetime.now().isoformat()
            }
    
    except Exception as e:
        return {"success": False, "error": f"Extraction failed: {str(e)}"}


def _decrypt_backup_data(data: bytes, password: str) -> bytes:
    """Decrypt Android backup data using provided password"""
    # Parse encryption metadata
    user_salt = data[:64]
    checksum_salt = data[64:128]
    rounds = struct.unpack(">I", data[128:132])[0]
    user_iv = data[132:148]
    master_key_blob = data[148:246]
    
    # Derive key from password using PBKDF2
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
    
    # Remove PKCS7 padding
    padding_length = master_key[-1]
    master_key = master_key[:-padding_length]
    
    # Extract actual key and IV from master key
    key = master_key[:32]
    iv = master_key[32:48]
    
    # Decrypt backup data
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
def collect_common_artifacts(
    output_dir: str,
    device_id: Optional[str] = None,
    case_id: Optional[str] = None
) -> dict[str, Any]:
    """
    Collect common forensic artifacts from Android device.
    Automatically pulls databases, logs, and configuration files.
    
    Args:
        output_dir: Output directory for collected artifacts
        device_id: Optional device serial number
        case_id: Optional case identifier for metadata
    """
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    
    # Define common artifact locations
    artifact_paths = {
        # Communication artifacts
        "contacts_db": "/data/data/com.android.providers.contacts/databases/contacts2.db",
        "calllog_db": "/data/data/com.android.providers.contacts/databases/calllog.db",
        "sms_db": "/data/data/com.android.providers.telephony/databases/mmssms.db",
        
        # Browser history
        "chrome_history": "/data/data/com.android.chrome/app_chrome/Default/History",
        "browser_db": "/data/data/com.android.browser/databases/browser2.db",
        
        # System artifacts
        "accounts_db": "/data/system/accounts.db",
        "wifi_config": "/data/misc/wifi/wpa_supplicant.conf",
        "wifi_config_new": "/data/misc/wifi/WifiConfigStore.xml",
        
        # Location data
        "location_db": "/data/data/com.google.android.gms/databases/herrevad",
        
        # User data
        "calendar_db": "/data/data/com.android.providers.calendar/databases/calendar.db",
        "media_db": "/data/data/com.android.providers.media/databases/external.db",
        
        # App-specific
        "whatsapp_db": "/data/data/com.whatsapp/databases/msgstore.db",
        "whatsapp_contacts": "/data/data/com.whatsapp/databases/wa.db",
        "telegram_db": "/data/data/org.telegram.messenger/files/cache4.db",
        
        # System logs
        "dropbox": "/data/system/dropbox",
        "bugreport": "/data/user_de/0/com.android.shell/files/bugreports",
    }
    
    collected = []
    errors = []
    prefix = ["-s", device_id] if device_id else []
    
    for artifact_name, remote_path in artifact_paths.items():
        local_artifact_path = output_path / artifact_name
        
        # Try to pull the artifact
        args = prefix + ["pull", remote_path, str(local_artifact_path)]
        result = execute_adb_command(args, timeout=120)
        
        if local_artifact_path.exists():
            if local_artifact_path.is_file():
                file_hash = calculate_file_hash(local_artifact_path)
                size = local_artifact_path.stat().st_size
            else:
                file_hash = calculate_directory_hash(local_artifact_path)
                size = sum(f.stat().st_size for f in local_artifact_path.rglob("*") if f.is_file())
            
            collected.append({
                "name": artifact_name,
                "remote_path": remote_path,
                "local_path": str(local_artifact_path),
                "size_bytes": size,
                "sha256_hash": file_hash
            })
        else:
            errors.append({
                "name": artifact_name,
                "remote_path": remote_path,
                "error": "Failed to pull - may require root access"
            })
    
    # Collect logcat
    logcat_result = execute_adb_command(prefix + ["logcat", "-d"], timeout=60)
    if logcat_result["success"]:
        logcat_file = output_path / "logcat.txt"
        with open(logcat_file, "w") as f:
            f.write(logcat_result["stdout"])
        collected.append({
            "name": "logcat",
            "local_path": str(logcat_file),
            "size_bytes": logcat_file.stat().st_size
        })
    
    # Collect bugreport
    bugreport_file = output_path / "bugreport.zip"
    bugreport_result = execute_adb_command(
        prefix + ["bugreport", str(bugreport_file)],
        timeout=300
    )
    if bugreport_file.exists():
        collected.append({
            "name": "bugreport",
            "local_path": str(bugreport_file),
            "size_bytes": bugreport_file.stat().st_size,
            "sha256_hash": calculate_file_hash(bugreport_file)
        })
    
    # Create metadata
    metadata = AcquisitionMetadata(
        device_serial=device_id,
        case_id=case_id,
        acquisition_type="common_artifacts",
        destination_path=str(output_path.absolute()),
        file_count=len(collected),
        total_size_bytes=sum(a.get("size_bytes", 0) for a in collected)
    )
    
    metadata_file = output_path / "acquisition_metadata.json"
    with open(metadata_file, "w") as f:
        json.dump({
            "metadata": metadata.model_dump(),
            "collected_artifacts": collected,
            "errors": errors
        }, f, indent=2)
    
    return {
        "success": True,
        "output_directory": str(output_path.absolute()),
        "artifacts_collected": len(collected),
        "artifacts_failed": len(errors),
        "collected": collected,
        "errors": errors,
        "metadata_file": str(metadata_file),
        "timestamp": datetime.now().isoformat(),
        "note": "Some artifacts require root access. Check errors for details."
    }


@mcp.tool()
def dump_database(
    remote_db_path: str,
    output_path: str,
    device_id: Optional[str] = None,
    dump_schema: bool = True,
    dump_data: bool = True
) -> dict[str, Any]:
    """
    Dump SQLite database content from device.
    Exports both schema and data in readable format.
    
    Args:
        remote_db_path: Path to database on device
        output_path: Local output directory
        device_id: Optional device serial number
        dump_schema: Include schema in dump
        dump_data: Include data in dump
    """
    output_dir = Path(output_path)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    prefix = ["-s", device_id] if device_id else []
    db_name = Path(remote_db_path).stem
    
    results = {"success": True, "database": db_name, "files": []}
    
    # Pull the original database file
    local_db = output_dir / f"{db_name}.db"
    pull_result = execute_adb_command(
        prefix + ["pull", remote_db_path, str(local_db)],
        timeout=120
    )
    
    if local_db.exists():
        results["files"].append({
            "type": "database",
            "path": str(local_db),
            "sha256": calculate_file_hash(local_db)
        })
    
    # Dump schema
    if dump_schema:
        schema_result = execute_adb_command(
            prefix + ["shell", f"sqlite3 {remote_db_path} '.schema'"],
            timeout=60
        )
        if schema_result["success"]:
            schema_file = output_dir / f"{db_name}_schema.sql"
            with open(schema_file, "w") as f:
                f.write(schema_result["stdout"])
            results["files"].append({"type": "schema", "path": str(schema_file)})
    
    # Dump data as CSV for each table
    if dump_data:
        tables_result = execute_adb_command(
            prefix + ["shell", f"sqlite3 {remote_db_path} '.tables'"],
            timeout=30
        )
        if tables_result["success"]:
            tables = tables_result["stdout"].split()
            for table in tables:
                csv_result = execute_adb_command(
                    prefix + ["shell", f"sqlite3 -header -csv {remote_db_path} 'SELECT * FROM {table}'"],
                    timeout=120
                )
                if csv_result["success"] and csv_result["stdout"].strip():
                    csv_file = output_dir / f"{db_name}_{table}.csv"
                    with open(csv_file, "w") as f:
                        f.write(csv_result["stdout"])
                    results["files"].append({"type": "table_data", "table": table, "path": str(csv_file)})
    
    results["output_directory"] = str(output_dir.absolute())
    results["timestamp"] = datetime.now().isoformat()
    
    return results


def main():
    """Run the Data Acquisition MCP server"""
    mcp.run()


if __name__ == "__main__":
    main()
