"""
FIA Android Forensics Framework - Digital Investigation Console
Federal Investigation Agency - Digital Forensics Unit

Classification: Official Use Only
Version: 2.2.0
"""

import json
import os
import subprocess
import re
import shutil
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import gradio as gr
from dotenv import load_dotenv

import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

load_dotenv()

# Configuration
OUTPUT_DIR = Path(os.getenv("OUTPUT_DIR", "./output"))
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
REPORTS_DIR = OUTPUT_DIR / "reports"
REPORTS_DIR.mkdir(parents=True, exist_ok=True)

# Find ADB executable
def find_adb() -> str:
    """Locate ADB executable."""
    # Check common locations
    locations = [
        Path(__file__).parent.parent / "adb.exe",
        Path(__file__).parent.parent / "adb",
        Path("./adb.exe"),
        Path("./adb"),
    ]
    
    for loc in locations:
        if loc.exists():
            return str(loc.absolute())
    
    # Check if in PATH
    adb_path = shutil.which("adb")
    if adb_path:
        return adb_path
    
    # Check platform-tools
    platform_tools = Path(os.environ.get("LOCALAPPDATA", "")) / "Android/Sdk/platform-tools/adb.exe"
    if platform_tools.exists():
        return str(platform_tools)
    
    return "adb"  # Fallback

ADB_PATH = find_adb()


class ADBExecutor:
    """Direct ADB command executor for forensic operations."""
    
    @staticmethod
    def run_command(command: str, timeout: int = 30) -> Dict[str, Any]:
        """Execute an ADB command and return results."""
        try:
            if command.strip().lower().startswith("adb "):
                cmd_parts = [ADB_PATH] + command.strip().split()[1:]
            else:
                cmd_parts = [ADB_PATH, "shell"] + command.strip().split()
            
            result = subprocess.run(
                cmd_parts,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=Path(__file__).parent.parent
            )
            
            return {
                "success": result.returncode == 0,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "command": " ".join(cmd_parts)
            }
        except subprocess.TimeoutExpired:
            return {"success": False, "error": "Command timed out", "command": command}
        except Exception as e:
            return {"success": False, "error": str(e), "command": command}
    
    @staticmethod
    def get_device_info() -> Dict[str, Any]:
        """Get comprehensive device information."""
        info = {}
        props = [
            ("manufacturer", "ro.product.manufacturer"),
            ("model", "ro.product.model"),
            ("brand", "ro.product.brand"),
            ("device", "ro.product.device"),
            ("android_version", "ro.build.version.release"),
            ("sdk_version", "ro.build.version.sdk"),
            ("build_id", "ro.build.id"),
            ("security_patch", "ro.build.version.security_patch"),
            ("serial", "ro.serialno"),
            ("hardware", "ro.hardware"),
            ("bootloader", "ro.bootloader"),
            ("baseband", "gsm.version.baseband"),
            ("fingerprint", "ro.build.fingerprint"),
            ("imei", "persist.radio.imei"),
        ]
        
        for key, prop in props:
            result = ADBExecutor.run_command(f"adb shell getprop {prop}", timeout=5)
            if result["success"]:
                info[key] = result["stdout"].strip() or "N/A"
            else:
                info[key] = "N/A"
        
        result = ADBExecutor.run_command("adb get-serialno", timeout=5)
        if result["success"]:
            info["device_id"] = result["stdout"].strip()
        
        return info
    
    @staticmethod
    def get_installed_packages() -> List[Dict[str, str]]:
        """Get list of installed packages."""
        result = ADBExecutor.run_command("adb shell pm list packages -f", timeout=60)
        packages = []
        
        if result["success"]:
            for line in result["stdout"].strip().split("\n"):
                if line.startswith("package:"):
                    match = re.match(r"package:(.+)=(.+)", line)
                    if match:
                        packages.append({
                            "path": match.group(1),
                            "package": match.group(2)
                        })
                    else:
                        pkg = line.replace("package:", "").strip()
                        packages.append({"package": pkg, "path": ""})
        
        return packages
    
    @staticmethod
    def get_logcat(lines: int = 500) -> str:
        result = ADBExecutor.run_command(f"adb logcat -d -t {lines}", timeout=30)
        return result["stdout"] if result["success"] else f"Error: {result.get('error', 'Unknown')}"
    
    @staticmethod
    def get_contacts() -> str:
        result = ADBExecutor.run_command(
            "adb shell content query --uri content://contacts/phones/",
            timeout=30
        )
        return result["stdout"] if result["success"] else f"Error: {result.get('error', 'Permission denied or not available')}"
    
    @staticmethod
    def get_call_log() -> str:
        result = ADBExecutor.run_command(
            "adb shell content query --uri content://call_log/calls/",
            timeout=30
        )
        return result["stdout"] if result["success"] else f"Error: {result.get('error', 'Permission denied or not available')}"
    
    @staticmethod
    def get_sms() -> str:
        result = ADBExecutor.run_command(
            "adb shell content query --uri content://sms/",
            timeout=30
        )
        return result["stdout"] if result["success"] else f"Error: {result.get('error', 'Permission denied or not available')}"
    
    @staticmethod  
    def get_battery_info() -> str:
        result = ADBExecutor.run_command("adb shell dumpsys battery", timeout=10)
        return result["stdout"] if result["success"] else f"Error: {result.get('error', 'Unknown')}"
    
    @staticmethod
    def get_network_info() -> str:
        result = ADBExecutor.run_command("adb shell dumpsys connectivity", timeout=15)
        return result["stdout"] if result["success"] else f"Error: {result.get('error', 'Unknown')}"
    
    @staticmethod
    def get_storage_info() -> str:
        result = ADBExecutor.run_command("adb shell df -h", timeout=10)
        return result["stdout"] if result["success"] else f"Error: {result.get('error', 'Unknown')}"
    
    @staticmethod
    def get_running_processes() -> str:
        result = ADBExecutor.run_command("adb shell ps -A", timeout=15)
        return result["stdout"] if result["success"] else f"Error: {result.get('error', 'Unknown')}"
    
    @staticmethod
    def pull_file(remote_path: str, local_path: str = None) -> Dict[str, Any]:
        if not local_path:
            local_path = str(OUTPUT_DIR / Path(remote_path).name)
        
        result = subprocess.run(
            [ADB_PATH, "pull", remote_path, local_path],
            capture_output=True,
            text=True,
            timeout=120,
            cwd=Path(__file__).parent.parent
        )
        
        return {
            "success": result.returncode == 0,
            "local_path": local_path if result.returncode == 0 else None,
            "message": result.stdout + result.stderr
        }


class DeviceMonitor:
    """Android device connection monitoring."""
    
    def __init__(self):
        self.connected = False
        self.device_info = {}
        self.last_check = None
    
    def check_adb(self) -> bool:
        try:
            result = subprocess.run(
                [ADB_PATH, "version"],
                capture_output=True, text=True, timeout=5,
                cwd=Path(__file__).parent.parent
            )
            return result.returncode == 0
        except Exception:
            return False
    
    def get_connected_devices(self) -> List[Dict]:
        try:
            result = subprocess.run(
                [ADB_PATH, "devices", "-l"],
                capture_output=True, text=True, timeout=10,
                cwd=Path(__file__).parent.parent
            )
            
            devices = []
            for line in result.stdout.strip().split("\n")[1:]:
                if line.strip() and "device" in line and "devices" not in line:
                    parts = line.split()
                    if len(parts) >= 2:
                        device_id = parts[0]
                        model = "Unknown"
                        for part in parts:
                            if part.startswith("model:"):
                                model = part.split(":")[1]
                        devices.append({"id": device_id, "model": model})
            
            return devices
        except Exception as e:
            print(f"Device enumeration error: {e}")
            return []
    
    def refresh_status(self) -> Dict:
        self.last_check = datetime.now()
        
        if not self.check_adb():
            return {"adb_available": False, "connected": False}
        
        devices = self.get_connected_devices()
        if not devices:
            return {"adb_available": True, "connected": False}
        
        self.connected = True
        self.device_info = ADBExecutor.get_device_info()
        self.device_info["device_id"] = devices[0]["id"]
        
        return {
            "adb_available": True,
            "connected": True,
            "device_info": self.device_info,
            "device_count": len(devices)
        }


class ForensicSession:
    """Forensic investigation session manager."""
    
    def __init__(self):
        self.device_monitor = DeviceMonitor()
        self.case = None
        self.artifacts = {}
        self.audit_log = []
        self.llm = None
        self.llm_available = False
    
    def log(self, message: str, level: str = "INFO", action: str = None):
        entry = {
            "timestamp": datetime.now().isoformat(),
            "time": datetime.now().strftime("%H:%M:%S"),
            "level": level,
            "action": action or "",
            "message": message
        }
        self.audit_log.append(entry)
        return entry
    
    def get_audit_text(self) -> str:
        lines = []
        for e in self.audit_log[-50:]:
            action = f"[{e['action']}] " if e['action'] else ""
            lines.append(f"{e['time']} {e['level']:7} {action}{e['message']}")
        return "\n".join(lines) if lines else "No audit entries"
    
    def init_llm(self) -> bool:
        try:
            from langchain_openai import ChatOpenAI
            
            api_key = os.getenv("XAI_API_KEY")
            if not api_key:
                self.log("XAI_API_KEY not configured", "WARNING")
                return False
            
            self.llm = ChatOpenAI(
                model=os.getenv("XAI_MODEL", "grok-4-latest"),
                api_key=api_key,
                base_url=os.getenv("XAI_BASE_URL", "https://api.x.ai/v1"),
                temperature=0.1,
            )
            self.llm_available = True
            self.log("AI Assistant initialized (xAI Grok)", "INFO", "LLM_INIT")
            return True
        except Exception as e:
            self.log(f"AI initialization failed: {e}", "WARNING")
            return False
    
    def start_case(self, case_number: str = "", examiner: str = "", 
                   agency: str = "", notes: str = "") -> Dict:
        self.case = {
            "case_number": case_number or f"FIA-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
            "examiner": examiner or os.getenv("INVESTIGATOR_NAME", "Examiner"),
            "agency": agency or "Federal Investigation Agency",
            "start_time": datetime.now().isoformat(),
            "notes": notes,
            "status": "ACTIVE"
        }
        self.artifacts = {}
        self.audit_log = []
        self.log(f"Case initiated: {self.case['case_number']}", "INFO", "CASE_OPENED")
        return self.case
    
    def add_artifact(self, name: str, data: Any, artifact_type: str = "text"):
        self.artifacts[name] = {
            "data": data,
            "type": artifact_type,
            "collected_at": datetime.now().isoformat()
        }
        self.log(f"Artifact acquired: {name}", "INFO", "ARTIFACT")
    
    def process_command(self, user_input: str) -> str:
        if not user_input.strip():
            return "Please enter a command or query."
        
        self.log(f"Command: {user_input[:80]}", "INFO", "USER_INPUT")
        
        # Direct ADB command
        if user_input.strip().lower().startswith("adb "):
            return self._execute_adb(user_input.strip())
        
        lower_input = user_input.lower()
        
        if any(k in lower_input for k in ["device info", "device information", "device status", "identify device"]):
            return self._get_device_info()
        
        if any(k in lower_input for k in ["installed apps", "installed packages", "list apps", "applications"]):
            return self._get_installed_apps()
        
        if any(k in lower_input for k in ["logcat", "system log", "logs"]):
            return self._get_logcat()
        
        if any(k in lower_input for k in ["contacts", "address book", "phone book"]):
            return self._get_contacts()
        
        if any(k in lower_input for k in ["call log", "call history", "calls"]):
            return self._get_call_log()
        
        if any(k in lower_input for k in ["sms", "messages", "text messages"]):
            return self._get_sms()
        
        if any(k in lower_input for k in ["battery", "power"]):
            return self._get_battery()
        
        if any(k in lower_input for k in ["storage", "disk", "memory usage"]):
            return self._get_storage()
        
        if any(k in lower_input for k in ["network", "wifi", "connectivity"]):
            return self._get_network()
        
        if any(k in lower_input for k in ["processes", "running apps", "running processes"]):
            return self._get_processes()
        
        if any(k in lower_input for k in ["pull ", "extract ", "download "]):
            match = re.search(r'(?:pull|extract|download)\s+([^\s]+)', lower_input)
            if match:
                return self._pull_file(match.group(1))
        
        if self.llm_available or self.init_llm():
            return self._query_llm(user_input)
        
        return self._help_message()
    
    def _execute_adb(self, command: str) -> str:
        self.log(f"Executing: {command}", "INFO", "ADB_EXEC")
        result = ADBExecutor.run_command(command)
        
        if result["success"]:
            output = result["stdout"] or "Command executed successfully (no output)"
            self.add_artifact(f"cmd_{datetime.now().strftime('%H%M%S')}", output, "command_output")
            return f"**Command:** `{command}`\n\n**Output:**\n```\n{output[:5000]}\n```"
        else:
            error = result.get("error") or result.get("stderr", "Unknown error")
            return f"**Command:** `{command}`\n\n**Error:**\n```\n{error}\n```"
    
    def _get_device_info(self) -> str:
        self.log("Acquiring device information", "INFO", "DEVICE_INFO")
        info = ADBExecutor.get_device_info()
        self.add_artifact("device_info", info, "device")
        
        md = "## DEVICE IDENTIFICATION\n\n"
        md += "| Property | Value |\n|----------|-------|\n"
        for key, value in info.items():
            md += f"| {key.replace('_', ' ').title()} | {value} |\n"
        
        return md
    
    def _get_installed_apps(self) -> str:
        self.log("Acquiring installed packages", "INFO", "PACKAGES")
        packages = ADBExecutor.get_installed_packages()
        self.add_artifact("installed_packages", packages, "packages")
        
        md = f"## INSTALLED APPLICATIONS\n\n**Total Packages:** {len(packages)}\n\n"
        md += "| Package Name | Installation Path |\n|--------------|-------------------|\n"
        for pkg in packages[:100]:
            md += f"| {pkg['package']} | {pkg.get('path', '')[:50]} |\n"
        
        if len(packages) > 100:
            md += f"\n*Additional {len(packages) - 100} packages not displayed*"
        
        return md
    
    def _get_logcat(self) -> str:
        self.log("Extracting system logs", "INFO", "LOGCAT")
        logs = ADBExecutor.get_logcat(200)
        self.add_artifact("logcat", logs, "logs")
        
        return f"## SYSTEM LOGS\n\n**Entries:** Last 200\n\n```\n{logs[:8000]}\n```"
    
    def _get_contacts(self) -> str:
        self.log("Extracting contacts", "INFO", "CONTACTS")
        contacts = ADBExecutor.get_contacts()
        self.add_artifact("contacts", contacts, "contacts")
        
        return f"## CONTACTS DATABASE\n\n```\n{contacts[:5000]}\n```"
    
    def _get_call_log(self) -> str:
        self.log("Extracting call records", "INFO", "CALL_LOG")
        calls = ADBExecutor.get_call_log()
        self.add_artifact("call_log", calls, "calls")
        
        return f"## CALL RECORDS\n\n```\n{calls[:5000]}\n```"
    
    def _get_sms(self) -> str:
        self.log("Extracting SMS messages", "INFO", "SMS")
        sms = ADBExecutor.get_sms()
        self.add_artifact("sms", sms, "messages")
        
        return f"## SMS MESSAGES\n\n```\n{sms[:5000]}\n```"
    
    def _get_battery(self) -> str:
        self.log("Acquiring battery status", "INFO", "BATTERY")
        battery = ADBExecutor.get_battery_info()
        self.add_artifact("battery", battery, "system")
        
        return f"## BATTERY STATUS\n\n```\n{battery}\n```"
    
    def _get_storage(self) -> str:
        self.log("Acquiring storage information", "INFO", "STORAGE")
        storage = ADBExecutor.get_storage_info()
        self.add_artifact("storage", storage, "system")
        
        return f"## STORAGE INFORMATION\n\n```\n{storage}\n```"
    
    def _get_network(self) -> str:
        self.log("Acquiring network configuration", "INFO", "NETWORK")
        network = ADBExecutor.get_network_info()
        self.add_artifact("network", network[:3000], "system")
        
        return f"## NETWORK CONFIGURATION\n\n```\n{network[:5000]}\n```"
    
    def _get_processes(self) -> str:
        self.log("Acquiring running processes", "INFO", "PROCESSES")
        procs = ADBExecutor.get_running_processes()
        self.add_artifact("processes", procs, "system")
        
        return f"## RUNNING PROCESSES\n\n```\n{procs[:8000]}\n```"
    
    def _pull_file(self, remote_path: str) -> str:
        self.log(f"Extracting file: {remote_path}", "INFO", "PULL_FILE")
        result = ADBExecutor.pull_file(remote_path)
        
        if result["success"]:
            self.add_artifact(f"file_{Path(remote_path).name}", result["local_path"], "file")
            return f"## FILE EXTRACTION COMPLETE\n\n**Source:** `{remote_path}`\n\n**Destination:** `{result['local_path']}`"
        else:
            return f"## FILE EXTRACTION FAILED\n\n**Path:** `{remote_path}`\n\n**Error:** {result['message']}"
    
    def _query_llm(self, query: str) -> str:
        try:
            from langchain_core.messages import HumanMessage, SystemMessage
            
            system_prompt = """You are a digital forensics specialist assisting law enforcement. Provide professional guidance for Android device investigations.
            
Available acquisition commands:
- device info - Device identification
- installed apps - Application inventory
- logcat - System logs
- contacts - Contact database
- call log - Call records
- sms - Text messages
- battery - Battery status
- storage - Storage information
- network - Network configuration
- processes - Running processes
- adb shell <command> - Direct shell command
- pull <path> - File extraction

Provide concise, professional responses."""
            
            messages = [
                SystemMessage(content=system_prompt),
                HumanMessage(content=query)
            ]
            
            response = self.llm.invoke(messages)
            return response.content if hasattr(response, "content") else str(response)
            
        except Exception as e:
            self.log(f"AI query failed: {e}", "ERROR")
            return self._help_message()
    
    def _help_message(self) -> str:
        return """## COMMAND REFERENCE

### Data Acquisition Commands
| Command | Description |
|---------|-------------|
| device info | Device identification and properties |
| installed apps | Complete application inventory |
| logcat | System log extraction |
| contacts | Contact database extraction |
| call log | Call history records |
| sms | Text message extraction |
| battery | Battery status |
| storage | Storage partition information |
| network | Network configuration |
| processes | Active process list |

### Direct ADB Commands
| Command | Description |
|---------|-------------|
| adb shell <command> | Execute shell command |
| adb pull <path> | Extract file from device |

### Examples
- `device info`
- `adb shell ls /sdcard/`
- `adb pull /sdcard/DCIM/photo.jpg`
"""
    
    def generate_report(self, format: str = "md") -> Tuple[str, str]:
        if not self.case:
            return None, "No active case"
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{self.case['case_number']}_report_{timestamp}"
        
        if format == "html":
            content = self._generate_html_report()
            filepath = REPORTS_DIR / f"{filename}.html"
        else:
            content = self._generate_md_report()
            filepath = REPORTS_DIR / f"{filename}.md"
        
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(content)
        
        self.log(f"Report generated: {filepath}", "INFO", "REPORT")
        return str(filepath), content
    
    def _generate_md_report(self) -> str:
        report = f"""# DIGITAL FORENSICS INVESTIGATION REPORT

## CLASSIFICATION: OFFICIAL USE ONLY

---

## CASE INFORMATION

| Field | Value |
|-------|-------|
| Case Number | {self.case['case_number']} |
| Examiner | {self.case['examiner']} |
| Agency | {self.case['agency']} |
| Investigation Started | {self.case['start_time']} |
| Report Generated | {datetime.now().isoformat()} |
| Case Notes | {self.case.get('notes', 'N/A')} |

---

## DEVICE INFORMATION

"""
        if "device_info" in self.artifacts:
            info = self.artifacts["device_info"]["data"]
            report += "| Property | Value |\n|----------|-------|\n"
            for key, value in info.items():
                report += f"| {key.replace('_', ' ').title()} | {value} |\n"
        else:
            report += "*Device information not acquired*\n"
        
        report += "\n---\n\n## ACQUIRED EVIDENCE\n\n"
        
        for name, artifact in self.artifacts.items():
            report += f"### {name.replace('_', ' ').upper()}\n\n"
            report += f"**Classification:** {artifact['type']}  \n"
            report += f"**Acquisition Time:** {artifact['collected_at']}\n\n"
            
            data = artifact["data"]
            if isinstance(data, dict):
                report += "```json\n" + json.dumps(data, indent=2, default=str)[:3000] + "\n```\n\n"
            elif isinstance(data, list):
                report += f"*{len(data)} items acquired*\n\n"
            else:
                report += f"```\n{str(data)[:2000]}\n```\n\n"
        
        report += "---\n\n## CHAIN OF CUSTODY - AUDIT LOG\n\n"
        report += "| Timestamp | Level | Action | Details |\n|-----------|-------|--------|--------|\n"
        for entry in self.audit_log:
            report += f"| {entry['time']} | {entry['level']} | {entry['action']} | {entry['message'][:50]} |\n"
        
        report += f"\n---\n\n**Report generated by FIA Digital Forensics Framework v2.2.0**\n\n"
        report += "*This document contains sensitive law enforcement information and is intended for official use only.*\n"
        
        return report
    
    def _generate_html_report(self) -> str:
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Forensic Report - {self.case['case_number']}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, sans-serif;
            background: #f8f9fa;
            color: #212529;
            line-height: 1.6;
        }}
        .container {{ max-width: 1100px; margin: 0 auto; padding: 40px; }}
        .header {{
            background: linear-gradient(135deg, #1a365d 0%, #2d3748 100%);
            color: white;
            padding: 40px;
            margin-bottom: 30px;
            border-bottom: 4px solid #c53030;
        }}
        .header h1 {{ font-size: 1.8rem; margin-bottom: 8px; letter-spacing: 1px; }}
        .header .agency {{ font-size: 1rem; opacity: 0.9; }}
        .classification {{
            background: #c53030;
            color: white;
            padding: 8px 20px;
            display: inline-block;
            font-weight: 600;
            font-size: 0.85rem;
            letter-spacing: 2px;
            margin-top: 20px;
        }}
        .section {{
            background: white;
            border: 1px solid #e2e8f0;
            margin-bottom: 24px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }}
        .section-header {{
            background: #2d3748;
            color: white;
            padding: 12px 20px;
            font-weight: 600;
            font-size: 0.9rem;
            letter-spacing: 0.5px;
        }}
        .section-content {{ padding: 20px; }}
        table {{
            width: 100%;
            border-collapse: collapse;
        }}
        th, td {{
            padding: 12px 16px;
            text-align: left;
            border-bottom: 1px solid #e2e8f0;
            font-size: 0.9rem;
        }}
        th {{
            background: #f7fafc;
            color: #4a5568;
            font-weight: 600;
            text-transform: uppercase;
            font-size: 0.75rem;
            letter-spacing: 0.5px;
        }}
        tr:hover {{ background: #f7fafc; }}
        pre {{
            background: #1a202c;
            color: #e2e8f0;
            padding: 16px;
            overflow-x: auto;
            font-family: 'Consolas', 'Monaco', monospace;
            font-size: 0.85rem;
            border-radius: 4px;
        }}
        .footer {{
            text-align: center;
            color: #718096;
            padding: 30px;
            font-size: 0.85rem;
            border-top: 1px solid #e2e8f0;
            margin-top: 40px;
        }}
        .artifact-meta {{
            background: #f7fafc;
            padding: 10px 16px;
            border-bottom: 1px solid #e2e8f0;
            font-size: 0.85rem;
            color: #4a5568;
        }}
        @media print {{
            body {{ background: white; }}
            .section {{ box-shadow: none; border: 1px solid #ccc; }}
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>DIGITAL FORENSICS INVESTIGATION REPORT</h1>
        <div class="agency">Federal Investigation Agency - Digital Forensics Unit</div>
        <div class="classification">OFFICIAL USE ONLY</div>
    </div>
    
    <div class="container">
        <div class="section">
            <div class="section-header">CASE INFORMATION</div>
            <div class="section-content">
                <table>
                    <tr><th style="width:200px">Case Number</th><td>{self.case['case_number']}</td></tr>
                    <tr><th>Examiner</th><td>{self.case['examiner']}</td></tr>
                    <tr><th>Agency</th><td>{self.case['agency']}</td></tr>
                    <tr><th>Investigation Started</th><td>{self.case['start_time']}</td></tr>
                    <tr><th>Report Generated</th><td>{datetime.now().isoformat()}</td></tr>
                    <tr><th>Case Notes</th><td>{self.case.get('notes', 'N/A')}</td></tr>
                </table>
            </div>
        </div>
"""
        
        if "device_info" in self.artifacts:
            info = self.artifacts["device_info"]["data"]
            html += """
        <div class="section">
            <div class="section-header">DEVICE IDENTIFICATION</div>
            <div class="section-content">
                <table>
"""
            for key, value in info.items():
                html += f"                    <tr><th style='width:200px'>{key.replace('_', ' ').title()}</th><td>{value}</td></tr>\n"
            html += "                </table>\n            </div>\n        </div>\n"
        
        html += """
        <div class="section">
            <div class="section-header">ACQUIRED EVIDENCE</div>
            <div class="section-content">
"""
        for name, artifact in self.artifacts.items():
            html += f"""
                <div style="margin-bottom: 24px;">
                    <h4 style="color: #2d3748; margin-bottom: 8px; text-transform: uppercase; font-size: 0.9rem;">{name.replace('_', ' ')}</h4>
                    <div class="artifact-meta">
                        <strong>Type:</strong> {artifact['type']} | <strong>Acquired:</strong> {artifact['collected_at']}
                    </div>
"""
            data = artifact["data"]
            if isinstance(data, dict):
                html += f"<pre>{json.dumps(data, indent=2, default=str)[:2000]}</pre>\n"
            elif isinstance(data, list):
                html += f"<p style='padding: 16px; color: #4a5568;'><em>{len(data)} items acquired</em></p>\n"
            else:
                html += f"<pre>{str(data)[:1500]}</pre>\n"
            html += "                </div>\n"
        
        html += """
            </div>
        </div>
        
        <div class="section">
            <div class="section-header">CHAIN OF CUSTODY - AUDIT LOG</div>
            <div class="section-content">
                <table>
                    <tr><th>Timestamp</th><th>Level</th><th>Action</th><th>Details</th></tr>
"""
        for entry in self.audit_log:
            html += f"                    <tr><td>{entry['time']}</td><td>{entry['level']}</td><td>{entry['action']}</td><td>{entry['message'][:60]}</td></tr>\n"
        
        html += """                </table>
            </div>
        </div>
        
        <div class="footer">
            <p>Report generated by FIA Digital Forensics Framework v2.2.0</p>
            <p>This document contains sensitive law enforcement information and is intended for official use only.</p>
        </div>
    </div>
</body>
</html>
"""
        return html


# Global session
session = ForensicSession()


def get_device_status():
    """Get device status for UI."""
    status = session.device_monitor.refresh_status()
    
    if not status.get("adb_available"):
        return (
            "STATUS: ADB NOT AVAILABLE",
            "Android Debug Bridge (ADB) not found.\n\nRequired Actions:\n- Install Android Platform Tools\n- Verify ADB installation path",
            gr.update(interactive=False),
            gr.update(interactive=False)
        )
    
    if not status.get("connected"):
        return (
            "STATUS: AWAITING DEVICE CONNECTION",
            "No Android device detected.\n\nRequired Actions:\n- Connect device via USB\n- Enable USB Debugging on device\n- Authorize computer on device prompt",
            gr.update(interactive=False),
            gr.update(interactive=False)
        )
    
    info = status.get("device_info", {})
    text = f"""Manufacturer: {info.get('manufacturer', 'N/A')}
Model: {info.get('model', 'N/A')}
Android Version: {info.get('android_version', 'N/A')}
Serial Number: {info.get('serial', 'N/A')}
Device ID: {info.get('device_id', 'N/A')}
Security Patch: {info.get('security_patch', 'N/A')}

Last Verified: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"""
    
    return (
        "STATUS: DEVICE CONNECTED",
        text,
        gr.update(interactive=True),
        gr.update(interactive=True)
    )


def handle_message(message: str, history: List) -> Tuple[List, str, str]:
    """Handle user message and return response."""
    if not message.strip():
        return history, "", session.get_audit_text()
    
    if not session.case:
        session.start_case()
    
    history = history or []
    response = session.process_command(message)
    
    # Gradio 6.0 requires messages format with role/content dictionaries
    history.append({"role": "user", "content": message})
    history.append({"role": "assistant", "content": response})
    
    return history, "", session.get_audit_text()


def handle_quick_action(action: str, history: List) -> Tuple[List, str, str]:
    """Handle quick action button click."""
    return handle_message(action, history)


def init_case(case_num: str, examiner: str, agency: str, notes: str):
    """Initialize new case."""
    case = session.start_case(case_num, examiner, agency, notes)
    # Return welcome message in Gradio 6.0 format
    initial_message = [{"role": "assistant", "content": f"Case {case['case_number']} initialized. Ready for forensic acquisition."}]
    return (
        initial_message,
        f"Case {case['case_number']} initialized successfully",
        session.get_audit_text()
    )


def generate_report(format_choice: str):
    """Generate and return report for download."""
    fmt = "html" if "HTML" in format_choice else "md"
    filepath, content = session.generate_report(fmt)
    
    if filepath:
        return filepath, f"Report generated: {filepath}"
    return None, "Error: No active case for report generation"


# Professional CSS styling
CUSTOM_CSS = """
    /* Professional Law Enforcement Theme */
    .gradio-container {
        font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, sans-serif !important;
        background: #f0f2f5 !important;
    }
    
    /* Header styling */
    .header-container {
        background: linear-gradient(135deg, #1a365d 0%, #2d3748 100%);
        color: white;
        padding: 24px 32px;
        border-bottom: 3px solid #c53030;
        margin: -16px -16px 24px -16px;
    }
    
    .header-title {
        font-size: 1.4rem;
        font-weight: 600;
        letter-spacing: 0.5px;
        margin: 0;
    }
    
    .header-subtitle {
        font-size: 0.9rem;
        opacity: 0.85;
        margin-top: 4px;
    }
    
    .classification-badge {
        background: #c53030;
        color: white;
        padding: 6px 16px;
        font-size: 0.75rem;
        font-weight: 600;
        letter-spacing: 1.5px;
        display: inline-block;
    }
    
    /* Status panel */
    .status-connected { color: #276749 !important; font-weight: 600; }
    .status-disconnected { color: #c53030 !important; font-weight: 600; }
    
    /* Section headers */
    .section-header {
        font-size: 0.85rem;
        font-weight: 600;
        color: #2d3748;
        text-transform: uppercase;
        letter-spacing: 0.5px;
        padding-bottom: 8px;
        border-bottom: 2px solid #e2e8f0;
        margin-bottom: 16px;
    }
    
    /* Buttons */
    .primary-btn {
        background: #2d3748 !important;
        color: white !important;
        font-weight: 500 !important;
        border: none !important;
    }
    
    .primary-btn:hover {
        background: #1a202c !important;
    }
    
    .secondary-btn {
        background: #e2e8f0 !important;
        color: #2d3748 !important;
        font-weight: 500 !important;
        border: 1px solid #cbd5e0 !important;
    }
    
    /* Chat area */
    .chat-area {
        border: 1px solid #e2e8f0;
        background: white;
    }
    
    /* Audit log */
    .audit-log {
        font-family: 'Consolas', 'Monaco', monospace;
        font-size: 0.8rem;
        background: #1a202c;
        color: #a0aec0;
        padding: 16px;
    }
"""


def create_interface():
    """Create the professional Gradio interface."""
    
    with gr.Blocks(
        title="FIA Digital Forensics"
    ) as interface:
        
        # Professional Header
        gr.HTML("""
        <div style="background: linear-gradient(135deg, #1a365d 0%, #2d3748 100%); padding: 24px 32px; margin: -16px -16px 24px -16px; border-bottom: 3px solid #c53030;">
            <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 16px;">
                <div>
                    <h1 style="color: white; font-size: 1.4rem; font-weight: 600; letter-spacing: 0.5px; margin: 0;">
                        DIGITAL FORENSICS INVESTIGATION CONSOLE
                    </h1>
                    <p style="color: rgba(255,255,255,0.85); font-size: 0.9rem; margin: 4px 0 0;">
                        Federal Investigation Agency | Mobile Device Evidence Acquisition System
                    </p>
                </div>
                <div style="background: #c53030; color: white; padding: 8px 20px; font-size: 0.75rem; font-weight: 600; letter-spacing: 1.5px;">
                    OFFICIAL USE ONLY
                </div>
            </div>
        </div>
        """)
        
        with gr.Row():
            # Left Panel - Control Center
            with gr.Column(scale=1):
                gr.HTML('<div style="font-size: 0.85rem; font-weight: 600; color: #2d3748; text-transform: uppercase; letter-spacing: 0.5px; padding-bottom: 8px; border-bottom: 2px solid #2d3748; margin-bottom: 16px;">DEVICE STATUS</div>')
                
                status_header = gr.Textbox(
                    value="STATUS: CHECKING...",
                    show_label=False,
                    interactive=False,
                    container=False
                )
                device_info = gr.Textbox(
                    value="Verifying device connection...",
                    show_label=False,
                    lines=7,
                    interactive=False
                )
                refresh_btn = gr.Button("REFRESH CONNECTION", variant="secondary", size="sm")
                
                gr.HTML('<div style="font-size: 0.85rem; font-weight: 600; color: #2d3748; text-transform: uppercase; letter-spacing: 0.5px; padding: 24px 0 8px 0; border-bottom: 2px solid #2d3748; margin-bottom: 16px;">CASE MANAGEMENT</div>')
                
                case_num = gr.Textbox(label="Case Number", placeholder="Auto-generated if blank")
                examiner = gr.Textbox(label="Examiner Name", value=os.getenv("INVESTIGATOR_NAME", ""))
                agency = gr.Textbox(label="Agency", value="Federal Investigation Agency")
                notes = gr.Textbox(label="Case Notes", lines=2, placeholder="Enter case-related notes...")
                
                new_case_btn = gr.Button("INITIALIZE NEW CASE", variant="primary", size="sm")
                case_status = gr.Textbox(show_label=False, interactive=False, container=False)
                
                gr.HTML('<div style="font-size: 0.85rem; font-weight: 600; color: #2d3748; text-transform: uppercase; letter-spacing: 0.5px; padding: 24px 0 8px 0; border-bottom: 2px solid #2d3748; margin-bottom: 16px;">REPORT GENERATION</div>')
                
                report_format = gr.Radio(
                    ["Markdown (.md)", "HTML Report (.html)"],
                    label="Export Format",
                    value="Markdown (.md)"
                )
                generate_btn = gr.Button("GENERATE REPORT", variant="secondary")
                report_file = gr.File(label="Download Report", visible=True)
                report_status = gr.Textbox(show_label=False, interactive=False, container=False)
            
            # Right Panel - Investigation Console
            with gr.Column(scale=2):
                gr.HTML('<div style="font-size: 0.85rem; font-weight: 600; color: #2d3748; text-transform: uppercase; letter-spacing: 0.5px; padding-bottom: 8px; border-bottom: 2px solid #2d3748; margin-bottom: 16px;">INVESTIGATION CONSOLE</div>')
                
                chat = gr.Chatbot(
                    height=380,
                    show_label=False,
                    container=True,
                    type="messages"
                )
                
                with gr.Row():
                    msg_input = gr.Textbox(
                        placeholder="Enter acquisition command or query...",
                        show_label=False,
                        scale=5,
                        interactive=False,
                        container=False
                    )
                    send_btn = gr.Button("EXECUTE", variant="primary", scale=1, interactive=False)
                
                gr.HTML('<div style="font-size: 0.85rem; font-weight: 600; color: #2d3748; text-transform: uppercase; letter-spacing: 0.5px; padding: 20px 0 12px 0; margin-bottom: 8px;">QUICK ACQUISITION</div>')
                
                with gr.Row():
                    btn_device = gr.Button("Device Info", size="sm", variant="secondary")
                    btn_apps = gr.Button("Applications", size="sm", variant="secondary")
                    btn_logs = gr.Button("System Logs", size="sm", variant="secondary")
                    btn_procs = gr.Button("Processes", size="sm", variant="secondary")
                
                with gr.Row():
                    btn_contacts = gr.Button("Contacts", size="sm", variant="secondary")
                    btn_calls = gr.Button("Call Records", size="sm", variant="secondary")
                    btn_sms = gr.Button("SMS Messages", size="sm", variant="secondary")
                    btn_storage = gr.Button("Storage", size="sm", variant="secondary")
        
        # Audit Log Section
        gr.HTML('<div style="font-size: 0.85rem; font-weight: 600; color: #2d3748; text-transform: uppercase; letter-spacing: 0.5px; padding: 24px 0 8px 0; border-bottom: 2px solid #2d3748; margin-bottom: 16px;">CHAIN OF CUSTODY - AUDIT LOG</div>')
        
        audit_log = gr.Textbox(
            show_label=False,
            lines=6,
            max_lines=10,
            interactive=False
        )
        
        # Event Handlers
        refresh_btn.click(
            get_device_status,
            outputs=[status_header, device_info, msg_input, send_btn]
        )
        
        new_case_btn.click(
            init_case,
            inputs=[case_num, examiner, agency, notes],
            outputs=[chat, case_status, audit_log]
        )
        
        send_btn.click(
            handle_message,
            inputs=[msg_input, chat],
            outputs=[chat, msg_input, audit_log]
        )
        
        msg_input.submit(
            handle_message,
            inputs=[msg_input, chat],
            outputs=[chat, msg_input, audit_log]
        )
        
        # Quick action handlers
        btn_device.click(lambda h: handle_quick_action("device info", h), inputs=[chat], outputs=[chat, msg_input, audit_log])
        btn_apps.click(lambda h: handle_quick_action("installed apps", h), inputs=[chat], outputs=[chat, msg_input, audit_log])
        btn_logs.click(lambda h: handle_quick_action("logcat", h), inputs=[chat], outputs=[chat, msg_input, audit_log])
        btn_procs.click(lambda h: handle_quick_action("processes", h), inputs=[chat], outputs=[chat, msg_input, audit_log])
        btn_contacts.click(lambda h: handle_quick_action("contacts", h), inputs=[chat], outputs=[chat, msg_input, audit_log])
        btn_calls.click(lambda h: handle_quick_action("call log", h), inputs=[chat], outputs=[chat, msg_input, audit_log])
        btn_sms.click(lambda h: handle_quick_action("sms", h), inputs=[chat], outputs=[chat, msg_input, audit_log])
        btn_storage.click(lambda h: handle_quick_action("storage", h), inputs=[chat], outputs=[chat, msg_input, audit_log])
        
        generate_btn.click(
            generate_report,
            inputs=[report_format],
            outputs=[report_file, report_status]
        )
        
        # Auto-refresh on load
        interface.load(
            get_device_status,
            outputs=[status_header, device_info, msg_input, send_btn]
        )
    
    return interface


def launch(share: bool = False, port: int = 7860):
    """Launch the investigation console."""
    print("""
    ================================================================
         FEDERAL INVESTIGATION AGENCY
         Digital Forensics Investigation Console
    ----------------------------------------------------------------
         Initializing System...
         ADB Path: """ + ADB_PATH + """
    ================================================================
    """)
    
    interface = create_interface()
    interface.launch(
        server_name="127.0.0.1",
        server_port=port,
        share=share,
        show_error=True,
        css=CUSTOM_CSS
    )


if __name__ == "__main__":
    launch()
