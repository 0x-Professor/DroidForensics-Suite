"""
FIA Android Forensics Framework - Digital Investigation Console
Federal Investigation Agency - Digital Forensics Unit

Streamlit-based Professional Interface
Version: 2.3.0
"""

import json
import os
import subprocess
import re
import shutil
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import base64

import streamlit as st
from dotenv import load_dotenv

# Import LangChain for AI features
try:
    from langchain_google_genai import ChatGoogleGenerativeAI
    from langchain_core.messages import HumanMessage, SystemMessage
    AI_AVAILABLE = True
except ImportError:
    AI_AVAILABLE = False

# Import Tavily for web search
try:
    from tavily import TavilyClient
    TAVILY_AVAILABLE = True
except ImportError:
    TAVILY_AVAILABLE = False

# Import for web search fallback
try:
    import requests
    WEB_SEARCH_AVAILABLE = True
except ImportError:
    WEB_SEARCH_AVAILABLE = False

import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

load_dotenv()

# Configuration
OUTPUT_DIR = Path(os.getenv("OUTPUT_DIR", "./output"))
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
REPORTS_DIR = OUTPUT_DIR / "reports"
REPORTS_DIR.mkdir(parents=True, exist_ok=True)


def find_adb() -> str:
    """Locate ADB executable."""
    locations = [
        Path(__file__).parent.parent / "adb.exe",
        Path(__file__).parent.parent / "adb",
        Path("./adb.exe"),
        Path("./adb"),
    ]
    
    for loc in locations:
        if loc.exists():
            return str(loc.absolute())
    
    adb_path = shutil.which("adb")
    if adb_path:
        return adb_path
    
    platform_tools = Path(os.environ.get("LOCALAPPDATA", "")) / "Android/Sdk/platform-tools/adb.exe"
    if platform_tools.exists():
        return str(platform_tools)
    
    return "adb"

ADB_PATH = find_adb()


class ADBExecutor:
    """Direct ADB command executor for forensic operations."""
    
    @staticmethod
    def run_command(command: str, timeout: int = 30) -> Dict[str, Any]:
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
        if result["success"] and result.get("stdout"):
            return result["stdout"]
        return f"Error: {result.get('error', result.get('stderr', 'Permission denied or no data available'))}"
    
    @staticmethod
    def get_call_log() -> str:
        result = ADBExecutor.run_command(
            "adb shell content query --uri content://call_log/calls/",
            timeout=30
        )
        if result["success"] and result.get("stdout"):
            return result["stdout"]
        return f"Error: {result.get('error', result.get('stderr', 'Permission denied or no data available'))}"
    
    @staticmethod
    def get_sms() -> str:
        result = ADBExecutor.run_command(
            "adb shell content query --uri content://sms/",
            timeout=30
        )
        if result["success"] and result.get("stdout"):
            return result["stdout"]
        return f"Error: {result.get('error', result.get('stderr', 'Permission denied or no data available'))}"
    
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
    
    @staticmethod
    def get_images_list() -> str:
        """List images on the device."""
        # Search common image locations
        locations = [
            "/sdcard/DCIM/",
            "/sdcard/Pictures/",
            "/sdcard/Download/",
            "/storage/emulated/0/DCIM/",
            "/storage/emulated/0/Pictures/"
        ]
        
        all_images = []
        for loc in locations:
            result = ADBExecutor.run_command(
                f'adb shell find {loc} -type f \\( -name "*.jpg" -o -name "*.jpeg" -o -name "*.png" -o -name "*.gif" -o -name "*.webp" \\) 2>/dev/null',
                timeout=30
            )
            if result["success"] and result.get("stdout"):
                images = [f.strip() for f in result["stdout"].strip().split("\n") if f.strip()]
                all_images.extend(images)
        
        if all_images:
            return f"Found {len(all_images)} images:\n" + "\n".join(all_images[:100])
        return "No images found or permission denied"
    
    @staticmethod
    def pull_images(dest_folder: str = None) -> Dict[str, Any]:
        """Pull images from device to local folder."""
        if not dest_folder:
            dest_folder = str(OUTPUT_DIR / "images" / datetime.now().strftime("%Y%m%d_%H%M%S"))
        
        Path(dest_folder).mkdir(parents=True, exist_ok=True)
        
        # Get list of images
        locations = ["/sdcard/DCIM/", "/sdcard/Pictures/"]
        pulled = []
        errors = []
        
        for loc in locations:
            result = subprocess.run(
                [ADB_PATH, "pull", loc, dest_folder],
                capture_output=True,
                text=True,
                timeout=300,
                cwd=Path(__file__).parent.parent
            )
            if result.returncode == 0:
                pulled.append(f"Pulled {loc}")
            else:
                errors.append(f"Failed {loc}: {result.stderr[:100]}")
        
        return {
            "success": len(pulled) > 0,
            "dest_folder": dest_folder,
            "pulled": pulled,
            "errors": errors,
            "message": f"Pulled from {len(pulled)} locations to {dest_folder}"
        }


# ========== AI INVESTIGATION PLANNER ==========

class InvestigationPlanner:
    """AI-powered investigation planner using LangChain and Gemini."""
    
    AVAILABLE_COMMANDS = {
        "device_info": "Get device identification and properties",
        "installed_apps": "Get complete application inventory",
        "logcat": "Extract system logs",
        "contacts": "Extract contact database",
        "call_log": "Extract call history records",
        "sms": "Extract text messages",
        "battery": "Get battery status",
        "storage": "Get storage partition information",
        "network": "Get network configuration",
        "processes": "Get active process list",
        "adb_shell": "Execute custom ADB shell command"
    }
    
    @staticmethod
    def is_available() -> bool:
        """Check if AI planning is available."""
        return AI_AVAILABLE and os.getenv("GEMINI_API_KEY")
    
    @staticmethod
    def create_investigation_plan(user_request: str) -> Optional[Dict]:
        """
        Analyze user request and create an investigation plan.
        Returns a plan with steps to execute.
        """
        if not InvestigationPlanner.is_available():
            return None
        
        try:
            llm = ChatGoogleGenerativeAI(
                model="gemini-2.0-flash",
                google_api_key=os.getenv("GEMINI_API_KEY"),
                temperature=0.1
            )
            
            system_prompt = f"""You are an expert Android forensics investigator assistant. 
Your task is to analyze user investigation requests and create structured execution plans.

Available forensic commands:
{json.dumps(InvestigationPlanner.AVAILABLE_COMMANDS, indent=2)}

For ADB shell commands, you can use "adb_shell:<command>" format.

Respond ONLY with a valid JSON object (no markdown, no explanation) in this format:
{{
    "plan_title": "Brief title of the investigation",
    "analysis": "Brief analysis of what the user wants to investigate",
    "steps": [
        {{
            "step_number": 1,
            "command": "command_name",
            "description": "What this step will do",
            "rationale": "Why this is needed for the investigation"
        }}
    ],
    "warnings": ["Any legal or procedural warnings"],
    "estimated_time": "Estimated completion time"
}}

If the request is a simple single command, return null.
If the request requires multiple data acquisitions or analysis, create a comprehensive plan.
Focus on forensically sound procedures that maintain chain of custody."""

            messages = [
                SystemMessage(content=system_prompt),
                HumanMessage(content=f"User request: {user_request}")
            ]
            
            response = llm.invoke(messages)
            content = response.content.strip()
            
            # Clean up the response
            if content.startswith("```"):
                content = content.split("```")[1]
                if content.startswith("json"):
                    content = content[4:]
            content = content.strip()
            
            if content.lower() == "null" or not content:
                return None
            
            plan = json.loads(content)
            return plan if plan and "steps" in plan and len(plan["steps"]) > 1 else None
            
        except Exception as e:
            return None
    
    @staticmethod
    def execute_plan_step(step: Dict) -> str:
        """Execute a single step from the plan."""
        command = step.get("command", "")
        
        # Map plan commands to actual execution
        command_map = {
            "device_info": "device info",
            "installed_apps": "installed apps",
            "logcat": "logcat",
            "contacts": "contacts",
            "call_log": "call log",
            "sms": "sms",
            "battery": "battery",
            "storage": "storage",
            "network": "network",
            "processes": "processes"
        }
        
        if command in command_map:
            return process_command(command_map[command])
        elif command.startswith("adb_shell:"):
            adb_cmd = command[10:]
            return process_command(f"adb shell {adb_cmd}")
        else:
            return f"Unknown command: {command}"


def search_web_for_guidance(query: str) -> str:
    """
    Search for forensic investigation guidance.
    Uses DuckDuckGo Instant Answer API for privacy.
    """
    if not WEB_SEARCH_AVAILABLE:
        return "Web search not available - requests module not installed"
    
    try:
        # Use DuckDuckGo Instant Answer API
        search_url = "https://api.duckduckgo.com/"
        params = {
            "q": f"android forensics {query}",
            "format": "json",
            "no_html": 1,
            "skip_disambig": 1
        }
        
        response = requests.get(search_url, params=params, timeout=10)
        data = response.json()
        
        results = []
        
        # Abstract (main answer)
        if data.get("Abstract"):
            results.append(f"**Summary:** {data['Abstract']}")
            if data.get("AbstractURL"):
                results.append(f"Source: {data['AbstractURL']}")
        
        # Related topics
        if data.get("RelatedTopics"):
            results.append("\n**Related Information:**")
            for topic in data["RelatedTopics"][:5]:
                if isinstance(topic, dict) and topic.get("Text"):
                    results.append(f"- {topic['Text'][:200]}")
        
        if results:
            return "\n".join(results)
        else:
            return "No specific guidance found. Consider consulting official Android forensics documentation or NIST guidelines."
            
    except Exception as e:
        return f"Search error: {str(e)}"


def get_ai_response(user_input: str) -> str:
    """Get AI response for general investigation questions."""
    if not AI_AVAILABLE or not os.getenv("GEMINI_API_KEY"):
        return None
    
    try:
        llm = ChatGoogleGenerativeAI(
            model="gemini-2.0-flash",
            google_api_key=os.getenv("GEMINI_API_KEY"),
            temperature=0.3
        )
        
        system_prompt = """You are an expert Android forensics investigator assistant for law enforcement.
Provide professional, accurate, and legally sound guidance for digital forensic investigations.
Keep responses concise and actionable. Reference proper forensic procedures and chain of custody requirements.
Do not include emojis or casual language. Maintain a professional law enforcement tone."""
        
        messages = [
            SystemMessage(content=system_prompt),
            HumanMessage(content=user_input)
        ]
        
        response = llm.invoke(messages)
        return response.content
    except Exception as e:
        return None


def check_device_connection() -> Dict:
    """Check if device is connected."""
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
        
        if devices:
            device_info = ADBExecutor.get_device_info()
            device_info["device_id"] = devices[0]["id"]
            return {"connected": True, "device_info": device_info, "device_count": len(devices)}
        
        return {"connected": False}
    except Exception as e:
        return {"connected": False, "error": str(e)}


def add_audit_log(message: str, level: str = "INFO", action: str = ""):
    """Add entry to audit log."""
    if "audit_log" not in st.session_state:
        st.session_state.audit_log = []
    
    st.session_state.audit_log.append({
        "timestamp": datetime.now().isoformat(),
        "time": datetime.now().strftime("%H:%M:%S"),
        "level": level,
        "action": action,
        "message": message
    })


def add_artifact(name: str, data: Any, artifact_type: str = "text"):
    """Store collected artifact."""
    if "artifacts" not in st.session_state:
        st.session_state.artifacts = {}
    
    st.session_state.artifacts[name] = {
        "data": data,
        "type": artifact_type,
        "collected_at": datetime.now().isoformat()
    }
    add_audit_log(f"Artifact acquired: {name}", "INFO", "ARTIFACT")


def process_command(user_input: str) -> str:
    """Process user command."""
    if not user_input.strip():
        return "Please enter a command or query."
    
    add_audit_log(f"Command: {user_input[:80]}", "INFO", "USER_INPUT")
    
    # Direct ADB command
    if user_input.strip().lower().startswith("adb "):
        result = ADBExecutor.run_command(user_input.strip())
        if result["success"]:
            output = result["stdout"] or "Command executed successfully"
            add_artifact(f"cmd_{datetime.now().strftime('%H%M%S')}", output, "command_output")
            return f"**Command:** `{user_input}`\n\n**Output:**\n```\n{output[:5000]}\n```"
        else:
            error = result.get("error") or result.get("stderr", "Unknown error")
            return f"**Command:** `{user_input}`\n\n**Error:**\n```\n{error}\n```"
    
    lower_input = user_input.lower()
    
    if any(k in lower_input for k in ["device info", "device information", "identify device"]):
        info = ADBExecutor.get_device_info()
        add_artifact("device_info", info, "device")
        return format_device_info(info)
    
    if any(k in lower_input for k in ["installed apps", "installed packages", "list apps", "applications"]):
        packages = ADBExecutor.get_installed_packages()
        add_artifact("installed_packages", packages, "packages")
        return format_packages(packages)
    
    if any(k in lower_input for k in ["logcat", "system log", "logs"]):
        logs = ADBExecutor.get_logcat(200) or "No log data retrieved"
        add_artifact("logcat", logs, "logs")
        return f"## SYSTEM LOGS\n\n```\n{str(logs)[:8000]}\n```"
    
    if any(k in lower_input for k in ["contacts", "address book"]):
        contacts = ADBExecutor.get_contacts() or "No contacts data retrieved"
        add_artifact("contacts", contacts, "contacts")
        return f"## CONTACTS DATABASE\n\n```\n{str(contacts)[:5000]}\n```"
    
    if any(k in lower_input for k in ["call log", "call history", "calls"]):
        calls = ADBExecutor.get_call_log() or "No call log data retrieved"
        add_artifact("call_log", calls, "calls")
        return f"## CALL RECORDS\n\n```\n{str(calls)[:5000]}\n```"
    
    if any(k in lower_input for k in ["sms", "messages", "text messages"]):
        sms = ADBExecutor.get_sms() or "No SMS data retrieved"
        add_artifact("sms", sms, "messages")
        return f"## SMS MESSAGES\n\n```\n{str(sms)[:5000]}\n```"
    
    if any(k in lower_input for k in ["battery", "power"]):
        battery = ADBExecutor.get_battery_info()
        add_artifact("battery", battery, "system")
        return f"## BATTERY STATUS\n\n```\n{battery}\n```"
    
    if any(k in lower_input for k in ["storage", "disk"]):
        storage = ADBExecutor.get_storage_info()
        add_artifact("storage", storage, "system")
        return f"## STORAGE INFORMATION\n\n```\n{storage}\n```"
    
    if any(k in lower_input for k in ["network", "wifi", "connectivity"]):
        network = ADBExecutor.get_network_info() or "No network data retrieved"
        add_artifact("network", str(network)[:3000], "system")
        return f"## NETWORK CONFIGURATION\n\n```\n{str(network)[:5000]}\n```"
    
    if any(k in lower_input for k in ["processes", "running apps"]):
        procs = ADBExecutor.get_running_processes() or "No process data retrieved"
        add_artifact("processes", procs, "system")
        return f"## RUNNING PROCESSES\n\n```\n{str(procs)[:8000]}\n```"
    
    # Web search for forensic guidance
    if any(k in lower_input for k in ["search", "how to", "guide", "procedure", "technique"]):
        search_results = search_web_for_guidance(user_input)
        return f"## FORENSIC GUIDANCE\n\n{search_results}"
    
    # Check if this is a complex investigation request that needs planning
    if InvestigationPlanner.is_available():
        plan = InvestigationPlanner.create_investigation_plan(user_input)
        if plan:
            # Store the plan in session state for approval
            st.session_state.pending_plan = plan
            st.session_state.pending_plan_request = user_input
            
            # Format the plan for display
            plan_display = f"## INVESTIGATION PLAN\n\n"
            plan_display += f"**{plan.get('plan_title', 'Investigation Plan')}**\n\n"
            plan_display += f"**Analysis:** {plan.get('analysis', '')}\n\n"
            plan_display += f"**Estimated Time:** {plan.get('estimated_time', 'Unknown')}\n\n"
            
            if plan.get('warnings'):
                plan_display += "**Warnings:**\n"
                for warning in plan['warnings']:
                    plan_display += f"- {warning}\n"
                plan_display += "\n"
            
            plan_display += "### Proposed Steps:\n\n"
            plan_display += "| Step | Command | Description | Rationale |\n"
            plan_display += "|------|---------|-------------|------------|\n"
            
            for step in plan.get('steps', []):
                plan_display += f"| {step.get('step_number', '')} | `{step.get('command', '')}` | {step.get('description', '')} | {step.get('rationale', '')} |\n"
            
            plan_display += "\n**Use the 'Execute Plan' button in the sidebar to proceed with this investigation, or type a new command to cancel.**"
            
            return plan_display
    
    # Try AI response for general questions
    ai_response = get_ai_response(user_input)
    if ai_response:
        return f"## AI ANALYSIS\n\n{ai_response}"
    
    return get_help_message()


def format_device_info(info: Dict) -> str:
    """Format device info as markdown table."""
    md = "## DEVICE IDENTIFICATION\n\n"
    md += "| Property | Value |\n|----------|-------|\n"
    for key, value in info.items():
        md += f"| {key.replace('_', ' ').title()} | {value} |\n"
    return md


def format_packages(packages: List[Dict]) -> str:
    """Format packages as markdown."""
    md = f"## INSTALLED APPLICATIONS\n\n**Total Packages:** {len(packages)}\n\n"
    md += "| Package Name | Path |\n|--------------|------|\n"
    for pkg in packages[:100]:
        md += f"| {pkg['package']} | {pkg.get('path', '')[:50]} |\n"
    if len(packages) > 100:
        md += f"\n*Additional {len(packages) - 100} packages not displayed*"
    return md


def get_help_message() -> str:
    """Return help message."""
    ai_status = "ACTIVE" if InvestigationPlanner.is_available() else "INACTIVE"
    
    return f"""## COMMAND REFERENCE

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
| adb shell [command] | Execute shell command |
| adb pull [path] | Extract file from device |

### AI-Powered Features (Status: {ai_status})
| Feature | Description |
|---------|-------------|
| Complex Investigation | Describe what you want to investigate and AI will create a step-by-step plan |
| Search Guidance | Ask "how to" questions for forensic procedure guidance |
| Evidence Analysis | Ask questions about findings for AI-powered analysis |

### Example Complex Requests
- "Investigate this device for evidence of financial fraud"
- "Collect all communication data for timeline analysis"
- "Perform a complete device triage for drug trafficking investigation"
- "Extract and analyze all user activity from the past 30 days"

**Note:** Complex investigation requests will generate a plan for your approval before execution.
"""


def generate_md_report() -> str:
    """Generate Markdown report."""
    case = st.session_state.get("case", {})
    artifacts = st.session_state.get("artifacts", {})
    audit_log = st.session_state.get("audit_log", [])
    
    report = f"""# DIGITAL FORENSICS INVESTIGATION REPORT

## CLASSIFICATION: OFFICIAL USE ONLY

---

## CASE INFORMATION

| Field | Value |
|-------|-------|
| Case Number | {case.get('case_number', 'N/A')} |
| Examiner | {case.get('examiner', 'N/A')} |
| Agency | {case.get('agency', 'N/A')} |
| Investigation Started | {case.get('start_time', 'N/A')} |
| Report Generated | {datetime.now().isoformat()} |
| Case Notes | {case.get('notes', 'N/A')} |

---

## DEVICE INFORMATION

"""
    if "device_info" in artifacts:
        info = artifacts["device_info"]["data"]
        report += "| Property | Value |\n|----------|-------|\n"
        for key, value in info.items():
            report += f"| {key.replace('_', ' ').title()} | {value} |\n"
    else:
        report += "*Device information not acquired*\n"
    
    report += "\n---\n\n## ACQUIRED EVIDENCE\n\n"
    
    for name, artifact in artifacts.items():
        report += f"### {name.replace('_', ' ').upper()}\n\n"
        report += f"**Type:** {artifact['type']}  \n"
        report += f"**Acquired:** {artifact['collected_at']}\n\n"
        
        data = artifact["data"]
        if isinstance(data, dict):
            report += "```json\n" + json.dumps(data, indent=2, default=str)[:3000] + "\n```\n\n"
        elif isinstance(data, list):
            report += f"*{len(data)} items acquired*\n\n"
        else:
            report += f"```\n{str(data)[:2000]}\n```\n\n"
    
    report += "---\n\n## CHAIN OF CUSTODY - AUDIT LOG\n\n"
    report += "| Timestamp | Level | Action | Details |\n|-----------|-------|--------|--------|\n"
    for entry in audit_log:
        report += f"| {entry['time']} | {entry['level']} | {entry['action']} | {entry['message'][:50]} |\n"
    
    report += f"\n---\n\n*Report generated by FIA Digital Forensics Framework v2.3.0*\n"
    
    return report


def generate_html_report() -> str:
    """Generate HTML report."""
    case = st.session_state.get("case", {})
    artifacts = st.session_state.get("artifacts", {})
    audit_log = st.session_state.get("audit_log", [])
    
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Forensic Report - {case.get('case_number', 'N/A')}</title>
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
        table {{ width: 100%; border-collapse: collapse; }}
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
        }}
        pre {{
            background: #1a202c;
            color: #e2e8f0;
            padding: 16px;
            overflow-x: auto;
            font-family: 'Consolas', monospace;
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
                    <tr><th style="width:200px">Case Number</th><td>{case.get('case_number', 'N/A')}</td></tr>
                    <tr><th>Examiner</th><td>{case.get('examiner', 'N/A')}</td></tr>
                    <tr><th>Agency</th><td>{case.get('agency', 'N/A')}</td></tr>
                    <tr><th>Investigation Started</th><td>{case.get('start_time', 'N/A')}</td></tr>
                    <tr><th>Report Generated</th><td>{datetime.now().isoformat()}</td></tr>
                    <tr><th>Case Notes</th><td>{case.get('notes', 'N/A')}</td></tr>
                </table>
            </div>
        </div>
"""
    
    if "device_info" in artifacts:
        info = artifacts["device_info"]["data"]
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
    for name, artifact in artifacts.items():
        html += f"""
                <div style="margin-bottom: 24px;">
                    <h4 style="color: #2d3748; margin-bottom: 8px; text-transform: uppercase;">{name.replace('_', ' ')}</h4>
                    <p style="color: #718096; font-size: 0.85rem;"><strong>Type:</strong> {artifact['type']} | <strong>Acquired:</strong> {artifact['collected_at']}</p>
"""
        data = artifact["data"]
        if isinstance(data, dict):
            html += f"<pre>{json.dumps(data, indent=2, default=str)[:2000]}</pre>\n"
        elif isinstance(data, list):
            html += f"<p style='color: #4a5568;'><em>{len(data)} items acquired</em></p>\n"
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
    for entry in audit_log:
        html += f"                    <tr><td>{entry['time']}</td><td>{entry['level']}</td><td>{entry['action']}</td><td>{entry['message'][:60]}</td></tr>\n"
    
    html += """                </table>
            </div>
        </div>
        
        <div class="footer">
            <p>Report generated by FIA Digital Forensics Framework v2.3.0</p>
            <p>This document is for official use only.</p>
        </div>
    </div>
</body>
</html>
"""
    return html


def main():
    """Main Streamlit application."""
    
    # Page configuration
    st.set_page_config(
        page_title="FIA Digital Forensics",
        page_icon="",
        layout="wide",
        initial_sidebar_state="expanded"
    )
    
    # Custom CSS for professional look
    st.markdown("""
    <style>
        .main-header {
            background: linear-gradient(135deg, #1a365d 0%, #2d3748 100%);
            color: white;
            padding: 24px 32px;
            border-bottom: 3px solid #c53030;
            margin: -1rem -1rem 2rem -1rem;
        }
        .main-header h1 {
            font-size: 1.5rem;
            font-weight: 600;
            letter-spacing: 0.5px;
            margin: 0;
        }
        .main-header p {
            color: rgba(255,255,255,0.85);
            margin: 4px 0 0 0;
        }
        .classification-badge {
            background: #c53030;
            color: white;
            padding: 6px 16px;
            font-size: 0.75rem;
            font-weight: 600;
            letter-spacing: 1.5px;
            display: inline-block;
            float: right;
        }
        .status-connected {
            background: #276749;
            color: white;
            padding: 8px 16px;
            border-radius: 4px;
            font-weight: 600;
        }
        .status-disconnected {
            background: #c53030;
            color: white;
            padding: 8px 16px;
            border-radius: 4px;
            font-weight: 600;
        }
        .section-header {
            font-size: 0.9rem;
            font-weight: 600;
            color: #2d3748;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            padding-bottom: 8px;
            border-bottom: 2px solid #2d3748;
            margin-bottom: 16px;
        }
        .stButton>button {
            background: #2d3748;
            color: white;
            border: none;
            font-weight: 500;
        }
        .stButton>button:hover {
            background: #1a202c;
            color: white;
        }
        div[data-testid="stExpander"] {
            border: 1px solid #e2e8f0;
        }
    </style>
    """, unsafe_allow_html=True)
    
    # Header
    st.markdown("""
    <div class="main-header">
        <span class="classification-badge">OFFICIAL USE ONLY</span>
        <h1>DIGITAL FORENSICS INVESTIGATION CONSOLE</h1>
        <p>Federal Investigation Agency | Mobile Device Evidence Acquisition System</p>
    </div>
    """, unsafe_allow_html=True)
    
    # Initialize session state
    if "messages" not in st.session_state:
        st.session_state.messages = []
    if "case" not in st.session_state:
        st.session_state.case = None
    if "artifacts" not in st.session_state:
        st.session_state.artifacts = {}
    if "audit_log" not in st.session_state:
        st.session_state.audit_log = []
    
    # Sidebar
    with st.sidebar:
        st.markdown('<div class="section-header">DEVICE STATUS</div>', unsafe_allow_html=True)
        
        if st.button("Refresh Connection", use_container_width=True):
            st.session_state.device_status = check_device_connection()
        
        if "device_status" not in st.session_state:
            st.session_state.device_status = check_device_connection()
        
        status = st.session_state.device_status
        
        if status.get("connected"):
            st.markdown('<div class="status-connected">DEVICE CONNECTED</div>', unsafe_allow_html=True)
            info = status.get("device_info", {})
            st.text(f"Manufacturer: {info.get('manufacturer', 'N/A')}")
            st.text(f"Model: {info.get('model', 'N/A')}")
            st.text(f"Android: {info.get('android_version', 'N/A')}")
            st.text(f"Serial: {info.get('serial', 'N/A')}")
            st.text(f"Device ID: {info.get('device_id', 'N/A')}")
        else:
            st.markdown('<div class="status-disconnected">NO DEVICE</div>', unsafe_allow_html=True)
            st.warning("Connect device via USB and enable USB Debugging")
        
        st.markdown("---")
        st.markdown('<div class="section-header">CASE MANAGEMENT</div>', unsafe_allow_html=True)
        
        case_num = st.text_input("Case Number", placeholder="Auto-generated if blank")
        examiner = st.text_input("Examiner Name", value=os.getenv("INVESTIGATOR_NAME", ""))
        agency = st.text_input("Agency", value="Federal Investigation Agency")
        notes = st.text_area("Case Notes", height=80)
        
        if st.button("Initialize New Case", use_container_width=True, type="primary"):
            st.session_state.case = {
                "case_number": case_num or f"FIA-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
                "examiner": examiner or "Examiner",
                "agency": agency or "Federal Investigation Agency",
                "start_time": datetime.now().isoformat(),
                "notes": notes,
                "status": "ACTIVE"
            }
            st.session_state.messages = []
            st.session_state.artifacts = {}
            st.session_state.audit_log = []
            add_audit_log(f"Case initiated: {st.session_state.case['case_number']}", "INFO", "CASE_OPENED")
            st.success(f"Case {st.session_state.case['case_number']} initialized")
        
        if st.session_state.case:
            st.info(f"Active: {st.session_state.case['case_number']}")
        
        st.markdown("---")
        st.markdown('<div class="section-header">REPORT GENERATION</div>', unsafe_allow_html=True)
        
        report_format = st.radio("Export Format", ["Markdown (.md)", "HTML Report (.html)"])
        
        if st.button("Generate Report", use_container_width=True):
            if st.session_state.case:
                if "HTML" in report_format:
                    report_content = generate_html_report()
                    filename = f"{st.session_state.case['case_number']}_report.html"
                else:
                    report_content = generate_md_report()
                    filename = f"{st.session_state.case['case_number']}_report.md"
                
                # Save to file
                filepath = REPORTS_DIR / filename
                with open(filepath, "w", encoding="utf-8") as f:
                    f.write(report_content)
                
                add_audit_log(f"Report generated: {filename}", "INFO", "REPORT")
                
                # Download button
                st.download_button(
                    label="Download Report",
                    data=report_content,
                    file_name=filename,
                    mime="text/html" if "HTML" in report_format else "text/markdown",
                    use_container_width=True
                )
                st.success(f"Report saved: {filepath}")
            else:
                st.error("No active case")
        
        # AI Investigation Plan Execution
        if st.session_state.get("pending_plan"):
            st.markdown("---")
            st.markdown('<div class="section-header">PENDING INVESTIGATION PLAN</div>', unsafe_allow_html=True)
            
            plan = st.session_state.pending_plan
            st.info(f"**{plan.get('plan_title', 'Investigation Plan')}**")
            st.text(f"Steps: {len(plan.get('steps', []))}")
            
            col_exec, col_cancel = st.columns(2)
            
            with col_exec:
                if st.button("Execute Plan", use_container_width=True, type="primary"):
                    st.session_state.plan_executing = True
                    results = []
                    
                    for step in plan.get("steps", []):
                        add_audit_log(f"Executing step {step.get('step_number')}: {step.get('command')}", "INFO", "PLAN_STEP")
                        result = InvestigationPlanner.execute_plan_step(step)
                        results.append({
                            "step": step.get("step_number"),
                            "command": step.get("command"),
                            "result": result
                        })
                    
                    # Format results
                    final_result = f"## INVESTIGATION PLAN EXECUTED\n\n"
                    final_result += f"**{plan.get('plan_title', 'Investigation')}**\n\n"
                    
                    for r in results:
                        final_result += f"### Step {r['step']}: {r['command']}\n\n"
                        final_result += f"{r['result']}\n\n---\n\n"
                    
                    st.session_state.messages.append({
                        "role": "user", 
                        "content": f"[Investigation Plan] {st.session_state.get('pending_plan_request', 'Plan execution')}"
                    })
                    st.session_state.messages.append({"role": "assistant", "content": final_result})
                    
                    # Clear the pending plan
                    st.session_state.pending_plan = None
                    st.session_state.pending_plan_request = None
                    st.session_state.plan_executing = False
                    
                    add_audit_log("Investigation plan completed", "INFO", "PLAN_COMPLETE")
                    st.rerun()
            
            with col_cancel:
                if st.button("Cancel Plan", use_container_width=True):
                    st.session_state.pending_plan = None
                    st.session_state.pending_plan_request = None
                    add_audit_log("Investigation plan cancelled", "INFO", "PLAN_CANCELLED")
                    st.rerun()
        
        # AI Status
        st.markdown("---")
        st.markdown('<div class="section-header">AI FEATURES</div>', unsafe_allow_html=True)
        
        if InvestigationPlanner.is_available():
            st.markdown('<span style="color: #276749; font-weight: bold;">AI PLANNING: ACTIVE</span>', unsafe_allow_html=True)
            st.text("Enter complex investigation\nrequests for AI planning")
        else:
            st.markdown('<span style="color: #c53030; font-weight: bold;">AI PLANNING: INACTIVE</span>', unsafe_allow_html=True)
            st.text("Set GEMINI_API_KEY in .env\nto enable AI features")
    
    # Main content area
    col1, col2 = st.columns([2, 1])
    
    with col1:
        st.markdown('<div class="section-header">INVESTIGATION CONSOLE</div>', unsafe_allow_html=True)
        
        # Quick actions
        st.markdown("**Quick Acquisition:**")
        qa_cols = st.columns(4)
        
        quick_actions = [
            ("Device Info", "device info"),
            ("Applications", "installed apps"),
            ("System Logs", "logcat"),
            ("Processes", "processes"),
            ("Contacts", "contacts"),
            ("Call Records", "call log"),
            ("SMS Messages", "sms"),
            ("Storage", "storage"),
        ]
        
        for i, (label, cmd) in enumerate(quick_actions):
            with qa_cols[i % 4]:
                if st.button(label, use_container_width=True, key=f"qa_{i}"):
                    if not st.session_state.case:
                        st.session_state.case = {
                            "case_number": f"FIA-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
                            "examiner": os.getenv("INVESTIGATOR_NAME", "Examiner"),
                            "agency": "Federal Investigation Agency",
                            "start_time": datetime.now().isoformat(),
                            "notes": "",
                            "status": "ACTIVE"
                        }
                        add_audit_log(f"Case auto-initiated: {st.session_state.case['case_number']}", "INFO", "CASE_OPENED")
                    
                    with st.spinner(f"Acquiring {label}..."):
                        response = process_command(cmd)
                        st.session_state.messages.append({"role": "user", "content": cmd})
                        st.session_state.messages.append({"role": "assistant", "content": response})
        
        st.markdown("---")
        
        # Chat interface
        chat_container = st.container(height=400)
        
        with chat_container:
            for msg in st.session_state.messages:
                if msg["role"] == "user":
                    st.markdown(f"**Command:** {msg['content']}")
                else:
                    st.markdown(msg["content"])
                st.markdown("---")
        
        # Command input
        user_input = st.chat_input("Enter acquisition command or ADB command...")
        
        if user_input:
            if not st.session_state.case:
                st.session_state.case = {
                    "case_number": f"FIA-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
                    "examiner": os.getenv("INVESTIGATOR_NAME", "Examiner"),
                    "agency": "Federal Investigation Agency",
                    "start_time": datetime.now().isoformat(),
                    "notes": "",
                    "status": "ACTIVE"
                }
                add_audit_log(f"Case auto-initiated", "INFO", "CASE_OPENED")
            
            response = process_command(user_input)
            st.session_state.messages.append({"role": "user", "content": user_input})
            st.session_state.messages.append({"role": "assistant", "content": response})
            st.rerun()
    
    with col2:
        st.markdown('<div class="section-header">ACQUIRED ARTIFACTS</div>', unsafe_allow_html=True)
        
        if st.session_state.artifacts:
            for name, artifact in st.session_state.artifacts.items():
                with st.expander(f"{name.replace('_', ' ').title()}"):
                    st.text(f"Type: {artifact['type']}")
                    st.text(f"Acquired: {artifact['collected_at']}")
                    if isinstance(artifact['data'], dict):
                        st.json(artifact['data'])
                    elif isinstance(artifact['data'], list):
                        st.text(f"{len(artifact['data'])} items")
                    else:
                        st.text(str(artifact['data'])[:500])
        else:
            st.info("No artifacts collected yet")
        
        st.markdown("---")
        st.markdown('<div class="section-header">AUDIT LOG</div>', unsafe_allow_html=True)
        
        audit_container = st.container(height=200)
        with audit_container:
            if st.session_state.audit_log:
                for entry in reversed(st.session_state.audit_log[-20:]):
                    st.text(f"{entry['time']} [{entry['level']}] {entry['action']}: {entry['message'][:40]}")
            else:
                st.text("No audit entries")


if __name__ == "__main__":
    main()
