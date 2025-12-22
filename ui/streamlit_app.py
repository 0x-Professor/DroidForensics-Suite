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


# ========== INTELLIGENT FORENSIC AGENT ==========

class ForensicAgent:
    """
    Intelligent AI-powered forensic agent that can:
    1. Understand any data extraction request and generate appropriate ADB commands
    2. Analyze collected artifacts and provide insights
    3. Handle errors gracefully with helpful suggestions
    4. Create multi-step investigation plans
    """
    
    _last_error = None
    
    # Common ADB commands for reference
    ADB_COMMAND_KNOWLEDGE = """
Common ADB commands for forensic data extraction:
- adb shell content query --uri content://sms/ : SMS messages
- adb shell content query --uri content://call_log/calls/ : Call logs
- adb shell content query --uri content://contacts/phones/ : Contacts
- adb shell content query --uri content://media/external/images/media : Image metadata
- adb shell content query --uri content://media/external/video/media : Video metadata
- adb shell content query --uri content://media/external/audio/media : Audio metadata
- adb shell content query --uri content://browser/bookmarks : Browser bookmarks
- adb shell content query --uri content://calendar/events : Calendar events
- adb shell dumpsys battery : Battery info
- adb shell dumpsys connectivity : Network info
- adb shell dumpsys package [package] : App info
- adb shell dumpsys activity : Activity info
- adb shell dumpsys location : Location services
- adb shell dumpsys notification : Notifications
- adb shell pm list packages : List packages
- adb shell ps -A : Running processes
- adb shell logcat -d : System logs
- adb shell getprop : All system properties
- adb shell ls [path] : List files
- adb shell cat [file] : Read file content
- adb shell find [path] -name [pattern] : Find files
- adb pull [remote] [local] : Pull file from device
- adb shell settings list system : System settings
- adb shell settings list secure : Secure settings
- adb shell settings list global : Global settings
- adb shell dumpsys wifi : WiFi information
- adb shell dumpsys bluetooth_manager : Bluetooth info
- adb shell dumpsys account : Account information
- adb shell content query --uri content://com.android.externalstorage.documents : External storage
"""
    
    @staticmethod
    def is_available() -> bool:
        """Check if AI agent is available."""
        return AI_AVAILABLE and bool(os.getenv("GEMINI_API_KEY"))
    
    @staticmethod
    def get_last_error() -> Optional[str]:
        return ForensicAgent._last_error
    
    @staticmethod
    def _get_llm():
        """Get configured LLM instance."""
        return ChatGoogleGenerativeAI(
            model="gemini-2.0-flash",
            google_api_key=os.getenv("GEMINI_API_KEY"),
            temperature=0.2,
            max_retries=2
        )
    
    @staticmethod
    def analyze_request(user_input: str, artifacts: Dict = None) -> Dict:
        """
        Analyze user request and determine the best action.
        Returns: {"action": "extract|analyze|search|plan|help", "details": {...}}
        """
        ForensicAgent._last_error = None
        
        if not ForensicAgent.is_available():
            return {"action": "error", "message": "AI not available. Set GEMINI_API_KEY in .env"}
        
        try:
            llm = ForensicAgent._get_llm()
            
            artifacts_summary = ""
            if artifacts:
                artifacts_summary = f"\n\nCurrently collected artifacts:\n"
                for name, data in artifacts.items():
                    artifacts_summary += f"- {name} (type: {data.get('type', 'unknown')}, collected: {data.get('collected_at', 'unknown')})\n"
            
            system_prompt = f"""You are an expert Android forensic investigator AI agent. Analyze the user's request and determine the best action.

{ForensicAgent.ADB_COMMAND_KNOWLEDGE}
{artifacts_summary}

Analyze the request and respond with ONLY a JSON object (no markdown):

For DATA EXTRACTION requests (user wants to get data from device):
{{"action": "extract", "adb_command": "the exact adb command to run", "description": "what this will retrieve", "data_type": "type of data"}}

For ARTIFACT ANALYSIS requests (user asking about collected data, its importance, or how to find specific info):
{{"action": "analyze", "artifact_names": ["list of relevant artifacts"], "analysis_type": "importance|search|explain|compare", "query": "what to analyze"}}

For WEB SEARCH requests (user asking how to do something, forensic procedures, or needs external info):
{{"action": "search", "query": "search query for forensic guidance"}}

For MULTI-STEP INVESTIGATION requests (complex investigation requiring multiple steps):
{{"action": "plan", "plan_title": "title", "steps": [{{"step": 1, "adb_command": "command", "description": "what it does"}}]}}

For UNCLEAR requests or needing more info:
{{"action": "help", "message": "helpful message explaining available options"}}

Be smart about interpreting user intent. "fetch images" means extract images, "what's important in call logs" means analyze artifacts."""

            messages = [
                SystemMessage(content=system_prompt),
                HumanMessage(content=f"User request: {user_input}")
            ]
            
            response = llm.invoke(messages)
            content = response.content.strip()
            
            # Clean JSON from markdown
            if "```json" in content:
                content = content.split("```json")[1].split("```")[0]
            elif "```" in content:
                content = content.split("```")[1].split("```")[0]
            content = content.strip()
            
            return json.loads(content)
            
        except json.JSONDecodeError as e:
            ForensicAgent._last_error = f"Failed to parse AI response: {str(e)}"
            return {"action": "error", "message": "AI response parsing error. Please try rephrasing your request."}
        except Exception as e:
            error_msg = str(e)
            if "429" in error_msg or "quota" in error_msg.lower():
                ForensicAgent._last_error = "API quota exceeded"
                return {"action": "error", "message": "API quota exceeded. Please wait a moment or use direct commands like 'device info', 'sms', 'call log'."}
            ForensicAgent._last_error = error_msg
            return {"action": "error", "message": f"AI Error: {error_msg[:150]}"}
    
    @staticmethod
    def execute_extraction(adb_command: str, description: str = "", data_type: str = "") -> str:
        """Execute an ADB command and return formatted results with error handling."""
        try:
            result = ADBExecutor.run_command(adb_command, timeout=60)
            
            if result["success"]:
                output = result.get("stdout", "")
                if output and output.strip():
                    # Store as artifact
                    artifact_name = data_type or f"extraction_{datetime.now().strftime('%H%M%S')}"
                    add_artifact(artifact_name, output[:10000], data_type or "extracted_data")
                    
                    return f"""## DATA EXTRACTION SUCCESSFUL

**Command:** `{adb_command}`
**Description:** {description}
**Data Type:** {data_type}

**Results:**
```
{output[:8000]}
```

{"*Output truncated (showing first 8000 characters)*" if len(output) > 8000 else ""}

*Data saved to artifacts as '{artifact_name}'*"""
                else:
                    return f"""## NO DATA RETURNED

**Command:** `{adb_command}`

The command executed successfully but returned no data. This could mean:
- The requested data doesn't exist on this device
- The app/feature hasn't been used
- Permission restrictions are in place

**Suggestions:**
- Check if the device has the relevant app installed
- Verify USB debugging permissions
- Try running: `adb shell pm list packages` to see available apps"""
            else:
                error = result.get("error") or result.get("stderr", "Unknown error")
                return ForensicAgent._format_error(adb_command, error)
                
        except Exception as e:
            return ForensicAgent._format_error(adb_command, str(e))
    
    @staticmethod
    def _format_error(command: str, error: str) -> str:
        """Format error messages with helpful suggestions."""
        suggestions = []
        
        if "permission" in error.lower() or "denied" in error.lower():
            suggestions = [
                "Ensure USB debugging is enabled on the device",
                "Check if the device is properly authorized",
                "Some data requires root access or special permissions",
                "Try: `adb shell pm grant [package] [permission]`"
            ]
        elif "not found" in error.lower():
            suggestions = [
                "The requested path or content provider may not exist",
                "Check if the relevant app is installed",
                "Try listing available content with: `adb shell content query --uri content://`"
            ]
        elif "timeout" in error.lower():
            suggestions = [
                "The command took too long to execute",
                "Device may be slow or busy",
                "Try a simpler command first"
            ]
        elif "device" in error.lower() and ("not" in error.lower() or "offline" in error.lower()):
            suggestions = [
                "Reconnect the USB cable",
                "Run: `adb kill-server` then `adb start-server`",
                "Check if USB debugging is still enabled"
            ]
        else:
            suggestions = [
                "Verify the device is connected: `adb devices`",
                "Check USB debugging status",
                "Try a basic command first: `device info`"
            ]
        
        return f"""## COMMAND ERROR

**Command:** `{command}`

**Error:**
```
{error[:500]}
```

**Troubleshooting Suggestions:**
{chr(10).join(f"- {s}" for s in suggestions)}"""
    
    @staticmethod
    def analyze_artifacts(artifacts: Dict, artifact_names: List[str], analysis_type: str, query: str) -> str:
        """Analyze collected artifacts and provide insights."""
        if not artifacts:
            return """## NO ARTIFACTS COLLECTED

No data has been collected yet. Use data extraction commands first:
- `device info` - Get device information
- `sms` - Extract SMS messages
- `call log` - Extract call history
- `contacts` - Extract contacts
- `installed apps` - List installed applications

Or describe what data you need: "fetch all images from the device" """
        
        # Filter relevant artifacts
        relevant_data = {}
        if artifact_names and artifact_names[0] != "all":
            for name in artifact_names:
                for art_name, art_data in artifacts.items():
                    if name.lower() in art_name.lower():
                        relevant_data[art_name] = art_data
        else:
            relevant_data = artifacts
        
        if not relevant_data:
            available = ", ".join(artifacts.keys())
            return f"""## ARTIFACT NOT FOUND

The requested artifact(s) were not found. 

**Available artifacts:** {available}

Please specify one of the available artifacts or collect new data."""
        
        # Use AI to analyze
        if ForensicAgent.is_available():
            try:
                llm = ForensicAgent._get_llm()
                
                # Prepare artifact summaries
                artifact_summary = ""
                for name, data in relevant_data.items():
                    content = str(data.get("data", ""))[:3000]
                    artifact_summary += f"\n\n=== {name} (type: {data.get('type')}) ===\n{content}"
                
                analysis_prompts = {
                    "importance": "Explain the forensic importance and evidentiary value of this data. What can investigators learn from it? What legal considerations apply?",
                    "search": f"Search through this data to find: {query}. Extract relevant entries and explain their significance.",
                    "explain": f"Explain what this data means and how to interpret it for forensic purposes. Answer: {query}",
                    "compare": "Compare and correlate these artifacts. What patterns or connections can you identify?"
                }
                
                prompt = analysis_prompts.get(analysis_type, f"Analyze this data and answer: {query}")
                
                messages = [
                    SystemMessage(content="""You are an expert forensic analyst. Analyze the provided device artifacts professionally.
Provide actionable insights for law enforcement. Be specific about what the data reveals.
Format your response with clear sections. Do not use emojis."""),
                    HumanMessage(content=f"{prompt}\n\nArtifacts:{artifact_summary}")
                ]
                
                response = llm.invoke(messages)
                
                return f"""## ARTIFACT ANALYSIS

**Analyzed:** {', '.join(relevant_data.keys())}
**Analysis Type:** {analysis_type}

{response.content}"""
                
            except Exception as e:
                if "429" in str(e):
                    return "## API QUOTA EXCEEDED\n\nPlease wait a moment before requesting AI analysis."
                return f"## ANALYSIS ERROR\n\n{str(e)[:200]}"
        
        # Fallback without AI
        return f"""## ARTIFACT SUMMARY

**Available Data:**
{chr(10).join(f"- **{name}**: {data.get('type', 'unknown')} (collected: {data.get('collected_at', 'unknown')})" for name, data in relevant_data.items())}

*AI analysis unavailable. Configure GEMINI_API_KEY for intelligent insights.*"""
    
    @staticmethod
    def create_and_display_plan(plan_data: Dict) -> str:
        """Format and display an investigation plan."""
        plan_display = f"""## INVESTIGATION PLAN

**{plan_data.get('plan_title', 'Investigation Plan')}**

### Proposed Steps:

| Step | Command | Description |
|------|---------|-------------|
"""
        for step in plan_data.get("steps", []):
            plan_display += f"| {step.get('step', '')} | `{step.get('adb_command', '')}` | {step.get('description', '')} |\n"
        
        plan_display += "\n**Use the 'Execute Plan' button in the sidebar to proceed, or enter a new command to cancel.**"
        
        return plan_display


def search_web_tavily(query: str) -> str:
    """Search for forensic investigation guidance using Tavily API."""
    tavily_key = os.getenv("TAVILY_API_KEY")
    
    if TAVILY_AVAILABLE and tavily_key:
        try:
            client = TavilyClient(api_key=tavily_key)
            response = client.search(
                query=f"android mobile forensics {query}",
                search_depth="advanced",
                max_results=5
            )
            
            results = ["## WEB SEARCH RESULTS\n"]
            
            for i, result in enumerate(response.get("results", [])[:5], 1):
                title = result.get("title", "No title")
                content = result.get("content", "No content")[:400]
                url = result.get("url", "")
                
                results.append(f"### {i}. {title}\n")
                results.append(f"{content}...\n")
                if url:
                    results.append(f"*Source: {url}*\n")
            
            return "\n".join(results) if len(results) > 1 else "No results found."
                
        except Exception as e:
            return f"## SEARCH ERROR\n\nTavily search failed: {str(e)}\n\nTry rephrasing your question."
    
    return search_web_duckduckgo(query)


def search_web_duckduckgo(query: str) -> str:
    """Fallback search using DuckDuckGo."""
    if not WEB_SEARCH_AVAILABLE:
        return "Web search not available - install requests: `pip install requests`"
    
    try:
        response = requests.get(
            "https://api.duckduckgo.com/",
            params={"q": f"android forensics {query}", "format": "json", "no_html": 1},
            timeout=10
        )
        data = response.json()
        
        results = []
        if data.get("Abstract"):
            results.append(f"**Summary:** {data['Abstract']}")
        if data.get("RelatedTopics"):
            for topic in data["RelatedTopics"][:5]:
                if isinstance(topic, dict) and topic.get("Text"):
                    results.append(f"- {topic['Text'][:200]}")
        
        return "\n".join(results) if results else "No specific guidance found."
    except Exception as e:
        return f"Search error: {str(e)}"


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
    """
    Process user command using the intelligent ForensicAgent.
    Handles data extraction, artifact analysis, web search, and investigation planning.
    """
    if not user_input.strip():
        return "Please enter a command or query."
    
    add_audit_log(f"Command: {user_input[:80]}", "INFO", "USER_INPUT")
    
    # Direct ADB command - execute immediately
    if user_input.strip().lower().startswith("adb "):
        return ForensicAgent.execute_extraction(
            user_input.strip(), 
            "Direct ADB command", 
            "adb_output"
        )
    
    lower_input = user_input.lower()
    
    # Quick commands for common operations (fast path, no AI needed)
    quick_commands = {
        "device info": ("adb shell getprop", "Device properties", "device_info"),
        "battery": ("adb shell dumpsys battery", "Battery status", "battery"),
        "storage": ("adb shell df -h", "Storage information", "storage"),
        "processes": ("adb shell ps -A", "Running processes", "processes"),
    }
    
    for trigger, (cmd, desc, dtype) in quick_commands.items():
        if trigger in lower_input and len(lower_input) < 30:
            # Use existing methods for common commands
            if "device info" in lower_input:
                info = ADBExecutor.get_device_info()
                add_artifact("device_info", info, "device")
                return format_device_info(info)
            elif "battery" in lower_input:
                battery = ADBExecutor.get_battery_info() or "No battery data"
                add_artifact("battery", battery, "system")
                return f"## BATTERY STATUS\n\n```\n{battery}\n```"
            elif "storage" in lower_input:
                storage = ADBExecutor.get_storage_info() or "No storage data"
                add_artifact("storage", storage, "system")
                return f"## STORAGE INFORMATION\n\n```\n{storage}\n```"
            elif "processes" in lower_input:
                procs = ADBExecutor.get_running_processes() or "No process data"
                add_artifact("processes", procs, "system")
                return f"## RUNNING PROCESSES\n\n```\n{str(procs)[:8000]}\n```"
    
    # Other quick commands
    if any(k in lower_input for k in ["installed apps", "list apps", "applications", "packages"]):
        packages = ADBExecutor.get_installed_packages()
        add_artifact("installed_packages", packages, "packages")
        return format_packages(packages)
    
    if any(k in lower_input for k in ["logcat", "system log"]) and "log" in lower_input:
        logs = ADBExecutor.get_logcat(200) or "No log data"
        add_artifact("logcat", logs, "logs")
        return f"## SYSTEM LOGS\n\n```\n{str(logs)[:8000]}\n```"
    
    if any(k in lower_input for k in ["contacts", "address book"]):
        contacts = ADBExecutor.get_contacts() or "No contacts data"
        add_artifact("contacts", contacts, "contacts")
        return f"## CONTACTS DATABASE\n\n```\n{str(contacts)[:5000]}\n```"
    
    if any(k in lower_input for k in ["call log", "call history", "calls"]) and "call" in lower_input:
        calls = ADBExecutor.get_call_log() or "No call log data"
        add_artifact("call_log", calls, "calls")
        return f"## CALL RECORDS\n\n```\n{str(calls)[:5000]}\n```"
    
    if "sms" in lower_input or "text message" in lower_input:
        sms = ADBExecutor.get_sms() or "No SMS data"
        add_artifact("sms", sms, "messages")
        return f"## SMS MESSAGES\n\n```\n{str(sms)[:5000]}\n```"
    
    if any(k in lower_input for k in ["network", "wifi", "connectivity"]):
        network = ADBExecutor.get_network_info() or "No network data"
        add_artifact("network", str(network)[:3000], "system")
        return f"## NETWORK CONFIGURATION\n\n```\n{str(network)[:5000]}\n```"
    
    # Help command
    if lower_input in ["help", "?", "commands", "what can you do"]:
        return get_help_message()
    
    # ========== INTELLIGENT AGENT PROCESSING ==========
    # For any other request, use the AI agent to understand and respond
    
    if ForensicAgent.is_available():
        # Get current artifacts for context
        artifacts = st.session_state.get("artifacts", {})
        
        # Analyze the request
        analysis = ForensicAgent.analyze_request(user_input, artifacts)
        action = analysis.get("action", "help")
        
        if action == "extract":
            # AI determined this is a data extraction request
            adb_command = analysis.get("adb_command", "")
            description = analysis.get("description", "Data extraction")
            data_type = analysis.get("data_type", "extracted_data")
            
            if adb_command:
                return ForensicAgent.execute_extraction(adb_command, description, data_type)
            else:
                return "## EXTRACTION ERROR\n\nCould not determine the appropriate command. Please be more specific or use a direct ADB command."
        
        elif action == "analyze":
            # AI determined this is an artifact analysis request
            artifact_names = analysis.get("artifact_names", ["all"])
            analysis_type = analysis.get("analysis_type", "explain")
            query = analysis.get("query", user_input)
            
            return ForensicAgent.analyze_artifacts(artifacts, artifact_names, analysis_type, query)
        
        elif action == "search":
            # AI determined this needs web search
            search_query = analysis.get("query", user_input)
            return search_web_tavily(search_query)
        
        elif action == "plan":
            # AI created a multi-step investigation plan
            st.session_state.pending_plan = analysis
            st.session_state.pending_plan_request = user_input
            return ForensicAgent.create_and_display_plan(analysis)
        
        elif action == "error":
            error_msg = analysis.get("message", "An error occurred")
            return f"## AGENT ERROR\n\n{error_msg}\n\n**Available quick commands:** device info, sms, call log, contacts, installed apps, logcat, battery, storage, network, processes"
        
        else:
            # Help or unknown action
            return analysis.get("message", get_help_message())
    
    else:
        # AI not available - provide helpful message
        return f"""## AI AGENT UNAVAILABLE

The intelligent agent requires configuration. Please ensure:
1. **GEMINI_API_KEY** is set in your `.env` file
2. Install: `pip install langchain-google-genai`

**Available Quick Commands (no AI required):**
- `device info` - Device identification
- `installed apps` - Application list
- `sms` - SMS messages
- `call log` - Call history
- `contacts` - Contact database
- `logcat` - System logs
- `battery` - Battery status
- `storage` - Storage info
- `network` - Network config
- `processes` - Running processes
- `adb shell [command]` - Direct ADB command

**Your request:** {user_input}

Please use one of the quick commands above, or configure the AI agent for intelligent processing."""


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
    ai_status = "ACTIVE" if ForensicAgent.is_available() else "INACTIVE"
    tavily_status = "ACTIVE" if TAVILY_AVAILABLE and os.getenv("TAVILY_API_KEY") else "INACTIVE"
    
    return f"""## INTELLIGENT FORENSIC AGENT

**AI Agent Status:** {ai_status} | **Web Search (Tavily):** {tavily_status}

### Quick Commands (No AI Required)
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
| adb shell [cmd] | Execute any ADB command |

### AI-Powered Capabilities (When Active)
The intelligent agent can understand natural language requests:

**Data Extraction Examples:**
- "Fetch all images from this device"
- "Get the browser history"
- "Extract WhatsApp databases"
- "Pull all media files"
- "Get calendar events"

**Artifact Analysis Examples:**
- "What's important in the call log data?"
- "Find any suspicious numbers in the contacts"
- "Analyze the SMS for evidence of fraud"
- "Which artifacts are most valuable for this case?"

**Investigation Planning Examples:**
- "Investigate this device for evidence of financial fraud"
- "Perform complete device triage"
- "Collect all communication data for timeline analysis"

**Web Search Examples:**
- "How to extract deleted messages from Android"
- "What is SQLite database forensics"
- "Search for mobile forensics best practices"

**Note:** The agent will ask for your approval before executing multi-step investigation plans.
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
                        # Execute the step using ForensicAgent
                        adb_cmd = step.get('adb_command', step.get('command', ''))
                        description = step.get('description', step.get('command', ''))
                        result = ForensicAgent.execute_extraction(adb_cmd, description, 'plan_step')
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
        
        if ForensicAgent.is_available():
            st.markdown('<span style="color: #276749; font-weight: bold;">🤖 FORENSIC AI: ACTIVE</span>', unsafe_allow_html=True)
            st.text("Ask me anything about\nforensic data extraction\nor artifact analysis")
        else:
            st.markdown('<span style="color: #c53030; font-weight: bold;">AI: INACTIVE</span>', unsafe_allow_html=True)
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
