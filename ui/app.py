"""
FIA Android Forensics Framework - Professional Investigation Console
Federal Investigation Agency - Digital Forensics Unit

Classification: Official Use Only
Version: 2.0.0
"""

import asyncio
import json
import os
import subprocess
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Generator, Optional

import gradio as gr
from dotenv import load_dotenv

# Add parent to path for imports
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

# Load environment
load_dotenv()

# Configuration
OUTPUT_DIR = Path(os.getenv("OUTPUT_DIR", "./output"))
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


class DeviceMonitor:
    """Android device connection monitoring service."""
    
    def __init__(self):
        self.connected = False
        self.device_info = {}
        self.last_check = None
    
    def check_adb(self) -> bool:
        """Verify ADB availability."""
        try:
            result = subprocess.run(
                ["adb", "version"],
                capture_output=True, text=True, timeout=5
            )
            return result.returncode == 0
        except Exception:
            return False
    
    def get_connected_devices(self) -> list:
        """Enumerate connected Android devices."""
        try:
            result = subprocess.run(
                ["adb", "devices", "-l"],
                capture_output=True, text=True, timeout=10
            )
            
            devices = []
            for line in result.stdout.strip().split("\n")[1:]:
                if line.strip() and "device" in line:
                    parts = line.split()
                    if len(parts) >= 2 and parts[1] == "device":
                        device_id = parts[0]
                        model = "Unknown"
                        for part in parts[2:]:
                            if part.startswith("model:"):
                                model = part.split(":")[1]
                                break
                        devices.append({
                            "id": device_id,
                            "model": model,
                            "status": "connected"
                        })
            
            return devices
        except Exception:
            return []
    
    def get_device_details(self, device_id: str = None) -> dict:
        """Retrieve detailed device properties."""
        try:
            cmd = ["adb"]
            if device_id:
                cmd.extend(["-s", device_id])
            
            info = {}
            
            props = [
                ("manufacturer", "ro.product.manufacturer"),
                ("model", "ro.product.model"),
                ("android_version", "ro.build.version.release"),
                ("serial", "ro.serialno"),
                ("build_id", "ro.build.id"),
                ("security_patch", "ro.build.version.security_patch"),
                ("sdk_version", "ro.build.version.sdk"),
            ]
            
            for key, prop in props:
                result = subprocess.run(
                    cmd + ["shell", "getprop", prop],
                    capture_output=True, text=True, timeout=5
                )
                info[key] = result.stdout.strip() or "N/A"
            
            return info
            
        except Exception as e:
            return {"error": str(e)}
    
    def refresh_status(self) -> dict:
        """Refresh device connection status."""
        self.last_check = datetime.now()
        
        adb_available = self.check_adb()
        if not adb_available:
            self.connected = False
            self.device_info = {}
            return {
                "adb_available": False,
                "connected": False,
                "status": "error",
                "message": "ADB not found. Install Android Platform Tools."
            }
        
        devices = self.get_connected_devices()
        
        if not devices:
            self.connected = False
            self.device_info = {}
            return {
                "adb_available": True,
                "connected": False,
                "status": "waiting",
                "message": "No devices connected. Connect device with USB debugging enabled."
            }
        
        device = devices[0]
        self.connected = True
        self.device_info = self.get_device_details(device["id"])
        self.device_info["device_id"] = device["id"]
        
        return {
            "adb_available": True,
            "connected": True,
            "status": "ready",
            "device_count": len(devices),
            "device_info": self.device_info,
            "message": f"Device connected: {self.device_info.get('manufacturer', '')} {self.device_info.get('model', '')}"
        }


class ForensicInvestigator:
    """
    Professional forensic investigation agent.
    Implements Human-in-the-Loop workflow for evidence handling.
    """
    
    def __init__(self):
        self.device_monitor = DeviceMonitor()
        self.conversation_history = []
        self.pending_tools = []
        self.audit_log = []
        self.current_case = None
        self.llm = None
        self.tools = []
        self.initialized = False
    
    def log_audit(self, message: str, level: str = "INFO", action: str = None):
        """Record entry in audit log with chain of custody compliance."""
        entry = {
            "timestamp": datetime.now().isoformat(),
            "level": level,
            "message": message,
            "action": action,
            "case_id": self.current_case.get("case_number") if self.current_case else None
        }
        self.audit_log.append(entry)
        return entry
    
    async def initialize(self):
        """Initialize investigation agent with LLM."""
        if self.initialized:
            return True
        
        try:
            from langchain_google_genai import ChatGoogleGenerativeAI
            
            api_key = os.getenv("GEMINI_API_KEY")
            if not api_key:
                self.log_audit("GEMINI_API_KEY not configured", "ERROR")
                return False
            
            self.llm = ChatGoogleGenerativeAI(
                model=os.getenv("GEMINI_MODEL", "gemini-2.0-flash"),
                google_api_key=api_key,
                temperature=0.1,
                max_tokens=8192,
            )
            
            self.log_audit("Investigation agent initialized", "INFO", "SYSTEM_INIT")
            self.initialized = True
            return True
            
        except Exception as e:
            self.log_audit(f"Initialization failed: {str(e)}", "ERROR")
            return False
    
    def start_case(self, case_number: str = None, examiner: str = None, 
                   agency: str = None, notes: str = "") -> dict:
        """Initialize new forensic investigation case."""
        self.current_case = {
            "case_number": case_number or f"FIA-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
            "examiner": examiner or os.getenv("INVESTIGATOR_NAME", "Examiner"),
            "agency": agency or "Federal Investigation Agency",
            "start_time": datetime.now().isoformat(),
            "notes": notes,
            "status": "ACTIVE",
            "evidence": [],
            "findings": [],
            "chain_of_custody": []
        }
        self.conversation_history = []
        self.audit_log = []
        self.log_audit(
            f"Case initiated: {self.current_case['case_number']}", 
            "INFO", 
            "CASE_OPENED"
        )
        return self.current_case
    
    async def process_query(
        self, 
        message: str, 
        require_approval: bool = True
    ) -> Generator[dict, None, None]:
        """
        Process investigation query with optional approval workflow.
        """
        if not self.initialized:
            await self.initialize()
        
        if not self.current_case:
            self.start_case()
        
        self.log_audit(f"Query received: {message[:80]}...", "INFO", "USER_INPUT")
        
        from langchain_core.messages import HumanMessage, SystemMessage, AIMessage
        
        system_prompt = """You are an Android Digital Forensics Specialist assigned to the Federal Investigation Agency (FIA).

PROTOCOL:
1. Maintain strict chain of custody for all evidence
2. Document every action with timestamps
3. Preserve original data - work on copies when possible
4. Follow legal procedures for evidence handling
5. Report findings objectively without speculation

CAPABILITIES:
- Device identification and status verification
- Forensic data acquisition and backup
- Database analysis (contacts, SMS, call logs)
- Application data extraction (messaging, social media)
- System log analysis and timeline reconstruction
- Evidence report generation

When planning investigative actions:
1. State the objective clearly
2. List specific tools/commands to be executed
3. Explain potential impact on device data
4. Wait for authorization before proceeding

Current device status and case context will be provided."""

        messages = [SystemMessage(content=system_prompt)]
        
        # Add device context
        device_status = self.device_monitor.refresh_status()
        context = f"\n\n[DEVICE STATUS]\n{json.dumps(device_status, indent=2)}"
        context += f"\n\n[CASE INFO]\n{json.dumps(self.current_case, indent=2, default=str)}"
        
        # Add conversation history
        for entry in self.conversation_history[-10:]:
            if entry["role"] == "user":
                messages.append(HumanMessage(content=entry["content"]))
            else:
                messages.append(AIMessage(content=entry["content"]))
        
        messages.append(HumanMessage(content=message + context))
        
        self.conversation_history.append({
            "role": "user",
            "content": message,
            "timestamp": datetime.now().isoformat()
        })
        
        yield {"type": "status", "message": "Processing query..."}
        
        try:
            response = await asyncio.to_thread(self.llm.invoke, messages)
            
            response_text = response.content if hasattr(response, "content") else str(response)
            
            # Check for action indicators
            action_indicators = [
                "I will use", "I'll execute", "Running command",
                "Executing", "Let me run", "I'll analyze", "I will extract",
                "Pulling data", "Creating backup"
            ]
            
            needs_approval = require_approval and any(
                indicator.lower() in response_text.lower() 
                for indicator in action_indicators
            )
            
            if needs_approval:
                yield {
                    "type": "approval_required",
                    "message": response_text,
                    "pending_action": True
                }
                self.log_audit("Action pending approval", "INFO", "APPROVAL_PENDING")
            else:
                yield {
                    "type": "response",
                    "message": response_text
                }
            
            self.conversation_history.append({
                "role": "assistant",
                "content": response_text,
                "timestamp": datetime.now().isoformat()
            })
            
            self.log_audit(f"Response generated ({len(response_text)} chars)", "INFO", "AI_RESPONSE")
            
        except Exception as e:
            error_msg = f"Processing error: {str(e)}"
            self.log_audit(error_msg, "ERROR", "SYSTEM_ERROR")
            yield {"type": "error", "message": error_msg}
    
    def authorize_action(self) -> dict:
        """Authorize pending forensic action."""
        self.log_audit("Action authorized by examiner", "INFO", "ACTION_AUTHORIZED")
        return {"authorized": True, "message": "Action authorized. Executing..."}
    
    def deny_action(self, reason: str = "") -> dict:
        """Deny pending forensic action."""
        self.log_audit(f"Action denied: {reason}", "WARNING", "ACTION_DENIED")
        return {"authorized": False, "message": f"Action denied. {reason}"}
    
    def get_audit_log(self) -> str:
        """Retrieve formatted audit log."""
        lines = []
        for entry in self.audit_log:
            ts = entry["timestamp"].split("T")[1][:8]
            level = entry["level"].ljust(7)
            action = f"[{entry['action']}]" if entry.get('action') else ""
            lines.append(f"{ts} {level} {action} {entry['message']}")
        return "\n".join(lines) if lines else "No audit entries"
    
    def export_case(self, output_path: str = None) -> str:
        """Export complete case file with chain of custody."""
        if not self.current_case:
            return None
        
        export_data = {
            "case_file": self.current_case,
            "transcript": self.conversation_history,
            "audit_log": self.audit_log,
            "export_timestamp": datetime.now().isoformat(),
            "export_format_version": "2.0"
        }
        
        if not output_path:
            output_path = OUTPUT_DIR / f"{self.current_case['case_number']}_case_file.json"
        
        with open(output_path, "w") as f:
            json.dump(export_data, f, indent=2, default=str)
        
        self.log_audit(f"Case exported: {output_path}", "INFO", "CASE_EXPORTED")
        return str(output_path)


# Global investigator instance
investigator = ForensicInvestigator()


def get_device_status():
    """Retrieve current device status for display."""
    status = investigator.device_monitor.refresh_status()
    
    if not status.get("adb_available"):
        return (
            "## STATUS: ERROR\nADB Not Available",
            "Android Debug Bridge (ADB) not found in system PATH.\n\nAction Required:\n- Install Android Platform Tools\n- Verify ADB is accessible from command line",
            gr.update(interactive=False),
            gr.update(interactive=False)
        )
    
    if not status.get("connected"):
        return (
            "## STATUS: AWAITING DEVICE",
            "No Android device detected.\n\nAction Required:\n- Connect device via USB\n- Enable USB Debugging in Developer Options\n- Authorize this computer on device",
            gr.update(interactive=False),
            gr.update(interactive=False)
        )
    
    info = status.get("device_info", {})
    device_text = f"""## STATUS: DEVICE CONNECTED

| Property | Value |
|----------|-------|
| Manufacturer | {info.get('manufacturer', 'N/A')} |
| Model | {info.get('model', 'N/A')} |
| Android Version | {info.get('android_version', 'N/A')} |
| SDK Version | {info.get('sdk_version', 'N/A')} |
| Security Patch | {info.get('security_patch', 'N/A')} |
| Serial Number | {info.get('serial', 'N/A')} |
| Device ID | {info.get('device_id', 'N/A')} |

Last Check: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
"""
    
    return (
        "## STATUS: READY",
        device_text,
        gr.update(interactive=True),
        gr.update(interactive=True)
    )


async def handle_query(message: str, history: list, require_approval: bool):
    """Process investigation query."""
    if not message.strip():
        return history, "", investigator.get_audit_log()
    
    history = history or []
    history.append([message, None])
    
    full_response = ""
    async for update in investigator.process_query(message, require_approval):
        if update["type"] in ["response", "approval_required"]:
            full_response = update["message"]
        elif update["type"] == "error":
            full_response = f"ERROR: {update['message']}"
    
    history[-1] = [message, full_response]
    
    return history, "", investigator.get_audit_log()


def sync_handle_query(message: str, history: list, require_approval: bool):
    """Synchronous wrapper for query handling."""
    return asyncio.run(handle_query(message, history, require_approval))


def initialize_case(case_number: str, examiner: str, agency: str, notes: str):
    """Start new investigation case."""
    case = investigator.start_case(case_number, examiner, agency, notes)
    return (
        [],
        f"Case **{case['case_number']}** initialized.\n\nExaminer: {case['examiner']}\nAgency: {case['agency']}\nStatus: {case['status']}",
        investigator.get_audit_log()
    )


def export_case_file():
    """Export current case."""
    path = investigator.export_case()
    if path:
        return f"Case file exported: {path}"
    return "No active case to export."


# Professional UI Theme
PROFESSIONAL_THEME = gr.themes.Base(
    primary_hue=gr.themes.colors.slate,
    secondary_hue=gr.themes.colors.blue,
    neutral_hue=gr.themes.colors.gray,
    font=gr.themes.GoogleFont("Inter"),
    font_mono=gr.themes.GoogleFont("JetBrains Mono"),
).set(
    body_background_fill="#0f172a",
    body_background_fill_dark="#0f172a",
    body_text_color="#e2e8f0",
    body_text_color_dark="#e2e8f0",
    button_primary_background_fill="#1e40af",
    button_primary_background_fill_hover="#1d4ed8",
    button_primary_text_color="#ffffff",
    button_secondary_background_fill="#334155",
    button_secondary_background_fill_hover="#475569",
    button_secondary_text_color="#e2e8f0",
    block_background_fill="#1e293b",
    block_background_fill_dark="#1e293b",
    block_border_color="#334155",
    block_label_text_color="#94a3b8",
    block_title_text_color="#f1f5f9",
    input_background_fill="#0f172a",
    input_background_fill_dark="#0f172a",
    input_border_color="#334155",
    input_placeholder_color="#64748b",
    panel_background_fill="#1e293b",
    panel_border_color="#334155",
)

PROFESSIONAL_CSS = """
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono&display=swap');

* {
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
}

.header-section {
    background: linear-gradient(135deg, #1e3a5f 0%, #0f172a 100%);
    padding: 24px 32px;
    border-radius: 8px;
    border: 1px solid #334155;
    margin-bottom: 24px;
}

.header-title {
    color: #f8fafc;
    font-size: 1.5rem;
    font-weight: 700;
    margin: 0;
    letter-spacing: -0.02em;
}

.header-subtitle {
    color: #94a3b8;
    font-size: 0.875rem;
    margin-top: 4px;
}

.status-panel {
    background: #1e293b;
    border: 1px solid #334155;
    border-radius: 8px;
    padding: 16px;
}

.status-ready {
    border-left: 4px solid #22c55e;
}

.status-waiting {
    border-left: 4px solid #eab308;
}

.status-error {
    border-left: 4px solid #ef4444;
}

.case-panel {
    background: #1e293b;
    border: 1px solid #334155;
    border-radius: 8px;
    padding: 20px;
}

.chat-container {
    background: #0f172a;
    border: 1px solid #334155;
    border-radius: 8px;
}

.message-user {
    background: #1e40af !important;
    color: #ffffff !important;
    border-radius: 8px 8px 0 8px !important;
}

.message-bot {
    background: #334155 !important;
    color: #e2e8f0 !important;
    border-radius: 8px 8px 8px 0 !important;
}

.audit-log {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.75rem;
    background: #0f172a;
    color: #94a3b8;
    border: 1px solid #334155;
    border-radius: 4px;
    padding: 12px;
}

.action-button {
    transition: all 0.2s ease;
}

.action-button:hover {
    transform: translateY(-1px);
}

.quick-action {
    background: #334155 !important;
    border: 1px solid #475569 !important;
    color: #e2e8f0 !important;
    font-size: 0.8rem !important;
    padding: 8px 16px !important;
}

.quick-action:hover {
    background: #475569 !important;
}

.section-label {
    color: #64748b;
    font-size: 0.75rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    margin-bottom: 8px;
}

.divider {
    border-top: 1px solid #334155;
    margin: 16px 0;
}

footer {
    display: none !important;
}
"""


def create_interface():
    """Build professional investigation interface."""
    
    with gr.Blocks(
        title="FIA Digital Forensics"
    ) as interface:
        
        # Header
        gr.HTML("""
        <div class="header-section">
            <div style="display: flex; justify-content: space-between; align-items: center;">
                <div>
                    <h1 class="header-title">DIGITAL FORENSICS INVESTIGATION CONSOLE</h1>
                    <p class="header-subtitle">Federal Investigation Agency | Android Evidence Acquisition & Analysis</p>
                </div>
                <div style="text-align: right; color: #64748b; font-size: 0.75rem;">
                    <div>OFFICIAL USE ONLY</div>
                    <div style="font-family: 'JetBrains Mono', monospace;">v2.0.0</div>
                </div>
            </div>
        </div>
        """)
        
        with gr.Row():
            # Left Panel - Device & Case Management
            with gr.Column(scale=1, min_width=350):
                
                # Device Status
                gr.HTML('<div class="section-label">DEVICE STATUS</div>')
                status_header = gr.Markdown("## STATUS: CHECKING...")
                device_info = gr.Markdown("Verifying device connection...", elem_classes="status-panel")
                refresh_btn = gr.Button("Refresh Status", variant="secondary", size="sm")
                
                gr.HTML('<div class="divider"></div>')
                
                # Case Information
                gr.HTML('<div class="section-label">CASE INFORMATION</div>')
                
                with gr.Group(elem_classes="case-panel"):
                    case_input = gr.Textbox(
                        label="Case Number",
                        placeholder="Auto-generated if blank",
                        max_lines=1
                    )
                    examiner_input = gr.Textbox(
                        label="Examiner",
                        value=os.getenv("INVESTIGATOR_NAME", ""),
                        max_lines=1
                    )
                    agency_input = gr.Textbox(
                        label="Agency/Unit",
                        value="Federal Investigation Agency",
                        max_lines=1
                    )
                    notes_input = gr.Textbox(
                        label="Case Notes",
                        placeholder="Brief description",
                        lines=2
                    )
                    
                    with gr.Row():
                        new_case_btn = gr.Button("Initialize Case", variant="primary", size="sm")
                        export_btn = gr.Button("Export", variant="secondary", size="sm")
                
                case_status = gr.Markdown("")
                export_status = gr.Markdown("")
            
            # Right Panel - Investigation Interface
            with gr.Column(scale=2):
                
                gr.HTML('<div class="section-label">INVESTIGATION INTERFACE</div>')
                
                # Controls
                with gr.Row():
                    approval_toggle = gr.Checkbox(
                        label="Human-in-the-Loop Authorization",
                        value=True,
                        info="Require approval before executing forensic actions"
                    )
                
                # Chat Interface
                chat_display = gr.Chatbot(
                    height=380,
                    show_label=False,
                    elem_classes="chat-container"
                )
                
                with gr.Row():
                    query_input = gr.Textbox(
                        placeholder="Enter investigation query or command...",
                        show_label=False,
                        scale=5,
                        interactive=False
                    )
                    submit_btn = gr.Button(
                        "Submit",
                        variant="primary",
                        scale=1,
                        interactive=False
                    )
                
                # Quick Actions
                gr.HTML('<div class="section-label" style="margin-top: 16px;">QUICK ACTIONS</div>')
                with gr.Row():
                    gr.Button("Device Info", size="sm", elem_classes="quick-action").click(
                        lambda h: sync_handle_query("Provide comprehensive device identification and status", h, True),
                        inputs=[chat_display],
                        outputs=[chat_display, query_input]
                    )
                    gr.Button("Installed Apps", size="sm", elem_classes="quick-action").click(
                        lambda h: sync_handle_query("List all installed applications with package names", h, True),
                        inputs=[chat_display],
                        outputs=[chat_display, query_input]
                    )
                    gr.Button("Communications", size="sm", elem_classes="quick-action").click(
                        lambda h: sync_handle_query("Analyze messaging applications and communication logs", h, True),
                        inputs=[chat_display],
                        outputs=[chat_display, query_input]
                    )
                    gr.Button("System Logs", size="sm", elem_classes="quick-action").click(
                        lambda h: sync_handle_query("Extract and analyze system logs for relevant activity", h, True),
                        inputs=[chat_display],
                        outputs=[chat_display, query_input]
                    )
        
        # Audit Log Section
        gr.HTML('<div class="section-label" style="margin-top: 24px;">AUDIT LOG</div>')
        audit_output = gr.Textbox(
            show_label=False,
            lines=6,
            max_lines=10,
            interactive=False,
            elem_classes="audit-log"
        )
        
        # Event Handlers
        refresh_btn.click(
            get_device_status,
            outputs=[status_header, device_info, query_input, submit_btn]
        )
        
        new_case_btn.click(
            initialize_case,
            inputs=[case_input, examiner_input, agency_input, notes_input],
            outputs=[chat_display, case_status, audit_output]
        )
        
        export_btn.click(
            export_case_file,
            outputs=[export_status]
        )
        
        submit_btn.click(
            sync_handle_query,
            inputs=[query_input, chat_display, approval_toggle],
            outputs=[chat_display, query_input, audit_output]
        )
        
        query_input.submit(
            sync_handle_query,
            inputs=[query_input, chat_display, approval_toggle],
            outputs=[chat_display, query_input, audit_output]
        )
        
        # Auto-refresh on load
        interface.load(
            get_device_status,
            outputs=[status_header, device_info, query_input, submit_btn]
        )
    
    return interface


def launch(share: bool = False, port: int = 7860):
    """Launch the investigation console."""
    print("""
    ================================================================
         FIA DIGITAL FORENSICS INVESTIGATION CONSOLE
         Federal Investigation Agency
    ----------------------------------------------------------------
         Status: Initializing...
         Port: """ + str(port) + """
    ================================================================
    """)
    
    interface = create_interface()
    interface.launch(
        share=share,
        server_port=port,
        show_error=True,
        inbrowser=True
    )


if __name__ == "__main__":
    launch()
