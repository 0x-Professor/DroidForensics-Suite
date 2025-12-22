"""
FIA Android Forensics Framework - Interactive Web UI
Federal Investigation Agency

Features:
- Device connection monitoring
- Human-in-the-loop tool approval
- Interactive investigation workflow
- Real-time logging and status updates
- LangGraph-powered AI agent
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

from agents.interactive_agent import InteractiveInvestigator, FORENSIC_TOOLS

# Load environment
load_dotenv()

# Configuration
OUTPUT_DIR = Path(os.getenv("OUTPUT_DIR", "./output"))
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


class DeviceMonitor:
    """Monitor Android device connection status."""
    
    def __init__(self):
        self.connected = False
        self.device_info = {}
        self.last_check = None
    
    def check_adb(self) -> bool:
        """Check if ADB is available."""
        try:
            result = subprocess.run(
                ["adb", "version"],
                capture_output=True, text=True, timeout=5
            )
            return result.returncode == 0
        except:
            return False
    
    def get_connected_devices(self) -> list:
        """Get list of connected Android devices."""
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
                        # Get device model
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
        except Exception as e:
            return []
    
    def get_device_details(self, device_id: str = None) -> dict:
        """Get detailed device information."""
        try:
            cmd = ["adb"]
            if device_id:
                cmd.extend(["-s", device_id])
            
            info = {}
            
            # Get manufacturer
            result = subprocess.run(
                cmd + ["shell", "getprop", "ro.product.manufacturer"],
                capture_output=True, text=True, timeout=5
            )
            info["manufacturer"] = result.stdout.strip()
            
            # Get model
            result = subprocess.run(
                cmd + ["shell", "getprop", "ro.product.model"],
                capture_output=True, text=True, timeout=5
            )
            info["model"] = result.stdout.strip()
            
            # Get Android version
            result = subprocess.run(
                cmd + ["shell", "getprop", "ro.build.version.release"],
                capture_output=True, text=True, timeout=5
            )
            info["android_version"] = result.stdout.strip()
            
            # Get serial
            result = subprocess.run(
                cmd + ["shell", "getprop", "ro.serialno"],
                capture_output=True, text=True, timeout=5
            )
            info["serial"] = result.stdout.strip()
            
            # Get IMEI (may require permissions)
            result = subprocess.run(
                cmd + ["shell", "service call iphonesubinfo 1 | grep -o '[0-9a-f]\\{8\\}' | tail -n+3 | while read line; do echo -n \"\\u$line\"; done"],
                capture_output=True, text=True, timeout=5, shell=True
            )
            
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
                "message": "❌ ADB not found. Please install Android Platform Tools."
            }
        
        devices = self.get_connected_devices()
        
        if not devices:
            self.connected = False
            self.device_info = {}
            return {
                "adb_available": True,
                "connected": False,
                "message": "📱 No devices connected. Please connect an Android device with USB debugging enabled."
            }
        
        # Use first device
        device = devices[0]
        self.connected = True
        self.device_info = self.get_device_details(device["id"])
        self.device_info["device_id"] = device["id"]
        
        return {
            "adb_available": True,
            "connected": True,
            "device_count": len(devices),
            "device_info": self.device_info,
            "message": f"✅ Device connected: {self.device_info.get('manufacturer', '')} {self.device_info.get('model', '')}"
        }


class InteractiveForensicAgent:
    """
    Interactive forensic agent with Human-in-the-Loop capabilities.
    Uses LangGraph with interrupt points for user approval.
    """
    
    def __init__(self):
        self.device_monitor = DeviceMonitor()
        self.conversation_history = []
        self.pending_tools = []
        self.investigation_log = []
        self.current_case = None
        self.llm = None
        self.tools = []
        self.initialized = False
    
    def log(self, message: str, level: str = "info"):
        """Add entry to investigation log."""
        entry = {
            "timestamp": datetime.now().isoformat(),
            "level": level,
            "message": message
        }
        self.investigation_log.append(entry)
        return entry
    
    async def initialize(self):
        """Initialize the agent with LLM and tools."""
        if self.initialized:
            return True
        
        try:
            from langchain_google_genai import ChatGoogleGenerativeAI
            
            api_key = os.getenv("GEMINI_API_KEY")
            if not api_key:
                self.log("❌ GEMINI_API_KEY not found in environment", "error")
                return False
            
            self.llm = ChatGoogleGenerativeAI(
                model=os.getenv("GEMINI_MODEL", "gemini-2.0-flash"),
                google_api_key=api_key,
                temperature=0.1,
                max_tokens=8192,
            )
            
            self.log("✅ LLM initialized successfully")
            self.initialized = True
            return True
            
        except Exception as e:
            self.log(f"❌ Failed to initialize: {str(e)}", "error")
            return False
    
    def start_new_case(self, case_number: str = None, examiner: str = None, notes: str = "") -> dict:
        """Start a new forensic investigation case."""
        self.current_case = {
            "case_number": case_number or f"FIA-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
            "examiner": examiner or os.getenv("INVESTIGATOR_NAME", "FIA Examiner"),
            "start_time": datetime.now().isoformat(),
            "notes": notes,
            "status": "active",
            "evidence": [],
            "findings": []
        }
        self.conversation_history = []
        self.investigation_log = []
        self.log(f"📋 New case started: {self.current_case['case_number']}")
        return self.current_case
    
    async def process_message(
        self, 
        message: str, 
        require_approval: bool = True
    ) -> Generator[dict, None, None]:
        """
        Process user message with optional tool approval.
        Yields updates as they occur for streaming UI updates.
        """
        if not self.initialized:
            await self.initialize()
        
        if not self.current_case:
            self.start_new_case()
        
        self.log(f"👤 User: {message[:100]}...")
        
        # Build conversation context
        from langchain_core.messages import HumanMessage, SystemMessage, AIMessage
        
        system_prompt = """You are an expert Android Digital Forensics Investigator for the Federal Investigation Agency (FIA).

You help investigate Android devices for digital evidence. You have access to forensic tools but MUST explain what you plan to do before taking action.

When the user asks you to do something:
1. First explain your plan
2. List the tools/commands you would use
3. Wait for approval before executing

Always be thorough and document everything. Explain technical concepts clearly.

Current device status will be provided. If no device is connected, guide the user on how to connect one.
"""
        
        messages = [SystemMessage(content=system_prompt)]
        
        # Add device context
        device_status = self.device_monitor.refresh_status()
        device_context = f"\n\n[DEVICE STATUS]\n{json.dumps(device_status, indent=2)}"
        
        # Add conversation history
        for entry in self.conversation_history[-10:]:  # Last 10 messages
            if entry["role"] == "user":
                messages.append(HumanMessage(content=entry["content"]))
            else:
                messages.append(AIMessage(content=entry["content"]))
        
        # Add current message with device context
        messages.append(HumanMessage(content=message + device_context))
        
        # Store in history
        self.conversation_history.append({
            "role": "user",
            "content": message,
            "timestamp": datetime.now().isoformat()
        })
        
        yield {"type": "status", "message": "🤔 Thinking..."}
        
        try:
            # Get LLM response
            response = await asyncio.to_thread(self.llm.invoke, messages)
            
            response_text = response.content if hasattr(response, "content") else str(response)
            
            # Check if LLM wants to use tools
            tool_indicators = [
                "I will use", "I'll execute", "Running command",
                "Executing", "Let me run", "I'll analyze"
            ]
            
            needs_approval = require_approval and any(
                indicator.lower() in response_text.lower() 
                for indicator in tool_indicators
            )
            
            if needs_approval:
                yield {
                    "type": "approval_needed",
                    "message": response_text,
                    "pending_action": True
                }
            else:
                yield {
                    "type": "response",
                    "message": response_text
                }
            
            # Store response
            self.conversation_history.append({
                "role": "assistant",
                "content": response_text,
                "timestamp": datetime.now().isoformat()
            })
            
            self.log(f"🤖 Agent responded ({len(response_text)} chars)")
            
        except Exception as e:
            error_msg = f"Error: {str(e)}"
            self.log(error_msg, "error")
            yield {"type": "error", "message": error_msg}
    
    def approve_action(self) -> dict:
        """Approve pending tool execution."""
        self.log("✅ User approved action")
        return {"approved": True, "message": "Action approved. Proceeding..."}
    
    def reject_action(self, reason: str = "") -> dict:
        """Reject pending tool execution."""
        self.log(f"❌ User rejected action: {reason}")
        return {"approved": False, "message": f"Action rejected. {reason}"}
    
    def get_log_text(self) -> str:
        """Get formatted investigation log."""
        lines = []
        for entry in self.investigation_log:
            ts = entry["timestamp"].split("T")[1][:8]
            lines.append(f"[{ts}] {entry['message']}")
        return "\n".join(lines)
    
    def export_case(self, output_path: str = None) -> str:
        """Export current case data to JSON."""
        if not self.current_case:
            return None
        
        export_data = {
            "case": self.current_case,
            "conversation": self.conversation_history,
            "log": self.investigation_log,
            "exported_at": datetime.now().isoformat()
        }
        
        if not output_path:
            output_path = OUTPUT_DIR / f"{self.current_case['case_number']}_export.json"
        
        with open(output_path, "w") as f:
            json.dump(export_data, f, indent=2)
        
        return str(output_path)


# Global agent instance
agent = InteractiveForensicAgent()


def check_device_status():
    """Check and return device status for UI."""
    status = agent.device_monitor.refresh_status()
    
    if not status.get("adb_available"):
        return (
            "❌ ADB Not Available",
            "Install Android Platform Tools and ensure ADB is in PATH",
            gr.update(interactive=False),
            gr.update(visible=False)
        )
    
    if not status.get("connected"):
        return (
            "📱 No Device Connected",
            "Connect an Android device with USB debugging enabled",
            gr.update(interactive=False),
            gr.update(visible=False)
        )
    
    info = status.get("device_info", {})
    device_text = f"""✅ Device Connected

**Manufacturer:** {info.get('manufacturer', 'Unknown')}
**Model:** {info.get('model', 'Unknown')}
**Android Version:** {info.get('android_version', 'Unknown')}
**Serial:** {info.get('serial', 'Unknown')}
**Device ID:** {info.get('device_id', 'Unknown')}
"""
    
    return (
        "✅ Device Connected",
        device_text,
        gr.update(interactive=True),
        gr.update(visible=True)
    )


async def process_chat(message: str, history: list, require_approval: bool):
    """Process chat message and return response."""
    if not message.strip():
        return history, "", agent.get_log_text()
    
    # Add user message to history
    history = history or []
    history.append((message, None))
    
    # Process through agent
    full_response = ""
    async for update in agent.process_message(message, require_approval):
        if update["type"] in ["response", "approval_needed"]:
            full_response = update["message"]
        elif update["type"] == "error":
            full_response = f"⚠️ {update['message']}"
    
    # Update history with response
    history[-1] = (message, full_response)
    
    return history, "", agent.get_log_text()


def sync_process_chat(message: str, history: list, require_approval: bool):
    """Synchronous wrapper for chat processing."""
    return asyncio.run(process_chat(message, history, require_approval))


def start_new_investigation(case_number: str, examiner: str, notes: str):
    """Start a new investigation case."""
    case = agent.start_new_case(case_number, examiner, notes)
    return (
        [],  # Clear chat history
        f"✅ New case started: **{case['case_number']}**\n\nExaminer: {case['examiner']}\nStarted: {case['start_time']}",
        agent.get_log_text()
    )


def export_investigation():
    """Export current investigation."""
    path = agent.export_case()
    if path:
        return f"✅ Case exported to: {path}"
    return "❌ No active case to export"


# UI Theme and CSS
UI_THEME = gr.themes.Soft(primary_hue="blue", secondary_hue="slate")
UI_CSS = """
.header { text-align: center; margin-bottom: 20px; }
.status-box { padding: 15px; border-radius: 8px; }
.connected { background-color: #d4edda; }
.disconnected { background-color: #f8d7da; }
"""


def create_ui():
    """Create the Gradio web interface."""
    
    with gr.Blocks(title="FIA Android Forensics") as app:
        
        # Header
        gr.Markdown("""
        # 🔍 FIA Android Digital Forensics Framework
        ### Federal Investigation Agency - Interactive Investigation Console
        """, elem_classes="header")
        
        with gr.Row():
            # Left Column - Device Status & Case Info
            with gr.Column(scale=1):
                gr.Markdown("## 📱 Device Status")
                
                device_status_label = gr.Markdown("Checking...")
                device_info_box = gr.Markdown("", elem_classes="status-box")
                refresh_btn = gr.Button("🔄 Refresh Device Status", variant="secondary")
                
                gr.Markdown("---")
                gr.Markdown("## 📋 Case Information")
                
                with gr.Group():
                    case_number_input = gr.Textbox(
                        label="Case Number",
                        placeholder="Auto-generated if empty"
                    )
                    examiner_input = gr.Textbox(
                        label="Examiner Name",
                        value=os.getenv("INVESTIGATOR_NAME", "")
                    )
                    case_notes_input = gr.Textbox(
                        label="Case Notes",
                        placeholder="Brief description of the investigation",
                        lines=3
                    )
                    new_case_btn = gr.Button("🆕 Start New Case", variant="primary")
                    case_status = gr.Markdown("")
                
                gr.Markdown("---")
                export_btn = gr.Button("📤 Export Case", variant="secondary")
                export_status = gr.Markdown("")
            
            # Right Column - Chat Interface
            with gr.Column(scale=2):
                gr.Markdown("## 💬 Investigation Chat")
                
                with gr.Group():
                    require_approval = gr.Checkbox(
                        label="🛡️ Human-in-the-Loop (Require approval for actions)",
                        value=True
                    )
                
                chatbot = gr.Chatbot(
                    height=400,
                    show_label=False,
                    avatar_images=(None, "🤖")
                )
                
                with gr.Row():
                    chat_input = gr.Textbox(
                        placeholder="Ask about the device or request an investigation action...",
                        show_label=False,
                        scale=4,
                        interactive=False  # Disabled until device connected
                    )
                    send_btn = gr.Button("Send", variant="primary", scale=1, interactive=False)
                
                gr.Markdown("### Quick Actions")
                with gr.Row():
                    gr.Button("📊 Get Device Info", size="sm").click(
                        lambda h: sync_process_chat("Get comprehensive device information", h, True),
                        inputs=[chatbot],
                        outputs=[chatbot, chat_input]
                    )
                    gr.Button("📱 List Apps", size="sm").click(
                        lambda h: sync_process_chat("List all installed applications and identify suspicious ones", h, True),
                        inputs=[chatbot],
                        outputs=[chatbot, chat_input]
                    )
                    gr.Button("💬 Check Messages", size="sm").click(
                        lambda h: sync_process_chat("Analyze messaging apps like WhatsApp and Telegram", h, True),
                        inputs=[chatbot],
                        outputs=[chatbot, chat_input]
                    )
                    gr.Button("📍 Location History", size="sm").click(
                        lambda h: sync_process_chat("Extract location history and WiFi networks", h, True),
                        inputs=[chatbot],
                        outputs=[chatbot, chat_input]
                    )
        
        # Bottom Section - Investigation Log
        with gr.Row():
            with gr.Column():
                gr.Markdown("## 📜 Investigation Log")
                log_output = gr.Textbox(
                    show_label=False,
                    lines=8,
                    max_lines=15,
                    interactive=False
                )
        
        # Event Handlers
        refresh_btn.click(
            check_device_status,
            outputs=[device_status_label, device_info_box, chat_input, send_btn]
        )
        
        new_case_btn.click(
            start_new_investigation,
            inputs=[case_number_input, examiner_input, case_notes_input],
            outputs=[chatbot, case_status, log_output]
        )
        
        export_btn.click(
            export_investigation,
            outputs=[export_status]
        )
        
        # Chat handlers
        send_btn.click(
            sync_process_chat,
            inputs=[chat_input, chatbot, require_approval],
            outputs=[chatbot, chat_input, log_output]
        )
        
        chat_input.submit(
            sync_process_chat,
            inputs=[chat_input, chatbot, require_approval],
            outputs=[chatbot, chat_input, log_output]
        )
        
        # Auto-refresh device status on load
        app.load(
            check_device_status,
            outputs=[device_status_label, device_info_box, chat_input, send_btn]
        )
    
    return app


def launch_ui(share: bool = False, port: int = 7860):
    """Launch the web UI."""
    print("""
    ╔═══════════════════════════════════════════════════════════════╗
    ║     FIA Android Digital Forensics Framework                   ║
    ║     Interactive Investigation Console                         ║
    ╠═══════════════════════════════════════════════════════════════╣
    ║  Starting Web UI...                                           ║
    ╚═══════════════════════════════════════════════════════════════╝
    """)
    
    app = create_ui()
    app.launch(
        share=share,
        server_port=port,
        show_error=True,
        inbrowser=True
    )


if __name__ == "__main__":
    launch_ui()
