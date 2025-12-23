"""
Interactive Forensic Agent with Human-in-the-Loop
Federal Investigation Agency (FIA) - Android Forensics Framework

This agent implements:
- LangGraph with interrupt_before for tool approval
- Device connection verification as prerequisite
- Plan-and-Execute workflow pattern
- Real-time streaming responses
"""

import asyncio
import json
import os
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Annotated, Any, Literal, Optional, TypedDict

from dotenv import load_dotenv
from langchain_core.messages import AIMessage, HumanMessage, SystemMessage, ToolMessage
from langchain_core.tools import tool
from langchain_openai import ChatOpenAI
from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, StateGraph
from langgraph.graph.message import add_messages
from langgraph.prebuilt import ToolNode
from pydantic import BaseModel, Field

# Load environment variables
load_dotenv()

# xAI Grok API Configuration
XAI_API_KEY = os.getenv("XAI_API_KEY")
XAI_MODEL = os.getenv("XAI_MODEL", "grok-4-latest")
XAI_BASE_URL = os.getenv("XAI_BASE_URL", "https://api.x.ai/v1")
OUTPUT_DIR = Path(os.getenv("OUTPUT_DIR", "./output"))


# ============================================================================
# State Definition
# ============================================================================

class InvestigationState(TypedDict):
    """Enhanced state for forensic investigation with human-in-the-loop."""
    messages: Annotated[list, add_messages]
    
    # Case information
    case_number: str
    examiner: str
    case_notes: str
    
    # Device state
    device_connected: bool
    device_info: dict
    
    # Investigation tracking
    investigation_plan: list
    current_step: int
    findings: list
    evidence: list
    
    # Human-in-the-loop
    pending_approval: bool
    pending_tool_calls: list
    human_feedback: str
    
    # Control flow
    phase: str  # "init", "planning", "executing", "reporting", "complete"
    error: str


# ============================================================================
# Built-in Forensic Tools (without MCP for reliability)
# ============================================================================

@tool
def check_device_connection() -> dict:
    """
    Check if an Android device is connected via ADB.
    This must be called first before any other forensic operation.
    """
    try:
        # Check ADB available
        result = subprocess.run(
            ["adb", "version"],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode != 0:
            return {"connected": False, "error": "ADB not found"}
        
        # Check devices
        result = subprocess.run(
            ["adb", "devices"],
            capture_output=True, text=True, timeout=10
        )
        
        lines = result.stdout.strip().split("\n")[1:]
        devices = [l for l in lines if l.strip() and "device" in l]
        
        if not devices:
            return {
                "connected": False,
                "error": "No devices connected. Enable USB debugging on the device."
            }
        
        device_id = devices[0].split()[0]
        
        # Get device info
        info = {}
        props = [
            ("manufacturer", "ro.product.manufacturer"),
            ("model", "ro.product.model"),
            ("android_version", "ro.build.version.release"),
            ("sdk_version", "ro.build.version.sdk"),
            ("serial", "ro.serialno"),
            ("build_id", "ro.build.id")
        ]
        
        for name, prop in props:
            try:
                r = subprocess.run(
                    ["adb", "-s", device_id, "shell", "getprop", prop],
                    capture_output=True, text=True, timeout=5
                )
                info[name] = r.stdout.strip()
            except:
                info[name] = "Unknown"
        
        info["device_id"] = device_id
        
        return {
            "connected": True,
            "device_count": len(devices),
            "device_info": info
        }
        
    except Exception as e:
        return {"connected": False, "error": str(e)}


@tool
def get_installed_apps(include_system: bool = False) -> dict:
    """
    Get list of installed applications on the connected device.
    
    Args:
        include_system: If True, include system apps. Default False for user apps only.
    """
    try:
        flag = "" if include_system else "-3"
        result = subprocess.run(
            ["adb", "shell", f"pm list packages {flag}".strip()],
            capture_output=True, text=True, timeout=60
        )
        
        packages = []
        for line in result.stdout.strip().split("\n"):
            if line.startswith("package:"):
                packages.append(line[8:])
        
        # Identify interesting apps
        forensic_keywords = [
            "whatsapp", "telegram", "signal", "messenger", "instagram",
            "facebook", "snapchat", "tiktok", "gmail", "email",
            "vpn", "tor", "proxy", "hide", "vault", "secret"
        ]
        
        interesting = [p for p in packages if any(k in p.lower() for k in forensic_keywords)]
        
        return {
            "success": True,
            "total_count": len(packages),
            "packages": packages[:50],  # Limit for display
            "interesting_apps": interesting,
            "interesting_count": len(interesting)
        }
        
    except Exception as e:
        return {"success": False, "error": str(e)}


@tool
def capture_device_logs(output_file: str, lines: int = 5000) -> dict:
    """
    Capture device system logs (logcat).
    
    Args:
        output_file: Path to save the log file
        lines: Number of log lines to capture
    """
    try:
        output_path = Path(output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        result = subprocess.run(
            ["adb", "shell", "logcat", "-d", "-t", str(lines)],
            capture_output=True, text=True, timeout=120
        )
        
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(result.stdout)
        
        return {
            "success": True,
            "output_file": str(output_path.absolute()),
            "line_count": len(result.stdout.split("\n")),
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        return {"success": False, "error": str(e)}


@tool
def check_root_status() -> dict:
    """
    Check if the device is rooted.
    Important for determining data access capabilities.
    """
    try:
        indicators = {
            "su_binary": False,
            "root_apps": [],
            "selinux_permissive": False,
            "test_keys": False
        }
        
        # Check su binary
        result = subprocess.run(
            ["adb", "shell", "which su"],
            capture_output=True, text=True, timeout=10
        )
        indicators["su_binary"] = bool(result.stdout.strip())
        
        # Check SELinux
        result = subprocess.run(
            ["adb", "shell", "getenforce"],
            capture_output=True, text=True, timeout=10
        )
        indicators["selinux_permissive"] = "permissive" in result.stdout.lower()
        
        # Check build tags
        result = subprocess.run(
            ["adb", "shell", "getprop", "ro.build.tags"],
            capture_output=True, text=True, timeout=10
        )
        indicators["test_keys"] = "test-keys" in result.stdout
        
        # Check for root management apps
        result = subprocess.run(
            ["adb", "shell", "pm list packages"],
            capture_output=True, text=True, timeout=30
        )
        root_keywords = ["supersu", "magisk", "kingroot", "kingoroot"]
        packages = result.stdout.lower()
        indicators["root_apps"] = [k for k in root_keywords if k in packages]
        
        is_rooted = any([
            indicators["su_binary"],
            indicators["selinux_permissive"],
            indicators["test_keys"],
            len(indicators["root_apps"]) > 0
        ])
        
        return {
            "is_rooted": is_rooted,
            "confidence": "high" if indicators["su_binary"] else "medium",
            "indicators": indicators,
            "forensic_implications": {
                "full_data_access": is_rooted,
                "can_bypass_encryption": is_rooted and indicators["selinux_permissive"]
            }
        }
        
    except Exception as e:
        return {"error": str(e)}


@tool
def get_device_accounts() -> dict:
    """
    Get registered accounts on the device (Google, social media, etc.).
    """
    try:
        result = subprocess.run(
            ["adb", "shell", "dumpsys", "account"],
            capture_output=True, text=True, timeout=30
        )
        
        import re
        accounts = []
        for match in re.finditer(r'Account \{name=([^,]+), type=([^}]+)\}', result.stdout):
            accounts.append({
                "name": match.group(1),
                "type": match.group(2)
            })
        
        # Group by type
        by_type = {}
        for acc in accounts:
            t = acc["type"]
            if t not in by_type:
                by_type[t] = []
            by_type[t].append(acc["name"])
        
        return {
            "success": True,
            "total_accounts": len(accounts),
            "accounts_by_type": by_type,
            "account_types": list(by_type.keys())
        }
        
    except Exception as e:
        return {"success": False, "error": str(e)}


@tool
def pull_file(remote_path: str, local_path: str) -> dict:
    """
    Pull a file from the device to local storage.
    
    Args:
        remote_path: Path on the Android device
        local_path: Local destination path
    """
    try:
        output_path = Path(local_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        result = subprocess.run(
            ["adb", "pull", remote_path, str(output_path)],
            capture_output=True, text=True, timeout=300
        )
        
        if result.returncode == 0:
            import hashlib
            sha256 = hashlib.sha256()
            with open(output_path, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    sha256.update(chunk)
            
            return {
                "success": True,
                "remote_path": remote_path,
                "local_path": str(output_path.absolute()),
                "size_bytes": output_path.stat().st_size,
                "sha256": sha256.hexdigest()
            }
        else:
            return {
                "success": False,
                "error": result.stderr or "Failed to pull file"
            }
        
    except Exception as e:
        return {"success": False, "error": str(e)}


@tool
def create_investigation_plan(objectives: str) -> dict:
    """
    Create a structured investigation plan based on objectives.
    
    Args:
        objectives: Description of what needs to be investigated
    """
    plan = {
        "objectives": objectives,
        "created_at": datetime.now().isoformat(),
        "steps": [
            {
                "step": 1,
                "name": "Device Verification",
                "description": "Verify device connection and gather basic info",
                "tools": ["check_device_connection"],
                "status": "pending"
            },
            {
                "step": 2,
                "name": "Security Assessment",
                "description": "Check root status and security configuration",
                "tools": ["check_root_status"],
                "status": "pending"
            },
            {
                "step": 3,
                "name": "Application Inventory",
                "description": "List installed apps and identify forensically relevant ones",
                "tools": ["get_installed_apps"],
                "status": "pending"
            },
            {
                "step": 4,
                "name": "Account Discovery",
                "description": "Identify registered accounts on device",
                "tools": ["get_device_accounts"],
                "status": "pending"
            },
            {
                "step": 5,
                "name": "Log Capture",
                "description": "Capture system logs for timeline analysis",
                "tools": ["capture_device_logs"],
                "status": "pending"
            },
            {
                "step": 6,
                "name": "Evidence Collection",
                "description": "Pull relevant files and databases",
                "tools": ["pull_file"],
                "status": "pending"
            }
        ]
    }
    
    return plan


# All available tools
FORENSIC_TOOLS = [
    check_device_connection,
    get_installed_apps,
    capture_device_logs,
    check_root_status,
    get_device_accounts,
    pull_file,
    create_investigation_plan
]


# ============================================================================
# Agent Graph Construction
# ============================================================================

def create_interactive_agent():
    """Create the LangGraph agent with human-in-the-loop."""
    
    # Initialize LLM with xAI Grok (OpenAI-compatible)
    llm = ChatOpenAI(
        model=XAI_MODEL,
        api_key=XAI_API_KEY,
        base_url=XAI_BASE_URL,
        temperature=0.1,
        max_tokens=8192,
    )
    
    # Bind tools to LLM
    llm_with_tools = llm.bind_tools(FORENSIC_TOOLS)
    
    # System prompt
    system_prompt = """You are an expert Android Digital Forensics Investigator for the Federal Investigation Agency (FIA).

## Your Approach

1. **ALWAYS check device connection first** using check_device_connection tool
2. If no device is connected, inform the user and wait
3. Create an investigation plan before taking action
4. Explain what you're about to do and why
5. Execute tools systematically, documenting everything

## Available Tools

- check_device_connection: Verify device is connected (ALWAYS FIRST)
- check_root_status: Check if device is rooted
- get_installed_apps: List installed applications
- get_device_accounts: Get registered accounts
- capture_device_logs: Capture system logs
- pull_file: Extract files from device
- create_investigation_plan: Create structured plan

## Guidelines

- Be thorough and methodical
- Explain technical concepts clearly
- Document all findings with hashes
- Prioritize based on investigation goals
- If something fails, explain why and suggest alternatives

When starting any investigation, FIRST check if a device is connected."""
    
    # Node functions
    def should_continue(state: InvestigationState) -> Literal["tools", "human_review", "__end__"]:
        """Route based on state."""
        messages = state["messages"]
        last_message = messages[-1] if messages else None
        
        if not last_message:
            return "__end__"
        
        # Check for tool calls
        if hasattr(last_message, "tool_calls") and last_message.tool_calls:
            # If human-in-the-loop is enabled and we have pending tools
            if state.get("pending_approval"):
                return "human_review"
            return "tools"
        
        return "__end__"
    
    def agent_node(state: InvestigationState) -> dict:
        """Main agent reasoning node."""
        messages = state["messages"]
        
        # Ensure system prompt
        if not any(isinstance(m, SystemMessage) for m in messages):
            messages = [SystemMessage(content=system_prompt)] + list(messages)
        
        # Add device context if available
        if state.get("device_connected") and state.get("device_info"):
            device_context = f"\n[DEVICE CONTEXT]: Connected - {state['device_info'].get('manufacturer', '')} {state['device_info'].get('model', '')}"
            if messages and isinstance(messages[-1], HumanMessage):
                messages[-1] = HumanMessage(content=messages[-1].content + device_context)
        
        response = llm_with_tools.invoke(messages)
        
        # Check if there are tool calls that need approval
        updates = {"messages": [response]}
        if hasattr(response, "tool_calls") and response.tool_calls:
            updates["pending_tool_calls"] = response.tool_calls
            updates["pending_approval"] = True
        
        return updates
    
    def tool_node(state: InvestigationState) -> dict:
        """Execute approved tools."""
        tool_executor = ToolNode(FORENSIC_TOOLS)
        result = tool_executor.invoke(state)
        
        # Update device state if we just checked connection
        messages = result.get("messages", [])
        for msg in messages:
            if isinstance(msg, ToolMessage):
                try:
                    content = json.loads(msg.content) if isinstance(msg.content, str) else msg.content
                    if isinstance(content, dict) and "connected" in content:
                        return {
                            **result,
                            "device_connected": content.get("connected", False),
                            "device_info": content.get("device_info", {}),
                            "pending_approval": False,
                            "pending_tool_calls": []
                        }
                except:
                    pass
        
        return {
            **result,
            "pending_approval": False,
            "pending_tool_calls": []
        }
    
    def human_review_node(state: InvestigationState) -> dict:
        """
        Human review node - execution pauses here for approval.
        This uses LangGraph's interrupt feature.
        """
        # This node acts as an interrupt point
        # The actual approval happens outside the graph
        pending_calls = state.get("pending_tool_calls", [])
        
        return {
            "phase": "awaiting_approval",
            "messages": [AIMessage(content=f"Awaiting approval for {len(pending_calls)} tool(s)...")]
        }
    
    # Build graph
    graph = StateGraph(InvestigationState)
    
    # Add nodes
    graph.add_node("agent", agent_node)
    graph.add_node("tools", tool_node)
    graph.add_node("human_review", human_review_node)
    
    # Set entry point
    graph.set_entry_point("agent")
    
    # Add edges
    graph.add_conditional_edges("agent", should_continue)
    graph.add_edge("tools", "agent")
    graph.add_edge("human_review", "tools")  # After approval, execute tools
    
    # Compile with memory for conversation persistence
    memory = MemorySaver()
    
    return graph.compile(
        checkpointer=memory,
        interrupt_before=["human_review"]  # Interrupt before human review for approval
    )


class InteractiveInvestigator:
    """
    High-level interface for interactive forensic investigations.
    Supports streaming, human-in-the-loop, and persistent sessions.
    """
    
    def __init__(self):
        self.graph = None
        self.thread_id = None
        self.initialized = False
    
    def initialize(self):
        """Initialize the agent."""
        if self.initialized:
            return
        
        self.graph = create_interactive_agent()
        self.thread_id = f"investigation_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        self.initialized = True
    
    def create_initial_state(
        self,
        case_number: str = None,
        examiner: str = None,
        notes: str = ""
    ) -> InvestigationState:
        """Create initial investigation state."""
        return {
            "messages": [],
            "case_number": case_number or f"FIA-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
            "examiner": examiner or os.getenv("INVESTIGATOR_NAME", "FIA Examiner"),
            "case_notes": notes,
            "device_connected": False,
            "device_info": {},
            "investigation_plan": [],
            "current_step": 0,
            "findings": [],
            "evidence": [],
            "pending_approval": False,
            "pending_tool_calls": [],
            "human_feedback": "",
            "phase": "init",
            "error": ""
        }
    
    async def send_message(
        self,
        message: str,
        config: dict = None
    ) -> dict:
        """
        Send a message and get response.
        May pause for human approval if tools are invoked.
        """
        if not self.initialized:
            self.initialize()
        
        config = config or {"configurable": {"thread_id": self.thread_id}}
        
        # Get current state
        current_state = self.graph.get_state(config)
        state = current_state.values if current_state.values else self.create_initial_state()
        
        # Add user message
        state["messages"] = list(state.get("messages", [])) + [HumanMessage(content=message)]
        
        # Run graph (may pause at interrupt)
        result = await self.graph.ainvoke(state, config)
        
        return result
    
    def approve_tools(self, config: dict = None) -> dict:
        """Approve pending tool execution and continue."""
        config = config or {"configurable": {"thread_id": self.thread_id}}
        
        # Get current state
        current_state = self.graph.get_state(config)
        if not current_state:
            return {"error": "No pending state"}
        
        state = current_state.values
        state["pending_approval"] = False
        
        # Continue execution
        result = asyncio.run(self.graph.ainvoke(state, config))
        return result
    
    def reject_tools(self, reason: str = "", config: dict = None) -> dict:
        """Reject pending tools and provide feedback."""
        config = config or {"configurable": {"thread_id": self.thread_id}}
        
        current_state = self.graph.get_state(config)
        if not current_state:
            return {"error": "No pending state"}
        
        state = current_state.values
        state["pending_approval"] = False
        state["pending_tool_calls"] = []
        state["human_feedback"] = reason
        state["messages"].append(
            HumanMessage(content=f"[TOOL EXECUTION REJECTED] {reason}")
        )
        
        return state
    
    def get_pending_tools(self, config: dict = None) -> list:
        """Get list of tools pending approval."""
        config = config or {"configurable": {"thread_id": self.thread_id}}
        
        current_state = self.graph.get_state(config)
        if not current_state or not current_state.values:
            return []
        
        return current_state.values.get("pending_tool_calls", [])


# Export for use in UI
__all__ = ["InteractiveInvestigator", "FORENSIC_TOOLS", "create_interactive_agent"]
