"""
Deep Agents Forensic Framework
Federal Investigation Agency - Android Digital Forensics

This module implements the Deep Agents architecture from LangChain for 
complex, multi-step forensic investigations with:
- Planning capabilities (todo list management)
- Subagent delegation for specialized tasks
- Human-in-the-Loop middleware for evidence handling
- Filesystem access for artifact storage
"""

import asyncio
import json
import os
from datetime import datetime
from pathlib import Path
from typing import Annotated, Any, Callable, Literal, Optional, Sequence, TypedDict

from dotenv import load_dotenv
from langchain_core.messages import AIMessage, HumanMessage, SystemMessage, ToolMessage
from langchain_core.tools import BaseTool, StructuredTool, tool
from langchain_openai import ChatOpenAI
from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, StateGraph
from langgraph.graph.message import add_messages
from langgraph.prebuilt import ToolNode
from langgraph.types import Command, interrupt

load_dotenv()

# Configuration - xAI Grok API
XAI_API_KEY = os.getenv("XAI_API_KEY")
XAI_MODEL = os.getenv("XAI_MODEL", "grok-4-latest")
XAI_BASE_URL = os.getenv("XAI_BASE_URL", "https://api.x.ai/v1")
OUTPUT_DIR = Path(os.getenv("OUTPUT_DIR", "./output"))
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


# =============================================================================
# STATE DEFINITIONS
# =============================================================================

class TodoItem(TypedDict):
    """Individual todo item for investigation planning."""
    id: str
    task: str
    status: Literal["pending", "in_progress", "completed", "blocked"]
    priority: Literal["high", "medium", "low"]
    assigned_to: Optional[str]
    notes: Optional[str]


class ForensicState(TypedDict):
    """State for the deep forensic investigation agent."""
    messages: Annotated[list, add_messages]
    case_info: dict
    device_info: dict
    todos: list[TodoItem]
    evidence_collected: list[dict]
    findings: list[dict]
    current_phase: str
    subagent_results: dict
    requires_approval: bool
    pending_action: Optional[dict]


# =============================================================================
# FORENSIC TOOLS
# =============================================================================

@tool
def check_device_connection() -> dict:
    """Check if an Android device is connected via ADB."""
    import subprocess
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
                    devices.append(parts[0])
        return {
            "connected": len(devices) > 0,
            "device_count": len(devices),
            "devices": devices,
            "status": "ready" if devices else "no_device"
        }
    except Exception as e:
        return {"connected": False, "error": str(e)}


@tool
def get_device_info(device_id: Optional[str] = None) -> dict:
    """Get detailed information about the connected Android device."""
    import subprocess
    try:
        cmd = ["adb"]
        if device_id:
            cmd.extend(["-s", device_id])
        
        props = {
            "manufacturer": "ro.product.manufacturer",
            "model": "ro.product.model",
            "android_version": "ro.build.version.release",
            "sdk_version": "ro.build.version.sdk",
            "serial": "ro.serialno",
            "security_patch": "ro.build.version.security_patch",
            "build_fingerprint": "ro.build.fingerprint",
        }
        
        info = {}
        for key, prop in props.items():
            result = subprocess.run(
                cmd + ["shell", "getprop", prop],
                capture_output=True, text=True, timeout=5
            )
            info[key] = result.stdout.strip() or "N/A"
        
        return {"success": True, "device_info": info}
    except Exception as e:
        return {"success": False, "error": str(e)}


@tool
def list_installed_packages(filter_type: Literal["all", "user", "system"] = "all") -> dict:
    """List installed packages on the Android device."""
    import subprocess
    try:
        cmd = ["adb", "shell", "pm", "list", "packages"]
        if filter_type == "user":
            cmd.append("-3")
        elif filter_type == "system":
            cmd.append("-s")
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        packages = [line.replace("package:", "") for line in result.stdout.strip().split("\n") if line]
        
        return {
            "success": True,
            "package_count": len(packages),
            "packages": packages[:100],  # Limit for display
            "filter": filter_type
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


@tool
def extract_logcat(lines: int = 500, filter_tag: Optional[str] = None) -> dict:
    """Extract system logs from the device."""
    import subprocess
    try:
        cmd = ["adb", "logcat", "-d", "-t", str(lines)]
        if filter_tag:
            cmd.extend(["-s", filter_tag])
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        
        # Save to file
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = OUTPUT_DIR / f"logcat_{timestamp}.txt"
        output_file.write_text(result.stdout)
        
        return {
            "success": True,
            "line_count": len(result.stdout.split("\n")),
            "output_file": str(output_file),
            "preview": result.stdout[:2000]
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


@tool
def pull_file(remote_path: str, local_name: Optional[str] = None) -> dict:
    """Pull a file from the Android device."""
    import subprocess
    try:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        if not local_name:
            local_name = Path(remote_path).name
        local_path = OUTPUT_DIR / f"{timestamp}_{local_name}"
        
        result = subprocess.run(
            ["adb", "pull", remote_path, str(local_path)],
            capture_output=True, text=True, timeout=60
        )
        
        if result.returncode == 0:
            return {
                "success": True,
                "remote_path": remote_path,
                "local_path": str(local_path),
                "message": result.stdout.strip()
            }
        else:
            return {"success": False, "error": result.stderr.strip()}
    except Exception as e:
        return {"success": False, "error": str(e)}


@tool
def execute_shell_command(command: str) -> dict:
    """Execute an ADB shell command on the device."""
    import subprocess
    try:
        result = subprocess.run(
            ["adb", "shell", command],
            capture_output=True, text=True, timeout=30
        )
        return {
            "success": True,
            "command": command,
            "stdout": result.stdout[:5000],
            "stderr": result.stderr[:1000] if result.stderr else None
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


# =============================================================================
# TODO/PLANNING TOOL
# =============================================================================

@tool
def write_todos(todos: list[dict]) -> dict:
    """
    Update the investigation todo list for planning.
    
    Args:
        todos: List of todo items with id, task, status, priority
    """
    return {"updated": True, "todo_count": len(todos), "todos": todos}


# =============================================================================
# SUBAGENT DEFINITIONS
# =============================================================================

DEVICE_ANALYSIS_SUBAGENT = {
    "name": "device_analyst",
    "description": "Specialized agent for device identification, status verification, and system information gathering",
    "system_prompt": """You are a Device Analysis Specialist. Your role is to:
1. Verify device connectivity
2. Gather comprehensive device information
3. Check for root status and security configurations
4. Document device identifiers for chain of custody

Always be thorough and document all findings.""",
    "tools": [check_device_connection, get_device_info, execute_shell_command]
}

APP_FORENSICS_SUBAGENT = {
    "name": "app_forensics",
    "description": "Specialized agent for analyzing installed applications and extracting app data",
    "system_prompt": """You are an Application Forensics Specialist. Your role is to:
1. Enumerate installed applications
2. Identify potentially relevant apps (messaging, social, financial)
3. Extract application data when authorized
4. Document package information and permissions

Focus on apps that may contain evidentiary value.""",
    "tools": [list_installed_packages, pull_file, execute_shell_command]
}

LOG_ANALYSIS_SUBAGENT = {
    "name": "log_analyst",
    "description": "Specialized agent for system log extraction and analysis",
    "system_prompt": """You are a Log Analysis Specialist. Your role is to:
1. Extract system logs (logcat, dmesg, kernel logs)
2. Identify security-relevant events
3. Create timelines of activity
4. Flag suspicious or anomalous entries

Document all log sources and maintain chain of custody.""",
    "tools": [extract_logcat, pull_file, execute_shell_command]
}

SUBAGENTS = [
    DEVICE_ANALYSIS_SUBAGENT,
    APP_FORENSICS_SUBAGENT,
    LOG_ANALYSIS_SUBAGENT
]


# =============================================================================
# HUMAN-IN-THE-LOOP MIDDLEWARE
# =============================================================================

def requires_human_approval(tool_name: str) -> bool:
    """Determine if a tool requires human approval before execution."""
    sensitive_tools = [
        "pull_file",
        "execute_shell_command",
        "create_backup",
        "extract_database",
    ]
    return tool_name in sensitive_tools


def request_approval(action: dict) -> dict:
    """Request human approval for a sensitive action."""
    return interrupt({
        "type": "approval_request",
        "action": action,
        "message": f"Approval required for: {action.get('tool_name', 'unknown action')}",
        "timestamp": datetime.now().isoformat()
    })


# =============================================================================
# DEEP AGENT GRAPH
# =============================================================================

class DeepForensicAgent:
    """
    Deep Agent implementation for forensic investigations.
    
    Features:
    - Planning via todo list management
    - Subagent delegation for specialized tasks
    - Human-in-the-Loop for sensitive operations
    - State persistence for long-running investigations
    """
    
    def __init__(self, model: str = None, checkpointer = None):
        self.model_name = model or XAI_MODEL
        self.checkpointer = checkpointer or MemorySaver()
        self.tools = self._build_tools()
        self.llm = self._create_llm()
        self.graph = self._build_graph()
    
    def _create_llm(self):
        """Create the LLM instance using xAI Grok."""
        llm = ChatOpenAI(
            model=self.model_name,
            api_key=XAI_API_KEY,
            base_url=XAI_BASE_URL,
            temperature=0.1,
            max_tokens=8192,
        )
        return llm.bind_tools(self.tools)
    
    def _build_tools(self) -> list:
        """Build the tool set for the agent."""
        return [
            check_device_connection,
            get_device_info,
            list_installed_packages,
            extract_logcat,
            pull_file,
            execute_shell_command,
            write_todos,
        ]
    
    def _get_system_prompt(self) -> str:
        """Generate the system prompt for the deep agent."""
        subagent_descriptions = "\n".join([
            f"- {sa['name']}: {sa['description']}"
            for sa in SUBAGENTS
        ])
        
        return f"""You are a Deep Forensic Investigation Agent for the Federal Investigation Agency (FIA).

## Your Capabilities

1. **Planning**: Create and manage investigation plans using the write_todos tool
2. **Device Analysis**: Check connectivity, gather device information
3. **Application Forensics**: Enumerate and analyze installed applications
4. **Log Analysis**: Extract and analyze system logs
5. **Evidence Collection**: Pull files and artifacts from the device

## Available Subagents
{subagent_descriptions}

## Investigation Protocol

1. **PLAN**: Start by creating a todo list of investigation steps
2. **VERIFY**: Check device connection before any operations
3. **DOCUMENT**: Record all device identifiers for chain of custody
4. **ACQUIRE**: Collect evidence systematically
5. **ANALYZE**: Examine collected artifacts
6. **REPORT**: Summarize findings

## Human-in-the-Loop

Sensitive operations require approval:
- File extraction (pull_file)
- Shell command execution
- Database extraction
- Backup creation

Always explain what you're about to do before requesting approval.

## Evidence Handling

- Calculate and record SHA-256 hashes for all evidence
- Maintain timestamps for all actions
- Document any limitations or access restrictions
- Preserve original data integrity
"""
    
    def _should_continue(self, state: ForensicState) -> Literal["tools", "approval", "end"]:
        """Determine the next step in the graph."""
        messages = state["messages"]
        last_message = messages[-1]
        
        # Check if there are tool calls
        if hasattr(last_message, "tool_calls") and last_message.tool_calls:
            # Check if any tool requires approval
            for tool_call in last_message.tool_calls:
                if requires_human_approval(tool_call["name"]):
                    return "approval"
            return "tools"
        
        return "end"
    
    def _model_node(self, state: ForensicState) -> dict:
        """Execute the model and return response."""
        messages = state["messages"]
        
        # Add system prompt if not present
        if not any(isinstance(m, SystemMessage) for m in messages):
            messages = [SystemMessage(content=self._get_system_prompt())] + list(messages)
        
        response = self.llm.invoke(messages)
        return {"messages": [response]}
    
    def _approval_node(self, state: ForensicState) -> dict:
        """Handle human-in-the-loop approval."""
        messages = state["messages"]
        last_message = messages[-1]
        
        if hasattr(last_message, "tool_calls") and last_message.tool_calls:
            # Find the sensitive tool call
            for tool_call in last_message.tool_calls:
                if requires_human_approval(tool_call["name"]):
                    # Request approval via interrupt
                    approval = interrupt({
                        "type": "approval_request",
                        "tool_name": tool_call["name"],
                        "tool_args": tool_call["args"],
                        "message": f"Authorization required for: {tool_call['name']}"
                    })
                    
                    # If we get here, approval was granted
                    return {"pending_action": None, "requires_approval": False}
        
        return {}
    
    def _tool_node(self, state: ForensicState):
        """Execute tools."""
        tool_node = ToolNode(self.tools)
        return tool_node.invoke(state)
    
    def _build_graph(self) -> StateGraph:
        """Build the LangGraph state graph."""
        graph = StateGraph(ForensicState)
        
        # Add nodes
        graph.add_node("model", self._model_node)
        graph.add_node("tools", self._tool_node)
        graph.add_node("approval", self._approval_node)
        
        # Set entry point
        graph.set_entry_point("model")
        
        # Add conditional edges
        graph.add_conditional_edges(
            "model",
            self._should_continue,
            {
                "tools": "tools",
                "approval": "approval",
                "end": END
            }
        )
        
        # Tools always return to model
        graph.add_edge("tools", "model")
        
        # Approval leads to tools
        graph.add_edge("approval", "tools")
        
        return graph.compile(checkpointer=self.checkpointer)
    
    def invoke(self, message: str, config: dict = None) -> dict:
        """Run the agent with a message."""
        config = config or {"configurable": {"thread_id": "default"}}
        
        initial_state = {
            "messages": [HumanMessage(content=message)],
            "case_info": {},
            "device_info": {},
            "todos": [],
            "evidence_collected": [],
            "findings": [],
            "current_phase": "initialization",
            "subagent_results": {},
            "requires_approval": False,
            "pending_action": None
        }
        
        return self.graph.invoke(initial_state, config)
    
    async def ainvoke(self, message: str, config: dict = None) -> dict:
        """Async version of invoke."""
        config = config or {"configurable": {"thread_id": "default"}}
        
        initial_state = {
            "messages": [HumanMessage(content=message)],
            "case_info": {},
            "device_info": {},
            "todos": [],
            "evidence_collected": [],
            "findings": [],
            "current_phase": "initialization",
            "subagent_results": {},
            "requires_approval": False,
            "pending_action": None
        }
        
        return await self.graph.ainvoke(initial_state, config)
    
    def stream(self, message: str, config: dict = None):
        """Stream agent execution."""
        config = config or {"configurable": {"thread_id": "default"}}
        
        initial_state = {
            "messages": [HumanMessage(content=message)],
            "case_info": {},
            "device_info": {},
            "todos": [],
            "evidence_collected": [],
            "findings": [],
            "current_phase": "initialization",
            "subagent_results": {},
            "requires_approval": False,
            "pending_action": None
        }
        
        for event in self.graph.stream(initial_state, config, stream_mode="updates"):
            yield event


# =============================================================================
# FACTORY FUNCTION
# =============================================================================

def create_deep_forensic_agent(
    model: str = None,
    checkpointer = None,
    enable_approval: bool = True
) -> DeepForensicAgent:
    """
    Create a deep forensic investigation agent.
    
    Args:
        model: LLM model name (defaults to GEMINI_MODEL)
        checkpointer: State checkpointer for persistence
        enable_approval: Whether to require human approval for sensitive ops
    
    Returns:
        Configured DeepForensicAgent instance
    """
    return DeepForensicAgent(
        model=model,
        checkpointer=checkpointer or MemorySaver()
    )


# =============================================================================
# CLI INTERFACE
# =============================================================================

async def main():
    """Command-line interface for the deep agent."""
    print("""
    ================================================================
         FIA DEEP FORENSIC AGENT
         Federal Investigation Agency
    ================================================================
    """)
    
    agent = create_deep_forensic_agent()
    thread_id = f"investigation_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    config = {"configurable": {"thread_id": thread_id}}
    
    print(f"Investigation ID: {thread_id}")
    print("Type 'exit' to quit, 'status' for device status\n")
    
    while True:
        try:
            user_input = input("Investigator > ").strip()
            
            if user_input.lower() == "exit":
                print("Investigation session ended.")
                break
            
            if user_input.lower() == "status":
                result = check_device_connection.invoke({})
                print(f"Device Status: {json.dumps(result, indent=2)}")
                continue
            
            if not user_input:
                continue
            
            # Run agent
            result = await agent.ainvoke(user_input, config)
            
            # Extract and display response
            messages = result.get("messages", [])
            for msg in messages:
                if isinstance(msg, AIMessage):
                    print(f"\nAgent: {msg.content}\n")
            
        except KeyboardInterrupt:
            print("\nSession interrupted.")
            break
        except Exception as e:
            print(f"Error: {e}")


if __name__ == "__main__":
    asyncio.run(main())
