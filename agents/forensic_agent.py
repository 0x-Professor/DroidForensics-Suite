"""
Forensic Agent - LangGraph-based AI Agent
Federal Investigation Agency (FIA) - Android Forensics Framework

This agent orchestrates the forensic investigation workflow using:
- LangGraph for agent state management and workflow
- MCP Adapter to load tools from MCP servers
- xAI Grok as the LLM backbone (OpenAI-compatible)
"""

import asyncio
import json
import os
from datetime import datetime
from pathlib import Path
from typing import Annotated, Any, Literal, Optional, TypedDict

from dotenv import load_dotenv
from langchain_core.messages import AIMessage, HumanMessage, SystemMessage
from langchain_openai import ChatOpenAI
from langgraph.graph import END, StateGraph
from langgraph.graph.message import add_messages
from langgraph.prebuilt import ToolNode, tools_condition

# Load environment variables
load_dotenv()

# Groq API Configuration (FREE & FAST)
GROQ_API_KEY = os.getenv("GROQ_API_KEY")
GROQ_MODEL = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")
GROQ_BASE_URL = os.getenv("GROQ_BASE_URL", "https://api.groq.com/openai/v1")

if not GROQ_API_KEY:
    raise ValueError("GROQ_API_KEY not found in environment. Please set it in .env file.")

OUTPUT_DIR = Path(os.getenv("OUTPUT_DIR", "./output"))


class AgentState(TypedDict):
    """State for the forensic investigation agent."""
    messages: Annotated[list, add_messages]
    case_info: dict
    device_info: dict
    evidence_collected: list
    findings: list
    current_phase: str
    investigation_complete: bool


# System prompt for the forensic agent
FORENSIC_SYSTEM_PROMPT = """You are an expert Android Digital Forensics Investigator for the Federal Investigation Agency (FIA).

Your role is to conduct thorough, methodical forensic investigations of Android devices. You have access to a comprehensive suite of forensic tools through MCP servers.

## Investigation Methodology

1. **Device Identification**: Always start by identifying and documenting the device
2. **Data Preservation**: Create forensic backups before any analysis
3. **Root Status Check**: Determine if device is rooted (affects data access)
4. **Systematic Analysis**: Analyze data sources methodically:
   - System logs and settings
   - Communications (SMS, calls, messaging apps)
   - Social media applications
   - Browser history and downloads
   - Media files and metadata
   - Location data and WiFi history
5. **Timeline Reconstruction**: Build chronological event timelines
6. **Report Generation**: Document all findings with proper chain of custody

## Available Tool Categories

1. **Device Manager**: Device connection, status, identification
2. **Data Acquisition**: Backups, file extraction, directory pulls
3. **Artifact Parser**: Database parsing, contacts, SMS, call logs, browser history
4. **App Analyzer**: WhatsApp, Telegram, Facebook, Instagram, Gmail analysis
5. **System Forensics**: Logs, root detection, processes, network, accounts
6. **Report Generator**: Forensic reports, timelines, evidence manifests

## Important Guidelines

- Always document evidence with SHA-256 hashes
- Maintain chain of custody for all artifacts
- Note any limitations (e.g., encrypted data, root required)
- Be thorough but efficient - prioritize based on investigation goals
- Generate reports in Markdown format for proper documentation

When you receive an investigation request, plan your approach and execute systematically.
"""


async def load_mcp_tools():
    """Load tools from all MCP servers using the MCP adapter."""
    try:
        from langchain_mcp_adapters.client import MultiServerMCPClient
        
        # Define MCP server configurations
        mcp_servers = {
            "device_manager": {
                "command": "python",
                "args": [str(Path(__file__).parent.parent / "mcp_servers" / "device_manager.py")],
                "transport": "stdio"
            },
            "data_acquisition": {
                "command": "python",
                "args": [str(Path(__file__).parent.parent / "mcp_servers" / "data_acquisition.py")],
                "transport": "stdio"
            },
            "artifact_parser": {
                "command": "python",
                "args": [str(Path(__file__).parent.parent / "mcp_servers" / "artifact_parser.py")],
                "transport": "stdio"
            },
            "app_analyzer": {
                "command": "python",
                "args": [str(Path(__file__).parent.parent / "mcp_servers" / "app_analyzer.py")],
                "transport": "stdio"
            },
            "system_forensics": {
                "command": "python",
                "args": [str(Path(__file__).parent.parent / "mcp_servers" / "system_forensics.py")],
                "transport": "stdio"
            },
            "report_generator": {
                "command": "python",
                "args": [str(Path(__file__).parent.parent / "mcp_servers" / "report_generator.py")],
                "transport": "stdio"
            }
        }
        
        # Create multi-server client
        client = MultiServerMCPClient(mcp_servers)
        
        # Get tools from all servers
        tools = await client.get_tools()
        
        return tools, client
        
    except ImportError:
        print("Warning: langchain-mcp-adapters not installed. Using fallback tool loading.")
        return [], None


def create_llm(tools: list = None):
    """Create the Groq LLM with optional tool binding."""
    llm = ChatOpenAI(
        model=GROQ_MODEL,
        api_key=GROQ_API_KEY,
        base_url=GROQ_BASE_URL,
        temperature=0.1,  # Low temperature for consistent forensic analysis
        max_tokens=8192,
    )
    
    if tools:
        return llm.bind_tools(tools)
    return llm


def create_forensic_graph(tools: list):
    """Create the LangGraph workflow for forensic investigation."""
    
    # Create LLM with tools bound
    llm = create_llm(tools)
    
    # Define node functions
    def intake_node(state: AgentState) -> dict:
        """Initial intake - gather case information."""
        messages = state["messages"]
        
        # Add system prompt if not present
        if not any(isinstance(m, SystemMessage) for m in messages):
            messages = [SystemMessage(content=FORENSIC_SYSTEM_PROMPT)] + messages
        
        return {
            "messages": messages,
            "current_phase": "intake"
        }
    
    def agent_node(state: AgentState) -> dict:
        """Main agent reasoning node."""
        messages = state["messages"]
        
        # Ensure system prompt is at the start
        if not any(isinstance(m, SystemMessage) for m in messages):
            messages = [SystemMessage(content=FORENSIC_SYSTEM_PROMPT)] + messages
        
        response = llm.invoke(messages)
        
        return {"messages": [response]}
    
    def should_continue(state: AgentState) -> Literal["tools", "report", "__end__"]:
        """Determine next step based on agent response."""
        messages = state["messages"]
        last_message = messages[-1]
        
        # Check if agent wants to use tools
        if hasattr(last_message, "tool_calls") and last_message.tool_calls:
            return "tools"
        
        # Check if investigation is complete
        if state.get("investigation_complete"):
            return "__end__"
        
        # Check message content for completion indicators
        content = last_message.content.lower() if hasattr(last_message, "content") else ""
        if any(phrase in content for phrase in ["investigation complete", "report generated", "analysis complete"]):
            return "__end__"
        
        return "__end__"
    
    def tools_node(state: AgentState) -> dict:
        """Execute tools and return results."""
        tool_node = ToolNode(tools)
        return tool_node.invoke(state)
    
    def report_node(state: AgentState) -> dict:
        """Generate final investigation report."""
        return {
            "current_phase": "reporting",
            "investigation_complete": True
        }
    
    # Build the graph
    graph = StateGraph(AgentState)
    
    # Add nodes
    graph.add_node("intake", intake_node)
    graph.add_node("agent", agent_node)
    graph.add_node("tools", tools_node)
    graph.add_node("report", report_node)
    
    # Set entry point
    graph.set_entry_point("intake")
    
    # Add edges
    graph.add_edge("intake", "agent")
    graph.add_conditional_edges("agent", should_continue)
    graph.add_edge("tools", "agent")
    graph.add_edge("report", END)
    
    return graph.compile()


class ForensicInvestigator:
    """
    High-level interface for the Forensic Investigation Agent.
    Manages MCP connections and LangGraph workflow execution.
    """
    
    def __init__(self):
        self.tools = []
        self.mcp_client = None
        self.graph = None
        self.initialized = False
    
    async def initialize(self):
        """Initialize the agent with MCP tools."""
        if self.initialized:
            return
        
        print("🔧 Loading MCP tools...")
        self.tools, self.mcp_client = await load_mcp_tools()
        
        if self.tools:
            print(f"✅ Loaded {len(self.tools)} tools from MCP servers")
        else:
            print("⚠️ No MCP tools loaded - running in limited mode")
        
        print("🔨 Building investigation workflow...")
        self.graph = create_forensic_graph(self.tools)
        
        self.initialized = True
        print("✅ Forensic Investigator ready")
    
    async def investigate(
        self,
        query: str,
        case_number: Optional[str] = None,
        examiner: Optional[str] = None
    ) -> dict:
        """
        Run a forensic investigation based on the query.
        
        Args:
            query: Investigation request or question
            case_number: Optional case identifier
            examiner: Optional examiner name
        
        Returns:
            Investigation results and any generated reports
        """
        if not self.initialized:
            await self.initialize()
        
        # Prepare case info
        case_info = {
            "case_number": case_number or f"FIA-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
            "examiner": examiner or os.getenv("INVESTIGATOR_NAME", "FIA Digital Forensics"),
            "date": datetime.now().isoformat(),
            "agency": "Federal Investigation Agency"
        }
        
        # Create initial state
        initial_state = {
            "messages": [HumanMessage(content=query)],
            "case_info": case_info,
            "device_info": {},
            "evidence_collected": [],
            "findings": [],
            "current_phase": "start",
            "investigation_complete": False
        }
        
        print(f"\n🔍 Starting Investigation: {case_info['case_number']}")
        print(f"📋 Query: {query[:100]}...")
        print("-" * 50)
        
        # Run the investigation
        try:
            result = await self.graph.ainvoke(initial_state)
            
            print("-" * 50)
            print("✅ Investigation Complete")
            
            return {
                "success": True,
                "case_info": case_info,
                "messages": result.get("messages", []),
                "findings": result.get("findings", []),
                "evidence_collected": result.get("evidence_collected", []),
                "final_response": result["messages"][-1].content if result.get("messages") else None
            }
            
        except Exception as e:
            print(f"❌ Investigation failed: {str(e)}")
            return {
                "success": False,
                "error": str(e),
                "case_info": case_info
            }
    
    async def chat(self, message: str, state: dict = None) -> dict:
        """
        Interactive chat for ongoing investigations.
        
        Args:
            message: User message
            state: Optional existing conversation state
        
        Returns:
            Updated state with response
        """
        if not self.initialized:
            await self.initialize()
        
        if state is None:
            state = {
                "messages": [],
                "case_info": {},
                "device_info": {},
                "evidence_collected": [],
                "findings": [],
                "current_phase": "interactive",
                "investigation_complete": False
            }
        
        # Add user message
        state["messages"].append(HumanMessage(content=message))
        
        # Run through graph
        result = await self.graph.ainvoke(state)
        
        return result
    
    async def cleanup(self):
        """Clean up MCP connections."""
        if self.mcp_client:
            try:
                await self.mcp_client.close()
            except:
                pass


async def main():
    """Main entry point for interactive investigation."""
    print("=" * 60)
    print("  FIA Android Digital Forensics Framework")
    print("  LangGraph Agent with MCP Tools")
    print("=" * 60)
    print()
    
    investigator = ForensicInvestigator()
    
    try:
        await investigator.initialize()
        
        print("\nReady for investigation. Type 'quit' to exit.\n")
        
        state = None
        
        while True:
            try:
                user_input = input("\n🔍 Investigation Query > ").strip()
                
                if user_input.lower() in ['quit', 'exit', 'q']:
                    print("\n👋 Ending session...")
                    break
                
                if not user_input:
                    continue
                
                # Check for special commands
                if user_input.lower() == 'new':
                    state = None
                    print("🆕 Started new investigation session")
                    continue
                
                if user_input.lower() == 'status':
                    if state:
                        print(f"📊 Messages: {len(state.get('messages', []))}")
                        print(f"📊 Findings: {len(state.get('findings', []))}")
                        print(f"📊 Evidence: {len(state.get('evidence_collected', []))}")
                    else:
                        print("📊 No active investigation")
                    continue
                
                # Run investigation/chat
                state = await investigator.chat(user_input, state)
                
                # Print response
                if state.get("messages"):
                    last_msg = state["messages"][-1]
                    if hasattr(last_msg, "content") and last_msg.content:
                        print(f"\n🤖 Agent:\n{last_msg.content}")
                        
            except KeyboardInterrupt:
                print("\n\n⚠️ Interrupted. Type 'quit' to exit.")
                
    finally:
        await investigator.cleanup()


def run_investigation(query: str, case_number: str = None, examiner: str = None) -> dict:
    """
    Synchronous wrapper for running investigations.
    Useful for integration with other tools.
    """
    investigator = ForensicInvestigator()
    
    async def _run():
        try:
            await investigator.initialize()
            return await investigator.investigate(query, case_number, examiner)
        finally:
            await investigator.cleanup()
    
    return asyncio.run(_run())


if __name__ == "__main__":
    asyncio.run(main())
