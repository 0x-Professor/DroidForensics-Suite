"""
Agents Module - FIA Android Forensics Framework

Contains LangGraph-based AI agents for forensic investigation:
- ForensicInvestigator: Basic agent with MCP tools
- InteractiveInvestigator: Human-in-the-loop agent for UI
"""

from .forensic_agent import ForensicInvestigator, run_investigation
from .interactive_agent import InteractiveInvestigator, FORENSIC_TOOLS

__all__ = [
    "ForensicInvestigator", 
    "run_investigation",
    "InteractiveInvestigator",
    "FORENSIC_TOOLS"
]
