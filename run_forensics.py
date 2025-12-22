"""
FIA Android Forensics Framework - CLI Runner
Quick start script for running the forensic investigation agent.
"""

import asyncio
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from agents.forensic_agent import ForensicInvestigator, main as agent_main


def main():
    """Main entry point."""
    print("""
    ╔═══════════════════════════════════════════════════════════════╗
    ║     FIA Android Digital Forensics Framework                   ║
    ║     Federal Investigation Agency                              ║
    ╠═══════════════════════════════════════════════════════════════╣
    ║  Architecture:                                                ║
    ║  • LangGraph Agent Orchestration                              ║
    ║  • MCP Servers as Forensic Tools                              ║
    ║  • Google Gemini AI Backend                                   ║
    ╚═══════════════════════════════════════════════════════════════╝
    """)
    
    asyncio.run(agent_main())


if __name__ == "__main__":
    main()
