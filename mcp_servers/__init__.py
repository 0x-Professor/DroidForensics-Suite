"""
MCP Servers Package for Android Forensics Framework
Federal Investigation Agency (FIA)

This package contains specialized MCP servers for different forensic operations:
- Device Manager: Device connection and management
- Data Acquisition: Backup, extraction, and data pulling
- Artifact Parser: Parse SMS, calls, contacts, browser history, SQLite databases
- App Analyzer: Messaging apps (WhatsApp, Telegram, Facebook, Instagram, Gmail)
- System Forensics: System logs, root detection, processes, accounts
- Report Generator: Comprehensive forensic report generation in Markdown

All servers use FastMCP framework with stdio transport for integration with
LangGraph agents via langchain-mcp-adapters.
"""

__version__ = "1.0.0"
__author__ = "FIA Digital Forensics Team"

# Server modules
from . import device_manager
from . import data_acquisition
from . import artifact_parser
from . import app_analyzer
from . import system_forensics
from . import report_generator

__all__ = [
    "device_manager",
    "data_acquisition", 
    "artifact_parser",
    "app_analyzer",
    "system_forensics",
    "report_generator"
]
