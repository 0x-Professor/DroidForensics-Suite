"""
Report Generator MCP Server
Federal Investigation Agency (FIA) - Android Forensics Framework

Generates comprehensive forensic reports in multiple formats:
- Markdown reports with proper formatting
- Executive summaries for non-technical stakeholders
- Detailed technical reports for investigators
- Timeline reports for chronological analysis
- Evidence chain of custody documentation
"""

import hashlib
import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel, Field

# Initialize FastMCP server
mcp = FastMCP(
    "FIA Report Generator",
    instructions="""
    MCP server for generating comprehensive forensic reports.
    Supports Markdown format with proper evidence documentation,
    chain of custody tracking, and executive summaries.
    """
)


def calculate_hash(data: str) -> str:
    """Calculate SHA-256 hash of string data"""
    return hashlib.sha256(data.encode()).hexdigest()


def format_timestamp(iso_timestamp: str = None) -> str:
    """Format timestamp for reports"""
    if iso_timestamp:
        try:
            dt = datetime.fromisoformat(iso_timestamp)
            return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
        except:
            return iso_timestamp
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")


@mcp.tool()
def generate_forensic_report(
    case_info: dict,
    device_info: dict,
    evidence_summary: dict,
    findings: list,
    output_file: str,
    include_hashes: bool = True
) -> dict[str, Any]:
    """
    Generate a comprehensive forensic investigation report.
    
    Args:
        case_info: Case metadata (case_number, examiner, agency, date, etc.)
        device_info: Device details (model, serial, IMEI, Android version, etc.)
        evidence_summary: Summary of collected evidence
        findings: List of forensic findings with details
        output_file: Path to save the Markdown report
        include_hashes: Include SHA-256 hashes for integrity
    """
    output_path = Path(output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    report_timestamp = datetime.now().isoformat()
    
    # Build report
    report_lines = []
    
    # Header
    report_lines.append("# FORENSIC INVESTIGATION REPORT")
    report_lines.append("")
    report_lines.append("---")
    report_lines.append("**OFFICIAL - LAW ENFORCEMENT SENSITIVE**")
    report_lines.append("---")
    report_lines.append("")
    
    # Case Information
    report_lines.append("## 1. Case Information")
    report_lines.append("")
    report_lines.append("| Field | Value |")
    report_lines.append("|-------|-------|")
    report_lines.append(f"| Case Number | {case_info.get('case_number', 'N/A')} |")
    report_lines.append(f"| Examiner | {case_info.get('examiner', 'N/A')} |")
    report_lines.append(f"| Agency | {case_info.get('agency', 'Federal Investigation Agency')} |")
    report_lines.append(f"| Examination Date | {case_info.get('date', format_timestamp())} |")
    report_lines.append(f"| Report Generated | {format_timestamp(report_timestamp)} |")
    if case_info.get('suspect_name'):
        report_lines.append(f"| Subject Name | {case_info.get('suspect_name')} |")
    if case_info.get('offense'):
        report_lines.append(f"| Alleged Offense | {case_info.get('offense')} |")
    report_lines.append("")
    
    # Device Information
    report_lines.append("## 2. Device Information")
    report_lines.append("")
    report_lines.append("| Property | Value |")
    report_lines.append("|----------|-------|")
    for key, value in device_info.items():
        report_lines.append(f"| {key.replace('_', ' ').title()} | {value} |")
    report_lines.append("")
    
    # Evidence Summary
    report_lines.append("## 3. Evidence Summary")
    report_lines.append("")
    report_lines.append("### 3.1 Data Collected")
    report_lines.append("")
    
    if isinstance(evidence_summary, dict):
        for category, data in evidence_summary.items():
            report_lines.append(f"#### {category.replace('_', ' ').title()}")
            report_lines.append("")
            if isinstance(data, dict):
                for k, v in data.items():
                    report_lines.append(f"- **{k.replace('_', ' ').title()}**: {v}")
            elif isinstance(data, list):
                for item in data:
                    report_lines.append(f"- {item}")
            else:
                report_lines.append(f"- {data}")
            report_lines.append("")
    
    # Findings
    report_lines.append("## 4. Forensic Findings")
    report_lines.append("")
    
    for i, finding in enumerate(findings, 1):
        report_lines.append(f"### 4.{i} {finding.get('title', 'Finding ' + str(i))}")
        report_lines.append("")
        
        if finding.get('severity'):
            severity_emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}.get(finding.get('severity', '').lower(), "⚪")
            report_lines.append(f"**Severity**: {severity_emoji} {finding.get('severity').upper()}")
            report_lines.append("")
        
        if finding.get('description'):
            report_lines.append(f"**Description**: {finding.get('description')}")
            report_lines.append("")
        
        if finding.get('evidence'):
            report_lines.append("**Supporting Evidence**:")
            report_lines.append("")
            if isinstance(finding['evidence'], list):
                for ev in finding['evidence']:
                    report_lines.append(f"- {ev}")
            else:
                report_lines.append(f"- {finding['evidence']}")
            report_lines.append("")
        
        if finding.get('artifact_path'):
            report_lines.append(f"**Artifact Location**: `{finding.get('artifact_path')}`")
            report_lines.append("")
        
        if finding.get('hash') and include_hashes:
            report_lines.append(f"**SHA-256 Hash**: `{finding.get('hash')}`")
            report_lines.append("")
        
        if finding.get('timestamp'):
            report_lines.append(f"**Timestamp**: {format_timestamp(finding.get('timestamp'))}")
            report_lines.append("")
    
    # Chain of Custody
    report_lines.append("## 5. Chain of Custody")
    report_lines.append("")
    report_lines.append("| Date/Time | Action | Personnel | Notes |")
    report_lines.append("|-----------|--------|-----------|-------|")
    report_lines.append(f"| {format_timestamp()} | Device Received | {case_info.get('examiner', 'Examiner')} | Initial intake |")
    report_lines.append(f"| {format_timestamp()} | Forensic Acquisition | {case_info.get('examiner', 'Examiner')} | Data extracted |")
    report_lines.append(f"| {format_timestamp()} | Analysis Complete | {case_info.get('examiner', 'Examiner')} | Report generated |")
    report_lines.append("")
    
    # Legal Notice
    report_lines.append("## 6. Legal Notice")
    report_lines.append("")
    report_lines.append("> This report is prepared for official use by the Federal Investigation Agency (FIA)")
    report_lines.append("> and authorized law enforcement personnel. The information contained herein is")
    report_lines.append("> confidential and should be handled in accordance with applicable laws and regulations.")
    report_lines.append(">")
    report_lines.append("> All evidence has been collected and preserved using forensically sound methods")
    report_lines.append("> to maintain integrity and admissibility in legal proceedings.")
    report_lines.append("")
    
    # Examiner Certification
    report_lines.append("## 7. Examiner Certification")
    report_lines.append("")
    report_lines.append("I hereby certify that the foregoing is a true and accurate report of my examination")
    report_lines.append("findings. The analysis was performed using accepted forensic methodologies and all")
    report_lines.append("evidence has been handled in accordance with established chain of custody procedures.")
    report_lines.append("")
    report_lines.append(f"**Digital Forensic Examiner**: {case_info.get('examiner', '________________')}")
    report_lines.append("")
    report_lines.append(f"**Date**: {format_timestamp()}")
    report_lines.append("")
    report_lines.append("---")
    report_lines.append("")
    report_lines.append("*Report generated by FIA Android Forensics Framework*")
    
    # Write report
    report_content = "\n".join(report_lines)
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(report_content)
    
    report_hash = calculate_hash(report_content)
    
    return {
        "success": True,
        "output_file": str(output_path.absolute()),
        "report_hash": report_hash,
        "line_count": len(report_lines),
        "finding_count": len(findings),
        "timestamp": report_timestamp
    }


@mcp.tool()
def generate_executive_summary(
    case_info: dict,
    key_findings: list,
    recommendations: list,
    output_file: str
) -> dict[str, Any]:
    """
    Generate an executive summary for non-technical stakeholders.
    
    Args:
        case_info: Case metadata
        key_findings: List of key findings (simplified)
        recommendations: List of recommendations
        output_file: Path to save the summary
    """
    output_path = Path(output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    report_lines = []
    
    report_lines.append("# EXECUTIVE SUMMARY")
    report_lines.append("## Digital Forensic Investigation")
    report_lines.append("")
    report_lines.append("---")
    report_lines.append("")
    
    # Overview
    report_lines.append("### Overview")
    report_lines.append("")
    report_lines.append(f"**Case Number**: {case_info.get('case_number', 'N/A')}")
    report_lines.append(f"**Date**: {case_info.get('date', format_timestamp())}")
    report_lines.append(f"**Agency**: {case_info.get('agency', 'Federal Investigation Agency')}")
    report_lines.append("")
    
    # Key Findings
    report_lines.append("### Key Findings")
    report_lines.append("")
    for i, finding in enumerate(key_findings, 1):
        if isinstance(finding, dict):
            report_lines.append(f"{i}. **{finding.get('title', 'Finding')}**: {finding.get('summary', '')}")
        else:
            report_lines.append(f"{i}. {finding}")
    report_lines.append("")
    
    # Recommendations
    report_lines.append("### Recommendations")
    report_lines.append("")
    for i, rec in enumerate(recommendations, 1):
        report_lines.append(f"{i}. {rec}")
    report_lines.append("")
    
    # Conclusion
    report_lines.append("### Conclusion")
    report_lines.append("")
    report_lines.append("Based on the forensic analysis conducted, the digital evidence collected")
    report_lines.append("supports the findings outlined above. All evidence has been preserved")
    report_lines.append("according to forensic best practices for potential legal proceedings.")
    report_lines.append("")
    report_lines.append("---")
    report_lines.append("")
    report_lines.append(f"*Prepared by: {case_info.get('examiner', 'Digital Forensics Unit')}*")
    
    report_content = "\n".join(report_lines)
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(report_content)
    
    return {
        "success": True,
        "output_file": str(output_path.absolute()),
        "report_hash": calculate_hash(report_content),
        "timestamp": datetime.now().isoformat()
    }


@mcp.tool()
def generate_timeline_report(
    events: list,
    output_file: str,
    title: str = "Forensic Timeline Analysis"
) -> dict[str, Any]:
    """
    Generate a chronological timeline report of events.
    
    Args:
        events: List of events with timestamp, source, and description
        output_file: Path to save the timeline report
        title: Report title
    """
    output_path = Path(output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    # Sort events by timestamp
    sorted_events = sorted(events, key=lambda x: x.get('timestamp', ''))
    
    report_lines = []
    
    report_lines.append(f"# {title}")
    report_lines.append("")
    report_lines.append(f"*Generated: {format_timestamp()}*")
    report_lines.append("")
    report_lines.append("---")
    report_lines.append("")
    
    report_lines.append("## Event Timeline")
    report_lines.append("")
    report_lines.append("| Timestamp | Source | Event Type | Description |")
    report_lines.append("|-----------|--------|------------|-------------|")
    
    for event in sorted_events:
        ts = format_timestamp(event.get('timestamp'))
        source = event.get('source', 'Unknown')
        event_type = event.get('type', 'General')
        desc = event.get('description', 'N/A')
        report_lines.append(f"| {ts} | {source} | {event_type} | {desc} |")
    
    report_lines.append("")
    report_lines.append("---")
    report_lines.append("")
    report_lines.append(f"**Total Events**: {len(sorted_events)}")
    
    if sorted_events:
        report_lines.append(f"**Date Range**: {format_timestamp(sorted_events[0].get('timestamp'))} to {format_timestamp(sorted_events[-1].get('timestamp'))}")
    
    report_content = "\n".join(report_lines)
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(report_content)
    
    return {
        "success": True,
        "output_file": str(output_path.absolute()),
        "event_count": len(sorted_events),
        "report_hash": calculate_hash(report_content),
        "timestamp": datetime.now().isoformat()
    }


@mcp.tool()
def generate_evidence_manifest(
    evidence_items: list,
    case_number: str,
    examiner: str,
    output_file: str
) -> dict[str, Any]:
    """
    Generate an evidence manifest with chain of custody hashes.
    
    Args:
        evidence_items: List of evidence items with paths, hashes, and metadata
        case_number: Case identifier
        examiner: Examiner name
        output_file: Path to save the manifest
    """
    output_path = Path(output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    report_lines = []
    
    report_lines.append("# EVIDENCE MANIFEST")
    report_lines.append("")
    report_lines.append("---")
    report_lines.append("**CHAIN OF CUSTODY DOCUMENT**")
    report_lines.append("---")
    report_lines.append("")
    
    report_lines.append(f"**Case Number**: {case_number}")
    report_lines.append(f"**Examiner**: {examiner}")
    report_lines.append(f"**Date Generated**: {format_timestamp()}")
    report_lines.append("")
    
    report_lines.append("## Evidence Items")
    report_lines.append("")
    
    for i, item in enumerate(evidence_items, 1):
        report_lines.append(f"### Item {i}: {item.get('name', 'Unknown')}")
        report_lines.append("")
        report_lines.append(f"- **Description**: {item.get('description', 'N/A')}")
        report_lines.append(f"- **File Path**: `{item.get('path', 'N/A')}`")
        report_lines.append(f"- **SHA-256 Hash**: `{item.get('sha256', 'NOT COMPUTED')}`")
        report_lines.append(f"- **File Size**: {item.get('size', 'N/A')} bytes")
        report_lines.append(f"- **Acquisition Time**: {format_timestamp(item.get('timestamp'))}")
        report_lines.append(f"- **Source**: {item.get('source', 'N/A')}")
        report_lines.append("")
    
    report_lines.append("---")
    report_lines.append("")
    report_lines.append("## Verification Statement")
    report_lines.append("")
    report_lines.append("I certify that the above evidence items have been collected, preserved,")
    report_lines.append("and documented in accordance with forensic best practices. The SHA-256")
    report_lines.append("hashes provided can be used to verify evidence integrity at any time.")
    report_lines.append("")
    report_lines.append(f"**Examiner Signature**: {examiner}")
    report_lines.append(f"**Date**: {format_timestamp()}")
    
    report_content = "\n".join(report_lines)
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(report_content)
    
    # Calculate manifest hash
    manifest_hash = calculate_hash(report_content)
    
    return {
        "success": True,
        "output_file": str(output_path.absolute()),
        "evidence_count": len(evidence_items),
        "manifest_hash": manifest_hash,
        "timestamp": datetime.now().isoformat()
    }


@mcp.tool()
def generate_app_analysis_report(
    app_name: str,
    app_data: dict,
    messages: list,
    media_files: list,
    output_file: str
) -> dict[str, Any]:
    """
    Generate a detailed report for a specific application analysis.
    
    Args:
        app_name: Name of the application (e.g., "WhatsApp")
        app_data: Application metadata and configuration
        messages: Extracted messages/communications
        media_files: List of extracted media files
        output_file: Path to save the report
    """
    output_path = Path(output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    report_lines = []
    
    report_lines.append(f"# {app_name} Forensic Analysis Report")
    report_lines.append("")
    report_lines.append(f"*Generated: {format_timestamp()}*")
    report_lines.append("")
    report_lines.append("---")
    report_lines.append("")
    
    # App Metadata
    report_lines.append("## Application Information")
    report_lines.append("")
    report_lines.append("| Property | Value |")
    report_lines.append("|----------|-------|")
    for key, value in app_data.items():
        if not isinstance(value, (dict, list)):
            report_lines.append(f"| {key.replace('_', ' ').title()} | {value} |")
    report_lines.append("")
    
    # Message Statistics
    report_lines.append("## Message Analysis")
    report_lines.append("")
    report_lines.append(f"**Total Messages Extracted**: {len(messages)}")
    report_lines.append("")
    
    if messages:
        # Show sample messages (first 20)
        report_lines.append("### Sample Messages")
        report_lines.append("")
        report_lines.append("| Timestamp | Sender | Content Preview |")
        report_lines.append("|-----------|--------|-----------------|")
        
        for msg in messages[:20]:
            ts = msg.get('timestamp', 'N/A')
            sender = msg.get('sender', 'Unknown')[:20]
            content = msg.get('content', '')[:50].replace('\n', ' ')
            if len(msg.get('content', '')) > 50:
                content += "..."
            report_lines.append(f"| {ts} | {sender} | {content} |")
        
        if len(messages) > 20:
            report_lines.append("")
            report_lines.append(f"*... and {len(messages) - 20} more messages*")
    report_lines.append("")
    
    # Media Files
    report_lines.append("## Media Files")
    report_lines.append("")
    report_lines.append(f"**Total Media Files**: {len(media_files)}")
    report_lines.append("")
    
    if media_files:
        # Categorize by type
        by_type = {}
        for f in media_files:
            ftype = f.get('type', 'unknown')
            by_type[ftype] = by_type.get(ftype, 0) + 1
        
        report_lines.append("### Media by Type")
        report_lines.append("")
        for ftype, count in by_type.items():
            report_lines.append(f"- **{ftype.title()}**: {count} files")
    report_lines.append("")
    
    report_lines.append("---")
    report_lines.append("")
    report_lines.append("*Report generated by FIA Android Forensics Framework*")
    
    report_content = "\n".join(report_lines)
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(report_content)
    
    return {
        "success": True,
        "output_file": str(output_path.absolute()),
        "message_count": len(messages),
        "media_count": len(media_files),
        "report_hash": calculate_hash(report_content),
        "timestamp": datetime.now().isoformat()
    }


@mcp.tool()
def combine_reports(
    report_files: list,
    output_file: str,
    title: str = "Combined Forensic Analysis Report"
) -> dict[str, Any]:
    """
    Combine multiple reports into a single comprehensive document.
    
    Args:
        report_files: List of paths to Markdown reports to combine
        output_file: Path for the combined output
        title: Title for the combined report
    """
    output_path = Path(output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    combined_lines = []
    combined_lines.append(f"# {title}")
    combined_lines.append("")
    combined_lines.append(f"*Combined Report Generated: {format_timestamp()}*")
    combined_lines.append("")
    combined_lines.append("---")
    combined_lines.append("")
    combined_lines.append("## Table of Contents")
    combined_lines.append("")
    
    report_contents = []
    for i, report_file in enumerate(report_files, 1):
        report_path = Path(report_file)
        if report_path.exists():
            combined_lines.append(f"{i}. [{report_path.stem}](#{report_path.stem.lower().replace(' ', '-')})")
            with open(report_path, 'r', encoding='utf-8') as f:
                report_contents.append((report_path.stem, f.read()))
    
    combined_lines.append("")
    combined_lines.append("---")
    combined_lines.append("")
    
    # Add each report
    for name, content in report_contents:
        combined_lines.append(f"<a id='{name.lower().replace(' ', '-')}'></a>")
        combined_lines.append("")
        combined_lines.append(content)
        combined_lines.append("")
        combined_lines.append("---")
        combined_lines.append("")
    
    combined_content = "\n".join(combined_lines)
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(combined_content)
    
    return {
        "success": True,
        "output_file": str(output_path.absolute()),
        "reports_combined": len(report_contents),
        "total_lines": len(combined_lines),
        "report_hash": calculate_hash(combined_content),
        "timestamp": datetime.now().isoformat()
    }


# Run server
if __name__ == "__main__":
    mcp.run(transport="stdio")
