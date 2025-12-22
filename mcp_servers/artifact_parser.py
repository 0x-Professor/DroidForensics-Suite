"""
Artifact Parser MCP Server
Federal Investigation Agency (FIA) - Android Forensics Framework

Provides tools for parsing Android forensic artifacts including:
- SQLite database parsing (contacts, SMS, call logs, etc.)
- Media metadata extraction (EXIF, GPS)
- Application data parsing
- File system artifact analysis
- Timeline reconstruction
"""

import hashlib
import json
import os
import re
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel, Field

# Initialize FastMCP server
mcp = FastMCP(
    "FIA Artifact Parser",
    instructions="""
    Secure MCP server for parsing Android forensic artifacts.
    Handles SQLite databases, media files, and application data.
    Maintains evidence integrity with SHA-256 hashing.
    """
)


class ArtifactMetadata(BaseModel):
    """Metadata for parsed artifacts"""
    timestamp: str = Field(default_factory=lambda: datetime.now().isoformat())
    artifact_type: str
    source_path: str
    sha256_hash: Optional[str] = None
    record_count: int = 0
    investigator: str = Field(default="FIA Officer")
    case_id: Optional[str] = None
    notes: Optional[str] = None


def calculate_file_hash(file_path: Path) -> str:
    """Calculate SHA-256 hash of a file"""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256_hash.update(chunk)
    return sha256_hash.hexdigest()


def convert_android_timestamp(timestamp: int) -> str:
    """Convert Android timestamp (milliseconds) to ISO format"""
    if timestamp and timestamp > 0:
        try:
            # Android timestamps are in milliseconds
            if timestamp > 10000000000000:  # Likely microseconds
                timestamp = timestamp // 1000
            elif timestamp > 10000000000:  # Likely milliseconds
                timestamp = timestamp // 1000
            return datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat()
        except:
            return str(timestamp)
    return "unknown"


@mcp.tool()
def parse_contacts_db(
    db_path: str,
    output_file: Optional[str] = None
) -> dict[str, Any]:
    """
    Parse Android contacts database (contacts2.db).
    Extracts all contact information including names, phone numbers, emails, etc.
    
    Args:
        db_path: Path to contacts2.db file
        output_file: Optional path to save parsed results as JSON
    """
    db_file = Path(db_path)
    if not db_file.exists():
        return {"success": False, "error": f"Database not found: {db_path}"}
    
    try:
        file_hash = calculate_file_hash(db_file)
        conn = sqlite3.connect(str(db_file))
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        contacts = []
        
        # Query contacts
        cursor.execute("""
            SELECT 
                c._id,
                c.display_name,
                c.starred,
                c.times_contacted,
                c.last_time_contacted,
                c.contact_last_updated_timestamp
            FROM contacts c
        """)
        
        for row in cursor.fetchall():
            contact = dict(row)
            contact_id = contact['_id']
            
            # Get phone numbers
            cursor.execute("""
                SELECT data1, data2 FROM data 
                WHERE contact_id = ? AND mimetype_id IN (
                    SELECT _id FROM mimetypes WHERE mimetype = 'vnd.android.cursor.item/phone_v2'
                )
            """, (contact_id,))
            contact['phone_numbers'] = [{"number": r[0], "type": r[1]} for r in cursor.fetchall()]
            
            # Get emails
            cursor.execute("""
                SELECT data1, data2 FROM data 
                WHERE contact_id = ? AND mimetype_id IN (
                    SELECT _id FROM mimetypes WHERE mimetype = 'vnd.android.cursor.item/email_v2'
                )
            """, (contact_id,))
            contact['emails'] = [{"email": r[0], "type": r[1]} for r in cursor.fetchall()]
            
            # Convert timestamps
            if contact.get('last_time_contacted'):
                contact['last_time_contacted'] = convert_android_timestamp(contact['last_time_contacted'])
            if contact.get('contact_last_updated_timestamp'):
                contact['contact_last_updated_timestamp'] = convert_android_timestamp(
                    contact['contact_last_updated_timestamp']
                )
            
            contacts.append(contact)
        
        conn.close()
        
        result = {
            "success": True,
            "artifact_type": "contacts",
            "source_file": str(db_file.absolute()),
            "sha256_hash": file_hash,
            "contact_count": len(contacts),
            "contacts": contacts,
            "timestamp": datetime.now().isoformat()
        }
        
        if output_file:
            output_path = Path(output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(result, f, indent=2, ensure_ascii=False)
            result["output_file"] = str(output_path.absolute())
        
        return result
        
    except Exception as e:
        return {"success": False, "error": str(e)}


@mcp.tool()
def parse_sms_db(
    db_path: str,
    output_file: Optional[str] = None
) -> dict[str, Any]:
    """
    Parse Android SMS/MMS database (mmssms.db).
    Extracts all text messages with timestamps and contact information.
    
    Args:
        db_path: Path to mmssms.db file
        output_file: Optional path to save parsed results as JSON
    """
    db_file = Path(db_path)
    if not db_file.exists():
        return {"success": False, "error": f"Database not found: {db_path}"}
    
    try:
        file_hash = calculate_file_hash(db_file)
        conn = sqlite3.connect(str(db_file))
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        messages = []
        
        # Query SMS messages
        cursor.execute("""
            SELECT 
                _id,
                thread_id,
                address,
                person,
                date,
                date_sent,
                read,
                type,
                body,
                seen,
                service_center
            FROM sms
            ORDER BY date DESC
        """)
        
        for row in cursor.fetchall():
            msg = dict(row)
            msg['date'] = convert_android_timestamp(msg['date'])
            msg['date_sent'] = convert_android_timestamp(msg['date_sent']) if msg['date_sent'] else None
            msg['direction'] = 'incoming' if msg['type'] == 1 else 'outgoing'
            messages.append(msg)
        
        conn.close()
        
        result = {
            "success": True,
            "artifact_type": "sms_messages",
            "source_file": str(db_file.absolute()),
            "sha256_hash": file_hash,
            "message_count": len(messages),
            "messages": messages,
            "timestamp": datetime.now().isoformat()
        }
        
        if output_file:
            output_path = Path(output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(result, f, indent=2, ensure_ascii=False)
            result["output_file"] = str(output_path.absolute())
        
        return result
        
    except Exception as e:
        return {"success": False, "error": str(e)}


@mcp.tool()
def parse_call_log_db(
    db_path: str,
    output_file: Optional[str] = None
) -> dict[str, Any]:
    """
    Parse Android call log database (calllog.db or contacts2.db).
    Extracts all call records with timestamps, duration, and contact info.
    
    Args:
        db_path: Path to call log database file
        output_file: Optional path to save parsed results as JSON
    """
    db_file = Path(db_path)
    if not db_file.exists():
        return {"success": False, "error": f"Database not found: {db_path}"}
    
    try:
        file_hash = calculate_file_hash(db_file)
        conn = sqlite3.connect(str(db_file))
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        calls = []
        
        # Query call logs
        cursor.execute("""
            SELECT 
                _id,
                number,
                presentation,
                date,
                duration,
                type,
                name,
                numberlabel,
                countryiso,
                geocoded_location,
                subscription_id
            FROM calls
            ORDER BY date DESC
        """)
        
        call_types = {1: 'incoming', 2: 'outgoing', 3: 'missed', 4: 'voicemail', 5: 'rejected', 6: 'blocked'}
        
        for row in cursor.fetchall():
            call = dict(row)
            call['date'] = convert_android_timestamp(call['date'])
            call['call_type'] = call_types.get(call['type'], 'unknown')
            call['duration_formatted'] = f"{call['duration'] // 60}m {call['duration'] % 60}s"
            calls.append(call)
        
        conn.close()
        
        # Calculate statistics
        total_duration = sum(c.get('duration', 0) for c in calls)
        incoming_count = sum(1 for c in calls if c.get('call_type') == 'incoming')
        outgoing_count = sum(1 for c in calls if c.get('call_type') == 'outgoing')
        missed_count = sum(1 for c in calls if c.get('call_type') == 'missed')
        
        result = {
            "success": True,
            "artifact_type": "call_logs",
            "source_file": str(db_file.absolute()),
            "sha256_hash": file_hash,
            "call_count": len(calls),
            "statistics": {
                "incoming": incoming_count,
                "outgoing": outgoing_count,
                "missed": missed_count,
                "total_duration_seconds": total_duration,
                "total_duration_formatted": f"{total_duration // 3600}h {(total_duration % 3600) // 60}m"
            },
            "calls": calls,
            "timestamp": datetime.now().isoformat()
        }
        
        if output_file:
            output_path = Path(output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(result, f, indent=2, ensure_ascii=False)
            result["output_file"] = str(output_path.absolute())
        
        return result
        
    except Exception as e:
        return {"success": False, "error": str(e)}


@mcp.tool()
def parse_browser_history(
    db_path: str,
    browser_type: str = "chrome",
    output_file: Optional[str] = None
) -> dict[str, Any]:
    """
    Parse browser history database (Chrome, Firefox, Samsung, etc.).
    Extracts visited URLs, titles, timestamps, and visit counts.
    
    Args:
        db_path: Path to browser history database
        browser_type: Type of browser (chrome, firefox, samsung)
        output_file: Optional path to save parsed results as JSON
    """
    db_file = Path(db_path)
    if not db_file.exists():
        return {"success": False, "error": f"Database not found: {db_path}"}
    
    try:
        file_hash = calculate_file_hash(db_file)
        conn = sqlite3.connect(str(db_file))
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        history = []
        
        if browser_type.lower() == "chrome":
            # Chrome/Chromium history
            cursor.execute("""
                SELECT 
                    u.id,
                    u.url,
                    u.title,
                    u.visit_count,
                    u.last_visit_time,
                    v.visit_time
                FROM urls u
                LEFT JOIN visits v ON u.id = v.url
                ORDER BY u.last_visit_time DESC
            """)
            
            for row in cursor.fetchall():
                entry = dict(row)
                # Chrome timestamps are microseconds since 1601-01-01
                if entry.get('last_visit_time'):
                    chrome_epoch = 11644473600000000  # microseconds from 1601 to 1970
                    unix_ts = (entry['last_visit_time'] - chrome_epoch) // 1000000
                    entry['last_visit_time'] = datetime.fromtimestamp(unix_ts, tz=timezone.utc).isoformat()
                history.append(entry)
        
        elif browser_type.lower() == "firefox":
            cursor.execute("""
                SELECT 
                    id,
                    url,
                    title,
                    visit_count,
                    last_visit_date
                FROM moz_places
                ORDER BY last_visit_date DESC
            """)
            
            for row in cursor.fetchall():
                entry = dict(row)
                if entry.get('last_visit_date'):
                    entry['last_visit_date'] = convert_android_timestamp(entry['last_visit_date'] // 1000)
                history.append(entry)
        
        conn.close()
        
        result = {
            "success": True,
            "artifact_type": "browser_history",
            "browser": browser_type,
            "source_file": str(db_file.absolute()),
            "sha256_hash": file_hash,
            "entry_count": len(history),
            "history": history,
            "timestamp": datetime.now().isoformat()
        }
        
        if output_file:
            output_path = Path(output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(result, f, indent=2, ensure_ascii=False)
            result["output_file"] = str(output_path.absolute())
        
        return result
        
    except Exception as e:
        return {"success": False, "error": str(e)}


@mcp.tool()
def parse_generic_sqlite(
    db_path: str,
    table_name: Optional[str] = None,
    query: Optional[str] = None,
    output_file: Optional[str] = None
) -> dict[str, Any]:
    """
    Parse any SQLite database with custom query or table extraction.
    Useful for analyzing unknown or application-specific databases.
    
    Args:
        db_path: Path to SQLite database file
        table_name: Specific table to extract (optional)
        query: Custom SQL query (optional, overrides table_name)
        output_file: Optional path to save parsed results as JSON
    """
    db_file = Path(db_path)
    if not db_file.exists():
        return {"success": False, "error": f"Database not found: {db_path}"}
    
    try:
        file_hash = calculate_file_hash(db_file)
        conn = sqlite3.connect(str(db_file))
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Get schema information
        cursor.execute("SELECT name, sql FROM sqlite_master WHERE type='table'")
        tables = {row[0]: row[1] for row in cursor.fetchall()}
        
        records = []
        executed_query = None
        
        if query:
            executed_query = query
            cursor.execute(query)
            records = [dict(row) for row in cursor.fetchall()]
        elif table_name:
            if table_name not in tables:
                return {"success": False, "error": f"Table '{table_name}' not found", "available_tables": list(tables.keys())}
            executed_query = f"SELECT * FROM {table_name}"
            cursor.execute(executed_query)
            records = [dict(row) for row in cursor.fetchall()]
        
        conn.close()
        
        result = {
            "success": True,
            "artifact_type": "sqlite_database",
            "source_file": str(db_file.absolute()),
            "sha256_hash": file_hash,
            "tables": list(tables.keys()),
            "table_schemas": tables,
            "executed_query": executed_query,
            "record_count": len(records),
            "records": records,
            "timestamp": datetime.now().isoformat()
        }
        
        if output_file:
            output_path = Path(output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(result, f, indent=2, ensure_ascii=False, default=str)
            result["output_file"] = str(output_path.absolute())
        
        return result
        
    except Exception as e:
        return {"success": False, "error": str(e)}


@mcp.tool()
def extract_exif_metadata(
    file_path: str,
    output_file: Optional[str] = None
) -> dict[str, Any]:
    """
    Extract EXIF metadata from image files.
    Critical for GPS location, timestamps, and camera information.
    
    Args:
        file_path: Path to image file (JPEG, TIFF, etc.)
        output_file: Optional path to save parsed results as JSON
    """
    image_file = Path(file_path)
    if not image_file.exists():
        return {"success": False, "error": f"File not found: {file_path}"}
    
    try:
        import exifread
        
        file_hash = calculate_file_hash(image_file)
        
        with open(image_file, 'rb') as f:
            tags = exifread.process_file(f, details=True)
        
        # Convert to serializable dict
        exif_data = {}
        for tag, value in tags.items():
            if tag not in ('JPEGThumbnail', 'TIFFThumbnail', 'EXIF MakerNote'):
                exif_data[tag] = str(value)
        
        # Extract GPS coordinates if available
        gps_info = None
        if 'GPS GPSLatitude' in tags and 'GPS GPSLongitude' in tags:
            def convert_gps_coord(coord, ref):
                d = float(coord.values[0].num) / float(coord.values[0].den)
                m = float(coord.values[1].num) / float(coord.values[1].den)
                s = float(coord.values[2].num) / float(coord.values[2].den)
                decimal = d + m/60 + s/3600
                if ref in ['S', 'W']:
                    decimal = -decimal
                return decimal
            
            lat = convert_gps_coord(tags['GPS GPSLatitude'], str(tags.get('GPS GPSLatitudeRef', 'N')))
            lon = convert_gps_coord(tags['GPS GPSLongitude'], str(tags.get('GPS GPSLongitudeRef', 'E')))
            gps_info = {
                "latitude": lat,
                "longitude": lon,
                "google_maps_link": f"https://www.google.com/maps?q={lat},{lon}"
            }
        
        result = {
            "success": True,
            "artifact_type": "image_metadata",
            "source_file": str(image_file.absolute()),
            "sha256_hash": file_hash,
            "file_size": image_file.stat().st_size,
            "exif_tag_count": len(exif_data),
            "gps_location": gps_info,
            "exif_data": exif_data,
            "timestamp": datetime.now().isoformat()
        }
        
        if output_file:
            output_path = Path(output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(result, f, indent=2, ensure_ascii=False)
            result["output_file"] = str(output_path.absolute())
        
        return result
        
    except ImportError:
        return {"success": False, "error": "exifread package not installed. Run: pip install exifread"}
    except Exception as e:
        return {"success": False, "error": str(e)}


@mcp.tool()
def extract_media_gallery_metadata(
    directory_path: str,
    extensions: list[str] = [".jpg", ".jpeg", ".png", ".mp4", ".mp3", ".pdf"],
    output_file: Optional[str] = None
) -> dict[str, Any]:
    """
    Scan directory for media files and extract metadata.
    Useful for analyzing downloaded files, camera roll, screenshots.
    
    Args:
        directory_path: Path to directory to scan
        extensions: File extensions to include
        output_file: Optional path to save results as JSON
    """
    dir_path = Path(directory_path)
    if not dir_path.exists():
        return {"success": False, "error": f"Directory not found: {directory_path}"}
    
    try:
        media_files = []
        
        for ext in extensions:
            for file_path in dir_path.rglob(f"*{ext}"):
                if file_path.is_file():
                    stat = file_path.stat()
                    media_files.append({
                        "path": str(file_path),
                        "name": file_path.name,
                        "extension": file_path.suffix,
                        "size_bytes": stat.st_size,
                        "created": datetime.fromtimestamp(stat.st_ctime).isoformat(),
                        "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                        "sha256": calculate_file_hash(file_path)
                    })
        
        # Sort by modification time
        media_files.sort(key=lambda x: x['modified'], reverse=True)
        
        # Calculate statistics
        total_size = sum(f['size_bytes'] for f in media_files)
        by_extension = {}
        for f in media_files:
            ext = f['extension'].lower()
            by_extension[ext] = by_extension.get(ext, 0) + 1
        
        result = {
            "success": True,
            "artifact_type": "media_gallery",
            "source_directory": str(dir_path.absolute()),
            "file_count": len(media_files),
            "total_size_bytes": total_size,
            "total_size_mb": round(total_size / (1024 * 1024), 2),
            "files_by_extension": by_extension,
            "files": media_files,
            "timestamp": datetime.now().isoformat()
        }
        
        if output_file:
            output_path = Path(output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(result, f, indent=2, ensure_ascii=False)
            result["output_file"] = str(output_path.absolute())
        
        return result
        
    except Exception as e:
        return {"success": False, "error": str(e)}


@mcp.tool()
def create_timeline(
    artifacts: list[dict[str, Any]],
    output_file: Optional[str] = None
) -> dict[str, Any]:
    """
    Create a unified timeline from multiple artifact sources.
    Merges SMS, calls, browser history, etc. into chronological order.
    
    Args:
        artifacts: List of parsed artifact dictionaries with timestamp fields
        output_file: Optional path to save timeline as JSON
    """
    try:
        timeline_events = []
        
        for artifact in artifacts:
            artifact_type = artifact.get('artifact_type', 'unknown')
            
            if artifact_type == 'sms_messages' and 'messages' in artifact:
                for msg in artifact['messages']:
                    timeline_events.append({
                        "timestamp": msg.get('date'),
                        "event_type": "sms",
                        "direction": msg.get('direction'),
                        "contact": msg.get('address'),
                        "content_preview": msg.get('body', '')[:100] if msg.get('body') else None,
                        "source": "mmssms.db"
                    })
            
            elif artifact_type == 'call_logs' and 'calls' in artifact:
                for call in artifact['calls']:
                    timeline_events.append({
                        "timestamp": call.get('date'),
                        "event_type": "call",
                        "call_type": call.get('call_type'),
                        "contact": call.get('number'),
                        "duration": call.get('duration_formatted'),
                        "source": "calllog.db"
                    })
            
            elif artifact_type == 'browser_history' and 'history' in artifact:
                for entry in artifact['history']:
                    timeline_events.append({
                        "timestamp": entry.get('last_visit_time') or entry.get('last_visit_date'),
                        "event_type": "web_visit",
                        "url": entry.get('url'),
                        "title": entry.get('title'),
                        "visit_count": entry.get('visit_count'),
                        "source": artifact.get('browser', 'browser')
                    })
        
        # Sort by timestamp
        timeline_events.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
        
        result = {
            "success": True,
            "artifact_type": "forensic_timeline",
            "event_count": len(timeline_events),
            "event_types": list(set(e.get('event_type') for e in timeline_events)),
            "timeline": timeline_events,
            "timestamp": datetime.now().isoformat()
        }
        
        if output_file:
            output_path = Path(output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(result, f, indent=2, ensure_ascii=False)
            result["output_file"] = str(output_path.absolute())
        
        return result
        
    except Exception as e:
        return {"success": False, "error": str(e)}


# Run server
if __name__ == "__main__":
    mcp.run(transport="stdio")
