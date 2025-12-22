"""
Application Analyzer MCP Server
Federal Investigation Agency (FIA) - Android Forensics Framework

Provides tools for analyzing specific application data including:
- WhatsApp messages and media
- Telegram chats
- Signal conversations
- Social media apps (Facebook, Instagram, Twitter)
- Email clients
- File managers and cloud storage apps
"""

import base64
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
    "FIA Application Analyzer",
    instructions="""
    Secure MCP server for analyzing Android application data.
    Specializes in messaging apps, social media, and communication forensics.
    Maintains evidence integrity with SHA-256 hashing.
    """
)


def calculate_file_hash(file_path: Path) -> str:
    """Calculate SHA-256 hash of a file"""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256_hash.update(chunk)
    return sha256_hash.hexdigest()


def convert_whatsapp_timestamp(timestamp: int) -> str:
    """Convert WhatsApp timestamp (milliseconds) to ISO format"""
    if timestamp and timestamp > 0:
        try:
            return datetime.fromtimestamp(timestamp / 1000, tz=timezone.utc).isoformat()
        except:
            return str(timestamp)
    return "unknown"


@mcp.tool()
def analyze_whatsapp(
    db_path: str,
    include_media_info: bool = True,
    output_file: Optional[str] = None
) -> dict[str, Any]:
    """
    Analyze WhatsApp msgstore.db database.
    Extracts messages, contacts, groups, and media references.
    
    Args:
        db_path: Path to WhatsApp msgstore.db or msgstore.db.crypt* file
        include_media_info: Include media file references
        output_file: Optional path to save parsed results as JSON
    
    Note: Encrypted databases (crypt12, crypt14, etc.) require the key file.
    """
    db_file = Path(db_path)
    if not db_file.exists():
        return {"success": False, "error": f"Database not found: {db_path}"}
    
    # Check if encrypted
    if ".crypt" in db_file.name:
        return {
            "success": False,
            "error": "Encrypted WhatsApp database detected",
            "encryption_type": db_file.suffix,
            "note": "Use decrypt_whatsapp_db tool with the key file from /data/data/com.whatsapp/files/key"
        }
    
    try:
        file_hash = calculate_file_hash(db_file)
        conn = sqlite3.connect(str(db_file))
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Get database version/schema info
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [row[0] for row in cursor.fetchall()]
        
        messages = []
        contacts = []
        groups = []
        
        # Parse messages (different schemas for different WhatsApp versions)
        if 'messages' in tables:
            # Newer WhatsApp schema
            cursor.execute("""
                SELECT 
                    m._id,
                    m.key_remote_jid,
                    m.key_from_me,
                    m.key_id,
                    m.status,
                    m.data,
                    m.timestamp,
                    m.media_wa_type,
                    m.media_size,
                    m.media_name,
                    m.media_caption,
                    m.latitude,
                    m.longitude,
                    m.remote_resource
                FROM messages m
                ORDER BY m.timestamp DESC
                LIMIT 10000
            """)
            
            media_types = {
                0: 'text', 1: 'image', 2: 'audio', 3: 'video',
                4: 'contact', 5: 'location', 8: 'document',
                9: 'gif', 13: 'sticker', 15: 'voice_note'
            }
            
            for row in cursor.fetchall():
                msg = dict(row)
                msg['timestamp'] = convert_whatsapp_timestamp(msg['timestamp'])
                msg['direction'] = 'sent' if msg['key_from_me'] else 'received'
                msg['media_type'] = media_types.get(msg.get('media_wa_type', 0), 'unknown')
                
                # Parse JID to get phone number
                jid = msg.get('key_remote_jid', '')
                if jid:
                    msg['contact_number'] = jid.split('@')[0]
                    msg['is_group'] = '@g.us' in jid
                
                messages.append(msg)
        
        elif 'message' in tables:
            # Older WhatsApp schema
            cursor.execute("""
                SELECT * FROM message
                ORDER BY timestamp DESC
                LIMIT 10000
            """)
            for row in cursor.fetchall():
                msg = dict(row)
                if 'timestamp' in msg:
                    msg['timestamp'] = convert_whatsapp_timestamp(msg['timestamp'])
                messages.append(msg)
        
        # Parse contacts/chats
        if 'jid' in tables:
            cursor.execute("SELECT * FROM jid")
            contacts = [dict(row) for row in cursor.fetchall()]
        elif 'wa_contacts' in tables:
            cursor.execute("SELECT * FROM wa_contacts")
            contacts = [dict(row) for row in cursor.fetchall()]
        
        # Parse groups
        if 'group_participants' in tables:
            cursor.execute("""
                SELECT gp.*, j.user as member_number
                FROM group_participants gp
                LEFT JOIN jid j ON gp.jid_row_id = j._id
            """)
            groups = [dict(row) for row in cursor.fetchall()]
        
        conn.close()
        
        # Calculate statistics
        sent_count = sum(1 for m in messages if m.get('direction') == 'sent')
        received_count = len(messages) - sent_count
        media_count = sum(1 for m in messages if m.get('media_type') and m.get('media_type') != 'text')
        
        # Get unique contacts
        unique_contacts = set()
        for m in messages:
            if m.get('contact_number'):
                unique_contacts.add(m['contact_number'])
        
        result = {
            "success": True,
            "artifact_type": "whatsapp",
            "source_file": str(db_file.absolute()),
            "sha256_hash": file_hash,
            "database_tables": tables,
            "statistics": {
                "total_messages": len(messages),
                "sent_messages": sent_count,
                "received_messages": received_count,
                "media_messages": media_count,
                "unique_contacts": len(unique_contacts),
                "groups_found": len(groups)
            },
            "messages": messages[:1000],  # Limit for response size
            "contacts": contacts[:500],
            "groups": groups[:100],
            "timestamp": datetime.now().isoformat(),
            "forensic_note": "Full message history available in output file"
        }
        
        if output_file:
            output_path = Path(output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            # Save full data
            full_result = result.copy()
            full_result["messages"] = messages
            full_result["contacts"] = contacts
            full_result["groups"] = groups
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(full_result, f, indent=2, ensure_ascii=False, default=str)
            result["output_file"] = str(output_path.absolute())
        
        return result
        
    except Exception as e:
        return {"success": False, "error": str(e)}


@mcp.tool()
def analyze_telegram(
    db_path: str,
    output_file: Optional[str] = None
) -> dict[str, Any]:
    """
    Analyze Telegram database.
    Extracts messages, contacts, channels, and groups.
    
    Args:
        db_path: Path to Telegram cache4.db or tgnet.dat
        output_file: Optional path to save parsed results as JSON
    
    Note: Telegram stores data in multiple locations and formats.
    """
    db_file = Path(db_path)
    if not db_file.exists():
        return {"success": False, "error": f"Database not found: {db_path}"}
    
    try:
        file_hash = calculate_file_hash(db_file)
        conn = sqlite3.connect(str(db_file))
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Get tables
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [row[0] for row in cursor.fetchall()]
        
        messages = []
        users = []
        chats = []
        
        # Parse messages
        if 'messages_v2' in tables:
            cursor.execute("""
                SELECT * FROM messages_v2 
                ORDER BY date DESC 
                LIMIT 10000
            """)
            for row in cursor.fetchall():
                msg = dict(row)
                if msg.get('date'):
                    msg['date'] = datetime.fromtimestamp(msg['date'], tz=timezone.utc).isoformat()
                messages.append(msg)
        elif 'messages' in tables:
            cursor.execute("SELECT * FROM messages ORDER BY date DESC LIMIT 10000")
            for row in cursor.fetchall():
                msg = dict(row)
                if msg.get('date'):
                    msg['date'] = datetime.fromtimestamp(msg['date'], tz=timezone.utc).isoformat()
                messages.append(msg)
        
        # Parse users
        if 'users' in tables:
            cursor.execute("SELECT * FROM users LIMIT 5000")
            users = [dict(row) for row in cursor.fetchall()]
        
        # Parse chats/channels
        if 'chats' in tables:
            cursor.execute("SELECT * FROM chats LIMIT 1000")
            chats = [dict(row) for row in cursor.fetchall()]
        
        conn.close()
        
        result = {
            "success": True,
            "artifact_type": "telegram",
            "source_file": str(db_file.absolute()),
            "sha256_hash": file_hash,
            "database_tables": tables,
            "statistics": {
                "total_messages": len(messages),
                "total_users": len(users),
                "total_chats": len(chats)
            },
            "messages": messages[:500],
            "users": users[:200],
            "chats": chats[:100],
            "timestamp": datetime.now().isoformat()
        }
        
        if output_file:
            output_path = Path(output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            full_result = result.copy()
            full_result["messages"] = messages
            full_result["users"] = users
            full_result["chats"] = chats
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(full_result, f, indent=2, ensure_ascii=False, default=str)
            result["output_file"] = str(output_path.absolute())
        
        return result
        
    except Exception as e:
        return {"success": False, "error": str(e)}


@mcp.tool()
def analyze_facebook_messenger(
    db_path: str,
    output_file: Optional[str] = None
) -> dict[str, Any]:
    """
    Analyze Facebook Messenger database (threads_db2).
    Extracts conversations, participants, and media.
    
    Args:
        db_path: Path to threads_db2 database
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
        
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [row[0] for row in cursor.fetchall()]
        
        messages = []
        threads = []
        
        # Parse messages
        if 'messages' in tables:
            cursor.execute("""
                SELECT * FROM messages 
                ORDER BY timestamp_ms DESC 
                LIMIT 10000
            """)
            for row in cursor.fetchall():
                msg = dict(row)
                if msg.get('timestamp_ms'):
                    msg['timestamp'] = datetime.fromtimestamp(
                        msg['timestamp_ms'] / 1000, tz=timezone.utc
                    ).isoformat()
                messages.append(msg)
        
        # Parse threads
        if 'threads' in tables:
            cursor.execute("SELECT * FROM threads LIMIT 500")
            threads = [dict(row) for row in cursor.fetchall()]
        
        conn.close()
        
        result = {
            "success": True,
            "artifact_type": "facebook_messenger",
            "source_file": str(db_file.absolute()),
            "sha256_hash": file_hash,
            "database_tables": tables,
            "statistics": {
                "total_messages": len(messages),
                "total_threads": len(threads)
            },
            "messages": messages[:500],
            "threads": threads[:100],
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
def analyze_instagram(
    db_path: str,
    output_file: Optional[str] = None
) -> dict[str, Any]:
    """
    Analyze Instagram database.
    Extracts direct messages, user data, and activity.
    
    Args:
        db_path: Path to Instagram database
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
        
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [row[0] for row in cursor.fetchall()]
        
        # Extract available data
        data = {}
        for table in tables[:20]:  # Limit tables to analyze
            try:
                cursor.execute(f"SELECT * FROM {table} LIMIT 1000")
                data[table] = [dict(row) for row in cursor.fetchall()]
            except:
                continue
        
        conn.close()
        
        result = {
            "success": True,
            "artifact_type": "instagram",
            "source_file": str(db_file.absolute()),
            "sha256_hash": file_hash,
            "database_tables": tables,
            "extracted_data": data,
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
def analyze_gmail(
    db_path: str,
    output_file: Optional[str] = None
) -> dict[str, Any]:
    """
    Analyze Gmail database (mailstore.*.db).
    Extracts emails, labels, and attachments info.
    
    Args:
        db_path: Path to Gmail database
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
        
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [row[0] for row in cursor.fetchall()]
        
        messages = []
        conversations = []
        
        # Parse messages/conversations
        if 'messages' in tables:
            cursor.execute("""
                SELECT * FROM messages 
                ORDER BY dateSentMs DESC 
                LIMIT 5000
            """)
            for row in cursor.fetchall():
                msg = dict(row)
                if msg.get('dateSentMs'):
                    msg['date_sent'] = datetime.fromtimestamp(
                        msg['dateSentMs'] / 1000, tz=timezone.utc
                    ).isoformat()
                messages.append(msg)
        
        if 'conversations' in tables:
            cursor.execute("SELECT * FROM conversations LIMIT 1000")
            conversations = [dict(row) for row in cursor.fetchall()]
        
        conn.close()
        
        result = {
            "success": True,
            "artifact_type": "gmail",
            "source_file": str(db_file.absolute()),
            "sha256_hash": file_hash,
            "database_tables": tables,
            "statistics": {
                "total_messages": len(messages),
                "total_conversations": len(conversations)
            },
            "messages": messages[:200],
            "conversations": conversations[:100],
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
def list_installed_apps_data(
    data_dir: str,
    output_file: Optional[str] = None
) -> dict[str, Any]:
    """
    List all installed applications and their data directories.
    Identifies forensically interesting apps for further analysis.
    
    Args:
        data_dir: Path to extracted /data/data directory
        output_file: Optional path to save results as JSON
    """
    data_path = Path(data_dir)
    if not data_path.exists():
        return {"success": False, "error": f"Directory not found: {data_dir}"}
    
    # Categories of forensically interesting apps
    forensic_categories = {
        "messaging": ["whatsapp", "telegram", "signal", "viber", "imo", "wechat", "line", "kik"],
        "social_media": ["facebook", "instagram", "twitter", "tiktok", "snapchat", "linkedin"],
        "email": ["gmail", "outlook", "yahoo", "mail"],
        "browsers": ["chrome", "firefox", "opera", "samsung", "brave", "edge"],
        "cloud_storage": ["dropbox", "drive", "onedrive", "mega", "box"],
        "dating": ["tinder", "bumble", "hinge", "grindr", "okcupid"],
        "finance": ["paypal", "venmo", "cashapp", "bank", "crypto", "wallet"],
        "vpn": ["vpn", "proxy", "tor", "tunnel"],
        "notes": ["keep", "evernote", "notion", "notes", "memo"]
    }
    
    apps = []
    categorized_apps = {cat: [] for cat in forensic_categories}
    
    try:
        for app_dir in data_path.iterdir():
            if app_dir.is_dir():
                package_name = app_dir.name
                
                # Get directory size and file count
                total_size = 0
                file_count = 0
                databases = []
                shared_prefs = []
                
                for f in app_dir.rglob("*"):
                    if f.is_file():
                        file_count += 1
                        total_size += f.stat().st_size
                        
                        if f.suffix in ['.db', '.sqlite', '.sqlite3']:
                            databases.append(str(f.relative_to(app_dir)))
                        elif f.suffix == '.xml' and 'shared_prefs' in str(f):
                            shared_prefs.append(str(f.relative_to(app_dir)))
                
                app_info = {
                    "package_name": package_name,
                    "path": str(app_dir),
                    "file_count": file_count,
                    "total_size_bytes": total_size,
                    "total_size_mb": round(total_size / (1024 * 1024), 2),
                    "databases": databases,
                    "shared_prefs": shared_prefs,
                    "has_databases": len(databases) > 0
                }
                
                apps.append(app_info)
                
                # Categorize
                pkg_lower = package_name.lower()
                for category, keywords in forensic_categories.items():
                    if any(kw in pkg_lower for kw in keywords):
                        categorized_apps[category].append(package_name)
                        app_info["forensic_category"] = category
                        break
        
        # Sort by size
        apps.sort(key=lambda x: x['total_size_bytes'], reverse=True)
        
        result = {
            "success": True,
            "artifact_type": "installed_apps_data",
            "source_directory": str(data_path.absolute()),
            "total_apps": len(apps),
            "apps_with_databases": sum(1 for a in apps if a['has_databases']),
            "categorized_apps": {k: v for k, v in categorized_apps.items() if v},
            "apps": apps,
            "timestamp": datetime.now().isoformat(),
            "forensic_note": "Focus analysis on apps in forensic categories"
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
def extract_app_credentials(
    app_data_path: str,
    output_file: Optional[str] = None
) -> dict[str, Any]:
    """
    Extract stored credentials and tokens from app data.
    Analyzes shared_prefs, databases, and cache for sensitive data.
    
    Args:
        app_data_path: Path to specific app's data directory
        output_file: Optional path to save results as JSON
    
    Warning: Handle extracted credentials with care - chain of custody applies.
    """
    app_path = Path(app_data_path)
    if not app_path.exists():
        return {"success": False, "error": f"Directory not found: {app_data_path}"}
    
    credentials = []
    tokens = []
    sensitive_data = []
    
    # Patterns to search for
    patterns = {
        "email": r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
        "phone": r'\+?[1-9]\d{6,14}',
        "token": r'(token|bearer|auth|api_key|secret)["\s:=]+([a-zA-Z0-9_\-\.]{20,})',
        "password": r'(password|passwd|pwd)["\s:=]+["\']?([^\s"\'<>]{4,})',
        "session": r'(session|sid|jsessionid)["\s:=]+([a-zA-Z0-9_\-]{16,})'
    }
    
    try:
        # Scan shared_prefs
        shared_prefs_dir = app_path / "shared_prefs"
        if shared_prefs_dir.exists():
            for xml_file in shared_prefs_dir.glob("*.xml"):
                try:
                    content = xml_file.read_text(encoding='utf-8', errors='ignore')
                    
                    for pattern_name, pattern in patterns.items():
                        matches = re.findall(pattern, content, re.IGNORECASE)
                        for match in matches:
                            if isinstance(match, tuple):
                                value = match[1] if len(match) > 1 else match[0]
                            else:
                                value = match
                            
                            sensitive_data.append({
                                "type": pattern_name,
                                "value": value[:100],  # Truncate for safety
                                "source_file": str(xml_file.name),
                                "source_type": "shared_prefs"
                            })
                except:
                    continue
        
        # Scan databases for account tables
        for db_file in app_path.rglob("*.db"):
            try:
                conn = sqlite3.connect(str(db_file))
                cursor = conn.cursor()
                
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
                tables = [row[0] for row in cursor.fetchall()]
                
                # Look for account/credential tables
                account_tables = [t for t in tables if any(
                    kw in t.lower() for kw in ['account', 'user', 'auth', 'credential', 'login', 'token']
                )]
                
                for table in account_tables:
                    try:
                        cursor.execute(f"SELECT * FROM {table} LIMIT 50")
                        rows = cursor.fetchall()
                        if rows:
                            columns = [d[0] for d in cursor.description]
                            for row in rows:
                                credentials.append({
                                    "table": table,
                                    "database": db_file.name,
                                    "columns": columns,
                                    "data": dict(zip(columns, [str(v)[:100] for v in row]))
                                })
                    except:
                        continue
                
                conn.close()
            except:
                continue
        
        result = {
            "success": True,
            "artifact_type": "app_credentials",
            "source_directory": str(app_path.absolute()),
            "findings": {
                "credentials_found": len(credentials),
                "sensitive_patterns_found": len(sensitive_data)
            },
            "credentials": credentials[:50],
            "sensitive_data": sensitive_data[:100],
            "timestamp": datetime.now().isoformat(),
            "warning": "Handle with care - contains potentially sensitive authentication data"
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


# Run server
if __name__ == "__main__":
    mcp.run(transport="stdio")
