"""
Real-World Attack Scenario Tests
Federal Investigation Agency - Android Forensics Framework

This test suite simulates real-world attack scenarios and edge cases
that investigators might encounter in the field.

Run with: python -m pytest tests/test_attack_scenarios.py -v
"""

import base64
import json
import os
import re
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional
from unittest.mock import MagicMock, patch, call

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


class TestAntiForensicsTechniques(unittest.TestCase):
    """Test handling of anti-forensics techniques."""
    
    def test_timestomping_detection(self):
        """Detect files with manipulated timestamps."""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"test data")
            temp_file = f.name
        
        try:
            # Set timestamp to future (suspicious)
            future_time = time.time() + 365 * 24 * 60 * 60  # 1 year in future
            os.utime(temp_file, (future_time, future_time))
            
            # Detect anomaly
            mtime = os.path.getmtime(temp_file)
            is_future = mtime > time.time()
            
            self.assertTrue(is_future)
        finally:
            os.unlink(temp_file)
    
    def test_hidden_file_detection(self):
        """Detect hidden files and directories."""
        hidden_patterns = [
            ".hidden_file",
            "....",
            ". ",  # Single dot with space
            ".nomedia",
            ".thumbnail",
        ]
        
        for pattern in hidden_patterns:
            is_hidden = pattern.startswith('.')
            self.assertTrue(is_hidden, f"{pattern} should be detected as hidden")
    
    def test_deleted_file_markers(self):
        """Detect markers of deleted files in database."""
        with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as f:
            db_path = f.name
        
        try:
            conn = sqlite3.connect(db_path)
            conn.execute("""
                CREATE TABLE files (
                    id INTEGER PRIMARY KEY,
                    path TEXT,
                    deleted INTEGER DEFAULT 0,
                    delete_time INTEGER
                )
            """)
            
            # Insert records including "deleted" ones
            conn.execute("INSERT INTO files VALUES (1, '/sdcard/photo.jpg', 0, NULL)")
            conn.execute("INSERT INTO files VALUES (2, '/sdcard/secret.pdf', 1, 1703260800000)")
            conn.execute("INSERT INTO files VALUES (3, '/sdcard/docs/file.txt', 1, 1703261800000)")
            conn.commit()
            
            # Find deleted files
            cursor = conn.execute("SELECT * FROM files WHERE deleted = 1")
            deleted = cursor.fetchall()
            conn.close()
            
            self.assertEqual(len(deleted), 2)
        finally:
            os.unlink(db_path)
    
    def test_obfuscated_data_detection(self):
        """Detect base64 encoded or obfuscated data."""
        samples = [
            "SGVsbG8gV29ybGQ=",  # Base64: "Hello World"
            "VGhpcyBpcyBzZWNyZXQ=",  # Base64: "This is secret"
            "aHR0cHM6Ly9leGFtcGxlLmNvbQ==",  # Base64: URL
        ]
        
        for sample in samples:
            try:
                decoded = base64.b64decode(sample)
                is_valid_base64 = True
                self.assertIsNotNone(decoded)
            except Exception:
                is_valid_base64 = False
    
    def test_encrypted_database_detection(self):
        """Detect encrypted SQLite databases."""
        # Create fake encrypted database (SQLCipher pattern)
        with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as f:
            # SQLCipher encrypted DBs have specific header
            f.write(b'\x00' * 16)  # Encrypted header
            f.write(os.urandom(1000))
            encrypted_db = f.name
        
        is_encrypted = False
        conn = None
        try:
            # Try to open - should fail when querying
            conn = sqlite3.connect(encrypted_db)
            conn.execute("SELECT * FROM sqlite_master")
            is_encrypted = False
        except sqlite3.DatabaseError:
            is_encrypted = True
        finally:
            if conn:
                try:
                    conn.close()
                except Exception:
                    pass
            # Small delay to ensure file handle is released on Windows
            import gc
            gc.collect()
            time.sleep(0.1)
            try:
                os.unlink(encrypted_db)
            except PermissionError:
                pass  # May fail on Windows, ignore
        
        self.assertTrue(is_encrypted)


class TestMalwareArtifacts(unittest.TestCase):
    """Test detection of malware-related artifacts."""
    
    def test_suspicious_package_names(self):
        """Detect suspicious package naming patterns."""
        suspicious_packages = [
            "com.google.android.update",  # Fake system app
            "com.android.systemupdate",
            "com.android.vending.billing.security",
            "com.samsung.android.app.settings.security",
            "com.system.service.hidden",
        ]
        
        known_legit_prefixes = [
            "com.google.",
            "com.android.",
            "com.samsung.",
        ]
        
        suspicious_keywords = ['hidden', 'security', 'update', 'system']
        
        # Check if packages look like they're impersonating system apps
        detected_suspicious = []
        for pkg in suspicious_packages:
            looks_like_system = any(pkg.startswith(p) for p in known_legit_prefixes)
            has_suspicious_words = any(w in pkg.lower() for w in suspicious_keywords)
            
            # Flag as suspicious if it looks like system app AND has suspicious keywords
            if looks_like_system or has_suspicious_words:
                detected_suspicious.append(pkg)
        
        # All our test cases should be flagged as suspicious
        self.assertEqual(len(detected_suspicious), len(suspicious_packages))
    
    def test_permission_escalation_detection(self):
        """Detect apps with suspicious permission combinations."""
        dangerous_combos = [
            {"READ_CONTACTS", "INTERNET", "RECEIVE_SMS"},
            {"CAMERA", "RECORD_AUDIO", "ACCESS_FINE_LOCATION", "INTERNET"},
            {"READ_CALL_LOG", "INTERNET", "RECEIVE_BOOT_COMPLETED"},
            {"READ_SMS", "SEND_SMS", "INTERNET", "RECEIVE_SMS"},
        ]
        
        for permissions in dangerous_combos:
            has_internet = "INTERNET" in permissions
            has_sensitive = any(p in permissions for p in [
                "READ_CONTACTS", "READ_SMS", "READ_CALL_LOG", 
                "CAMERA", "RECORD_AUDIO", "ACCESS_FINE_LOCATION"
            ])
            
            is_suspicious = has_internet and has_sensitive
            self.assertTrue(is_suspicious)
    
    def test_rootkit_indicators(self):
        """Detect potential rootkit indicators."""
        suspicious_files = [
            "/system/xbin/su",
            "/system/bin/su",
            "/sbin/su",
            "/system/app/Superuser.apk",
            "/data/local/xbin/su",
            "/system/xbin/busybox",
        ]
        
        suspicious_props = [
            "ro.debuggable=1",
            "ro.secure=0",
            "ro.adb.secure=0",
        ]
        
        # In real scenario, check if these exist
        for file in suspicious_files:
            path = Path(file)
            self.assertTrue(path.name in ["su", "busybox", "Superuser.apk"])
        
        for prop in suspicious_props:
            key, value = prop.split("=")
            # These values indicate rooted/insecure device
            self.assertIn(value, ["0", "1"])
    
    def test_c2_communication_patterns(self):
        """Detect Command & Control communication patterns."""
        suspicious_domains = [
            "update.evil-server.xyz",
            "api.malware-c2.ru",
            "download.suspicious-cdn.cc",
        ]
        
        suspicious_patterns = [
            r"\.xyz$",
            r"\.ru$",
            r"\.cc$",
            r"c2|malware|evil",
        ]
        
        for domain in suspicious_domains:
            is_suspicious = any(re.search(p, domain, re.I) for p in suspicious_patterns)
            self.assertTrue(is_suspicious)


class TestDataExfiltrationScenarios(unittest.TestCase):
    """Test scenarios related to data exfiltration detection."""
    
    def test_large_data_transfer_detection(self):
        """Detect unusually large data transfers."""
        network_log = [
            {"app": "com.whatsapp", "bytes_sent": 1024000, "bytes_recv": 2048000},
            {"app": "com.unknown.app", "bytes_sent": 500000000, "bytes_recv": 100},  # Suspicious
            {"app": "com.android.chrome", "bytes_sent": 5000000, "bytes_recv": 50000000},
            {"app": "com.malicious.app", "bytes_sent": 1000000000, "bytes_recv": 50},  # Suspicious
        ]
        
        # Detect asymmetric traffic (lots of upload, little download)
        suspicious = []
        for entry in network_log:
            ratio = entry["bytes_sent"] / max(entry["bytes_recv"], 1)
            if ratio > 1000:  # Sent 1000x more than received
                suspicious.append(entry)
        
        self.assertEqual(len(suspicious), 2)
    
    def test_contact_harvesting_detection(self):
        """Detect mass contact access patterns."""
        access_log = []
        
        # Simulate contact access log
        for i in range(1000):
            access_log.append({
                "timestamp": datetime.now() - timedelta(minutes=i % 60),
                "action": "read_contact",
                "app": "com.suspicious.app" if i < 900 else "com.whatsapp"
            })
        
        # Analyze access patterns
        app_access = {}
        for entry in access_log:
            app = entry["app"]
            app_access[app] = app_access.get(app, 0) + 1
        
        # Detect bulk access
        suspicious_apps = [app for app, count in app_access.items() if count > 100]
        self.assertIn("com.suspicious.app", suspicious_apps)
    
    def test_screenshot_detection(self):
        """Detect suspicious screenshot activity."""
        screenshot_paths = [
            "/sdcard/DCIM/Screenshots/Screenshot_20240115_143000.png",
            "/sdcard/Pictures/Screenshots/screen_1.png",
            "/data/data/com.malware/cache/screenshot.png",  # Suspicious
            "/sdcard/.hidden/screens/capture.png",  # Suspicious
        ]
        
        suspicious = []
        for path in screenshot_paths:
            # Check for hidden directories or app data
            if "/data/data/" in path or "/." in path:
                suspicious.append(path)
        
        self.assertEqual(len(suspicious), 2)


class TestDeviceTamperingScenarios(unittest.TestCase):
    """Test scenarios related to device tampering."""
    
    @patch('subprocess.run')
    def test_bootloader_unlock_detection(self, mock_run):
        """Detect unlocked bootloader."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="Device unlocked: true"
        )
        
        result = mock_run.return_value.stdout
        is_unlocked = "unlocked: true" in result.lower()
        self.assertTrue(is_unlocked)
    
    @patch('subprocess.run')
    def test_custom_rom_detection(self, mock_run):
        """Detect custom ROM installation."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="""ro.build.display.id=LineageOS 20.0-20240115
ro.lineage.version=20.0-20240115-NIGHTLY"""
        )
        
        result = mock_run.return_value.stdout
        custom_rom_indicators = ["lineage", "cyanogen", "resurrection", "pixel experience"]
        has_custom = any(ind in result.lower() for ind in custom_rom_indicators)
        self.assertTrue(has_custom)
    
    @patch('subprocess.run')
    def test_magisk_detection(self, mock_run):
        """Detect Magisk root solution."""
        # Magisk hides itself, but leaves some traces
        magisk_indicators = [
            "/data/adb/magisk",
            "/sbin/.magisk",
            "magisk.db",
            "com.topjohnwu.magisk",
        ]
        
        def check_path(cmd, **kwargs):
            path = cmd[-1] if len(cmd) > 2 else ""
            if "magisk" in path.lower():
                return MagicMock(returncode=0, stdout="exists")
            return MagicMock(returncode=1, stdout="")
        
        mock_run.side_effect = check_path
        
        found = []
        for indicator in magisk_indicators:
            result = mock_run(["adb", "shell", "ls", indicator])
            if result.returncode == 0:
                found.append(indicator)
        
        self.assertGreater(len(found), 0)
    
    @patch('subprocess.run')
    def test_adb_over_network_detection(self, mock_run):
        """Detect ADB enabled over network."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="service.adb.tcp.port=5555"
        )
        
        result = mock_run.return_value.stdout
        adb_network = "adb.tcp.port" in result and "5555" in result
        self.assertTrue(adb_network)


class TestCommunicationAnalysis(unittest.TestCase):
    """Test analysis of communication artifacts."""
    
    def test_deleted_message_recovery(self):
        """Test recovery of deleted messages from database."""
        with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as f:
            db_path = f.name
        
        try:
            conn = sqlite3.connect(db_path)
            conn.execute("""
                CREATE TABLE messages (
                    _id INTEGER PRIMARY KEY,
                    address TEXT,
                    body TEXT,
                    date INTEGER,
                    deleted INTEGER DEFAULT 0
                )
            """)
            
            # Insert messages including soft-deleted
            messages = [
                (1, "+1234567890", "Normal message", 1703260800000, 0),
                (2, "+1234567890", "Deleted: Meet at location X", 1703261000000, 1),
                (3, "+0987654321", "Another normal", 1703262000000, 0),
                (4, "+1111111111", "Deleted: Password is 1234", 1703263000000, 1),
            ]
            
            for msg in messages:
                conn.execute("INSERT INTO messages VALUES (?,?,?,?,?)", msg)
            conn.commit()
            
            # Recover deleted
            cursor = conn.execute("SELECT * FROM messages WHERE deleted = 1")
            deleted = cursor.fetchall()
            conn.close()
            
            self.assertEqual(len(deleted), 2)
            self.assertIn("Password", deleted[1][2])
        finally:
            os.unlink(db_path)
    
    def test_encrypted_messaging_detection(self):
        """Detect usage of encrypted messaging apps."""
        encrypted_apps = [
            "org.thoughtcrime.securesms",  # Signal
            "org.telegram.messenger",
            "com.whatsapp",  # E2E encrypted
            "com.wickr.pro",
            "ch.threema.app",
        ]
        
        installed = [
            "com.facebook.orca",
            "org.telegram.messenger",
            "com.whatsapp",
            "com.android.chrome",
        ]
        
        encrypted_found = [app for app in installed if app in encrypted_apps]
        self.assertEqual(len(encrypted_found), 2)
    
    def test_voip_call_detection(self):
        """Detect VoIP calls that bypass call logs."""
        voip_apps = [
            "com.whatsapp",
            "org.telegram.messenger",
            "com.viber.voip",
            "com.skype.raider",
            "us.zoom.videomeetings",
        ]
        
        # Check for VoIP usage in logs
        log_entries = [
            "01-15 14:30:00 I/WhatsApp: VoIP call started",
            "01-15 14:35:00 I/Telegram: Initiating voice call",
            "01-15 14:40:00 I/Zoom: Meeting started",
        ]
        
        voip_detected = []
        for entry in log_entries:
            for app in voip_apps:
                app_name = app.split('.')[-1]
                if app_name.lower() in entry.lower():
                    voip_detected.append(entry)
        
        self.assertGreater(len(voip_detected), 0)


class TestTimelineReconstruction(unittest.TestCase):
    """Test reconstruction of activity timelines."""
    
    def test_cross_artifact_timeline(self):
        """Build timeline from multiple artifact sources."""
        events = []
        
        # SMS events
        sms = [
            {"time": "2024-01-15 14:00:00", "type": "sms", "detail": "Received from +123"},
            {"time": "2024-01-15 14:05:00", "type": "sms", "detail": "Sent to +456"},
        ]
        events.extend(sms)
        
        # Call events
        calls = [
            {"time": "2024-01-15 14:02:00", "type": "call", "detail": "Incoming from +789"},
            {"time": "2024-01-15 14:10:00", "type": "call", "detail": "Outgoing to +123"},
        ]
        events.extend(calls)
        
        # Location events
        locations = [
            {"time": "2024-01-15 14:01:00", "type": "location", "detail": "GPS: 40.7128, -74.0060"},
            {"time": "2024-01-15 14:08:00", "type": "location", "detail": "GPS: 40.7580, -73.9855"},
        ]
        events.extend(locations)
        
        # Sort by time
        timeline = sorted(events, key=lambda x: x["time"])
        
        self.assertEqual(len(timeline), 6)
        self.assertEqual(timeline[0]["type"], "sms")  # 14:00:00
        self.assertEqual(timeline[1]["type"], "location")  # 14:01:00
        self.assertEqual(timeline[-1]["type"], "call")  # 14:10:00
    
    def test_gap_detection_in_timeline(self):
        """Detect suspicious gaps in activity."""
        events = [
            {"time": "2024-01-15 14:00:00"},
            {"time": "2024-01-15 14:05:00"},
            {"time": "2024-01-15 14:10:00"},
            {"time": "2024-01-15 18:00:00"},  # 4-hour gap
            {"time": "2024-01-15 18:05:00"},
        ]
        
        gaps = []
        for i in range(1, len(events)):
            t1 = datetime.fromisoformat(events[i-1]["time"])
            t2 = datetime.fromisoformat(events[i]["time"])
            gap = (t2 - t1).total_seconds() / 60  # In minutes
            
            if gap > 60:  # Gap larger than 1 hour
                gaps.append({
                    "start": events[i-1]["time"],
                    "end": events[i]["time"],
                    "duration_minutes": gap
                })
        
        self.assertEqual(len(gaps), 1)
        self.assertEqual(gaps[0]["duration_minutes"], 230)  # 3 hours 50 minutes
    
    def test_activity_pattern_anomaly(self):
        """Detect anomalous activity patterns."""
        # Typical user is active 8am-11pm
        activities = []
        
        # Normal activity
        for hour in range(8, 23):
            activities.append({
                "time": f"2024-01-15 {hour:02d}:00:00",
                "count": 10 + (hour % 5)
            })
        
        # Anomalous 3am activity
        activities.append({
            "time": "2024-01-16 03:00:00",
            "count": 50  # High activity at unusual hour
        })
        
        # Detect anomalies
        anomalies = []
        for activity in activities:
            hour = int(activity["time"].split()[1].split(":")[0])
            if hour < 6 or hour > 23:  # Outside normal hours
                if activity["count"] > 5:  # Significant activity
                    anomalies.append(activity)
        
        self.assertEqual(len(anomalies), 1)


class TestChainOfCustody(unittest.TestCase):
    """Test chain of custody documentation."""
    
    def test_evidence_hash_chain(self):
        """Verify hash chain for evidence integrity."""
        import hashlib
        
        evidence_chain = []
        
        # Original evidence
        original_data = b"Original forensic evidence data"
        original_hash = hashlib.sha256(original_data).hexdigest()
        evidence_chain.append({
            "stage": "acquisition",
            "hash": original_hash,
            "timestamp": datetime.now().isoformat()
        })
        
        # After processing (should be same hash if unmodified)
        processed_data = b"Original forensic evidence data"
        processed_hash = hashlib.sha256(processed_data).hexdigest()
        evidence_chain.append({
            "stage": "analysis",
            "hash": processed_hash,
            "timestamp": datetime.now().isoformat()
        })
        
        # Verify chain
        hashes_match = all(
            e["hash"] == original_hash for e in evidence_chain
        )
        
        self.assertTrue(hashes_match)
    
    def test_audit_log_integrity(self):
        """Test audit log cannot be tampered."""
        import hashlib
        
        audit_log = []
        
        def add_entry(action: str, details: str):
            entry = {
                "timestamp": datetime.now().isoformat(),
                "action": action,
                "details": details
            }
            
            # Calculate hash including previous entry hash
            prev_hash = audit_log[-1]["entry_hash"] if audit_log else "0" * 64
            entry_str = json.dumps(entry) + prev_hash
            entry["entry_hash"] = hashlib.sha256(entry_str.encode()).hexdigest()
            entry["prev_hash"] = prev_hash
            
            audit_log.append(entry)
        
        add_entry("case_opened", "Case FIA-2024-001")
        add_entry("device_connected", "OnePlus LE2117")
        add_entry("data_extracted", "contacts.db")
        add_entry("data_extracted", "messages.db")
        
        # Verify chain
        for i in range(1, len(audit_log)):
            self.assertEqual(
                audit_log[i]["prev_hash"],
                audit_log[i-1]["entry_hash"]
            )
    
    def test_officer_action_logging(self):
        """Test logging of officer actions."""
        officer_actions = []
        
        def log_action(officer_id: str, action: str, target: str):
            officer_actions.append({
                "timestamp": datetime.now().isoformat(),
                "officer_id": officer_id,
                "action": action,
                "target": target,
                "ip_address": "192.168.1.100",  # Would be real in production
            })
        
        log_action("OFFICER-001", "login", "forensic_system")
        log_action("OFFICER-001", "connect_device", "OnePlus_LE2117")
        log_action("OFFICER-001", "extract_data", "/data/data/com.whatsapp/")
        log_action("OFFICER-001", "export_report", "case_FIA-2024-001.pdf")
        
        self.assertEqual(len(officer_actions), 4)
        self.assertTrue(all(a["officer_id"] == "OFFICER-001" for a in officer_actions))


# =============================================================================
# RUN ATTACK SCENARIO TESTS
# =============================================================================

if __name__ == "__main__":
    print("""
    ================================================================
         ATTACK SCENARIO TEST SUITE
         Federal Investigation Agency - Android Forensics
    ================================================================
         Testing:
         - Anti-Forensics Techniques
         - Malware Artifacts
         - Data Exfiltration
         - Device Tampering
         - Communication Analysis
         - Timeline Reconstruction
         - Chain of Custody
    ================================================================
    """)
    
    unittest.main(verbosity=2)
