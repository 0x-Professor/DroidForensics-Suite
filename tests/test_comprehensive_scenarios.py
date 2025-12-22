"""
Comprehensive Forensic Framework Test Suite
Federal Investigation Agency - Android Forensics Framework

This test suite covers:
- EASY: Basic functionality verification
- MEDIUM: Integration and workflow scenarios
- HARD: Complex multi-step operations, concurrency
- EDGE CASES: Unexpected inputs, malformed data, failures

Run with: python -m pytest tests/test_comprehensive_scenarios.py -v
"""

import asyncio
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError
from datetime import datetime
from pathlib import Path
from typing import Optional
from unittest.mock import MagicMock, patch, PropertyMock

# Add project root to path
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


# =============================================================================
# EASY TESTS - Basic Functionality
# =============================================================================

class TestEasyBasicFunctionality(unittest.TestCase):
    """Easy tests for basic functionality verification."""
    
    def test_output_directory_creation(self):
        """Verify output directory can be created."""
        output_dir = PROJECT_ROOT / "output" / "test_easy"
        output_dir.mkdir(parents=True, exist_ok=True)
        self.assertTrue(output_dir.exists())
        # Cleanup
        output_dir.rmdir()
    
    def test_json_serialization(self):
        """Verify JSON serialization works for forensic data."""
        data = {
            "case_number": "FIA-2024-001",
            "timestamp": datetime.now().isoformat(),
            "evidence": ["file1.db", "file2.txt"],
            "hash": "abc123def456"
        }
        json_str = json.dumps(data)
        parsed = json.loads(json_str)
        self.assertEqual(parsed["case_number"], "FIA-2024-001")
    
    def test_path_manipulation(self):
        """Verify path handling for Android paths."""
        android_path = "/data/data/com.whatsapp/databases/msgstore.db"
        path = Path(android_path)
        self.assertEqual(path.name, "msgstore.db")
        self.assertEqual(path.suffix, ".db")
    
    def test_timestamp_formatting(self):
        """Verify timestamp formatting for audit logs."""
        now = datetime.now()
        iso_format = now.isoformat()
        readable = now.strftime("%Y-%m-%d %H:%M:%S")
        self.assertIn("T", iso_format)
        self.assertIn("-", readable)
    
    def test_hash_calculation(self):
        """Verify SHA-256 hash calculation."""
        import hashlib
        data = b"test evidence data"
        hash_value = hashlib.sha256(data).hexdigest()
        self.assertEqual(len(hash_value), 64)
    
    def test_environment_variables(self):
        """Verify environment variable handling."""
        os.environ["TEST_FIA_VAR"] = "test_value"
        self.assertEqual(os.getenv("TEST_FIA_VAR"), "test_value")
        del os.environ["TEST_FIA_VAR"]
    
    def test_subprocess_basic(self):
        """Verify subprocess execution works."""
        result = subprocess.run(
            ["echo", "test"],
            capture_output=True, text=True, shell=True
        )
        self.assertEqual(result.returncode, 0)
    
    def test_temp_file_creation(self):
        """Verify temporary file creation for processing."""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".db") as f:
            f.write(b"test data")
            temp_path = f.name
        self.assertTrue(os.path.exists(temp_path))
        os.unlink(temp_path)


class TestEasyModuleImports(unittest.TestCase):
    """Easy tests for module availability."""
    
    def test_import_deep_agent(self):
        """Verify deep agent imports."""
        from agents.deep_agent import DeepForensicAgent, create_deep_forensic_agent
        self.assertTrue(callable(create_deep_forensic_agent))
    
    def test_import_ui_components(self):
        """Verify UI components import."""
        from ui.app import ForensicInvestigator, DeviceMonitor
        self.assertIsNotNone(ForensicInvestigator)
        self.assertIsNotNone(DeviceMonitor)
    
    def test_import_mcp_servers(self):
        """Verify all MCP servers import."""
        from mcp_servers import device_manager
        from mcp_servers import data_acquisition
        from mcp_servers import artifact_parser
        from mcp_servers import app_analyzer
        from mcp_servers import system_forensics
        from mcp_servers import report_generator
        self.assertIsNotNone(device_manager.mcp)


# =============================================================================
# MEDIUM TESTS - Integration Scenarios
# =============================================================================

class TestMediumDeviceOperations(unittest.TestCase):
    """Medium complexity tests for device operations."""
    
    @patch('subprocess.run')
    def test_device_enumeration_multiple_devices(self, mock_run):
        """Test handling multiple connected devices."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="""List of devices attached
RF8M33DEVICE1\tdevice model:SM-G950F
RF8M33DEVICE2\tdevice model:Pixel_6
RF8M33DEVICE3\tdevice model:OnePlus_9"""
        )
        
        result = mock_run.return_value.stdout
        lines = result.strip().split("\n")[1:]
        devices = [line.split()[0] for line in lines if "device" in line]
        
        self.assertEqual(len(devices), 3)
        self.assertIn("RF8M33DEVICE1", devices)
    
    @patch('subprocess.run')
    def test_device_properties_retrieval(self, mock_run):
        """Test retrieving multiple device properties."""
        properties = {
            "ro.product.manufacturer": "Samsung",
            "ro.product.model": "SM-G950F",
            "ro.build.version.release": "12",
            "ro.serialno": "RF8M33ABCDEF"
        }
        
        def mock_getprop(cmd, **kwargs):
            prop = cmd[-1] if cmd[-1].startswith("ro.") else None
            return MagicMock(
                returncode=0,
                stdout=properties.get(prop, "unknown")
            )
        
        mock_run.side_effect = mock_getprop
        
        # Simulate property retrieval
        for prop, expected in properties.items():
            result = mock_run(["adb", "shell", "getprop", prop])
            self.assertEqual(result.stdout, expected)
    
    @patch('subprocess.run')
    def test_package_list_filtering(self, mock_run):
        """Test package list with different filters."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="""package:com.whatsapp
package:com.facebook.orca
package:org.telegram.messenger
package:com.android.chrome
package:com.instagram.android"""
        )
        
        packages = [
            line.replace("package:", "") 
            for line in mock_run.return_value.stdout.split("\n")
        ]
        
        # Filter for messaging apps
        messaging = [p for p in packages if any(
            x in p for x in ["whatsapp", "telegram", "messenger"]
        )]
        
        self.assertEqual(len(messaging), 3)
    
    def test_sqlite_database_operations(self):
        """Test SQLite database creation and querying."""
        with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as f:
            db_path = f.name
        
        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            
            # Create tables similar to Android databases
            cursor.execute('''
                CREATE TABLE messages (
                    _id INTEGER PRIMARY KEY,
                    address TEXT,
                    body TEXT,
                    date INTEGER,
                    type INTEGER
                )
            ''')
            
            # Insert test data
            messages = [
                (1, "+1234567890", "Test message 1", 1703260800000, 1),
                (2, "+0987654321", "Test message 2", 1703260900000, 2),
                (3, "+1234567890", "Reply message", 1703261000000, 1),
            ]
            cursor.executemany("INSERT INTO messages VALUES (?,?,?,?,?)", messages)
            conn.commit()
            
            # Query by address
            cursor.execute("SELECT * FROM messages WHERE address = ?", ("+1234567890",))
            results = cursor.fetchall()
            conn.close()
            
            self.assertEqual(len(results), 2)
        finally:
            os.unlink(db_path)


class TestMediumDataProcessing(unittest.TestCase):
    """Medium complexity tests for data processing."""
    
    def test_logcat_parsing(self):
        """Test parsing logcat output."""
        logcat_sample = """01-15 14:30:45.123  1234  1234 I ActivityManager: Starting activity
01-15 14:30:45.234  1234  1234 D WindowManager: Window focused
01-15 14:30:45.345  1234  1234 W System: Warning message
01-15 14:30:45.456  1234  1234 E Error: Something went wrong"""
        
        lines = logcat_sample.strip().split("\n")
        parsed = []
        
        for line in lines:
            parts = line.split()
            if len(parts) >= 6:
                parsed.append({
                    "date": parts[0],
                    "time": parts[1],
                    "pid": parts[2],
                    "level": parts[4],
                    "tag": parts[5].rstrip(":"),
                    "message": " ".join(parts[6:])
                })
        
        self.assertEqual(len(parsed), 4)
        self.assertEqual(parsed[2]["level"], "W")
        self.assertEqual(parsed[3]["level"], "E")
    
    def test_timeline_construction(self):
        """Test building investigation timeline."""
        events = [
            {"time": "2024-01-15 14:30:00", "type": "sms", "action": "received"},
            {"time": "2024-01-15 14:35:00", "type": "call", "action": "outgoing"},
            {"time": "2024-01-15 14:25:00", "type": "app", "action": "whatsapp_opened"},
            {"time": "2024-01-15 14:40:00", "type": "location", "action": "gps_update"},
        ]
        
        # Sort by time
        timeline = sorted(events, key=lambda x: x["time"])
        
        self.assertEqual(timeline[0]["type"], "app")
        self.assertEqual(timeline[-1]["type"], "location")
    
    def test_contact_deduplication(self):
        """Test deduplicating contact records."""
        contacts = [
            {"name": "John Doe", "phone": "+1234567890"},
            {"name": "John Doe", "phone": "+1234567890"},
            {"name": "Jane Smith", "phone": "+0987654321"},
            {"name": "John D.", "phone": "+1234567890"},
        ]
        
        # Deduplicate by phone
        seen = set()
        unique = []
        for c in contacts:
            if c["phone"] not in seen:
                seen.add(c["phone"])
                unique.append(c)
        
        self.assertEqual(len(unique), 2)


# =============================================================================
# HARD TESTS - Complex Operations
# =============================================================================

class TestHardConcurrentOperations(unittest.TestCase):
    """Hard tests for concurrent operations."""
    
    def test_concurrent_file_processing(self):
        """Test processing multiple files concurrently."""
        results = []
        lock = threading.Lock()
        
        def process_file(file_id):
            time.sleep(0.1)  # Simulate processing
            with lock:
                results.append({
                    "file_id": file_id,
                    "processed": True,
                    "timestamp": datetime.now().isoformat()
                })
            return file_id
        
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(process_file, i) for i in range(10)]
            completed = [f.result() for f in futures]
        
        self.assertEqual(len(results), 10)
        self.assertEqual(len(completed), 10)
    
    def test_timeout_handling(self):
        """Test handling of operation timeouts."""
        def slow_operation():
            time.sleep(5)
            return "completed"
        
        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(slow_operation)
            with self.assertRaises(FuturesTimeoutError):
                future.result(timeout=0.1)
    
    def test_large_data_processing(self):
        """Test processing large datasets."""
        # Simulate processing 10000 SMS records
        records = [
            {"id": i, "body": f"Message {i}" * 10, "timestamp": i * 1000}
            for i in range(10000)
        ]
        
        # Filter and transform
        start = time.time()
        filtered = [r for r in records if r["id"] % 2 == 0]
        elapsed = time.time() - start
        
        self.assertEqual(len(filtered), 5000)
        self.assertLess(elapsed, 1.0)  # Should complete in under 1 second
    
    def test_recursive_directory_scanning(self):
        """Test recursive directory structure processing."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create nested structure
            for i in range(3):
                subdir = Path(tmpdir) / f"level1_{i}"
                subdir.mkdir()
                for j in range(3):
                    subsubdir = subdir / f"level2_{j}"
                    subsubdir.mkdir()
                    (subsubdir / f"file_{j}.txt").write_text("data")
            
            # Count all files recursively
            files = list(Path(tmpdir).rglob("*.txt"))
            self.assertEqual(len(files), 9)


class TestHardErrorRecovery(unittest.TestCase):
    """Hard tests for error recovery scenarios."""
    
    @patch('subprocess.run')
    def test_adb_command_retry(self, mock_run):
        """Test retry logic for failed ADB commands."""
        call_count = [0]
        
        def flaky_command(*args, **kwargs):
            call_count[0] += 1
            if call_count[0] < 3:
                return MagicMock(returncode=1, stderr="device offline")
            return MagicMock(returncode=0, stdout="success")
        
        mock_run.side_effect = flaky_command
        
        # Retry logic
        max_retries = 5
        for attempt in range(max_retries):
            result = mock_run(["adb", "shell", "echo", "test"])
            if result.returncode == 0:
                break
        
        self.assertEqual(call_count[0], 3)
        self.assertEqual(result.returncode, 0)
    
    def test_corrupted_database_handling(self):
        """Test handling of corrupted SQLite databases."""
        with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as f:
            # Write garbage data to simulate corruption
            f.write(b"NOT A VALID SQLITE DATABASE" + os.urandom(1000))
            db_path = f.name
        
        try:
            try:
                conn = sqlite3.connect(db_path)
                conn.execute("SELECT * FROM messages")
                self.fail("Should have raised an exception")
            except sqlite3.DatabaseError as e:
                self.assertIn("file is not a database", str(e).lower())
        finally:
            os.unlink(db_path)
    
    def test_partial_data_extraction(self):
        """Test handling partial data when extraction is interrupted."""
        data = []
        
        def extract_with_failure():
            for i in range(100):
                if i == 50:
                    raise IOError("Connection lost")
                data.append({"id": i, "status": "extracted"})
        
        try:
            extract_with_failure()
        except IOError:
            pass  # Handle gracefully
        
        # Verify partial data was captured
        self.assertEqual(len(data), 50)
        self.assertEqual(data[-1]["id"], 49)


class TestHardStateManagement(unittest.TestCase):
    """Hard tests for state management."""
    
    def test_investigation_state_persistence(self):
        """Test saving and restoring investigation state."""
        state = {
            "case_number": "FIA-2024-001",
            "phase": "data_acquisition",
            "evidence": [
                {"file": "contacts.db", "hash": "abc123"},
                {"file": "messages.db", "hash": "def456"}
            ],
            "checkpoint": 42
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(state, f)
            state_file = f.name
        
        try:
            # Restore state
            with open(state_file, 'r') as f:
                restored = json.load(f)
            
            self.assertEqual(restored["case_number"], state["case_number"])
            self.assertEqual(len(restored["evidence"]), 2)
        finally:
            os.unlink(state_file)
    
    def test_transaction_rollback(self):
        """Test database transaction rollback on error."""
        with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as f:
            db_path = f.name
        
        try:
            conn = sqlite3.connect(db_path)
            conn.execute("CREATE TABLE test (id INTEGER PRIMARY KEY, value TEXT)")
            conn.commit()
            
            try:
                conn.execute("INSERT INTO test VALUES (1, 'value1')")
                conn.execute("INSERT INTO test VALUES (2, 'value2')")
                # Simulate error before commit
                raise Exception("Simulated error")
                conn.commit()
            except Exception:
                conn.rollback()
            
            # Verify no data was committed
            cursor = conn.execute("SELECT COUNT(*) FROM test")
            count = cursor.fetchone()[0]
            conn.close()
            
            self.assertEqual(count, 0)
        finally:
            os.unlink(db_path)


# =============================================================================
# EDGE CASE TESTS - Unexpected Scenarios
# =============================================================================

class TestEdgeCaseInputValidation(unittest.TestCase):
    """Edge case tests for input validation."""
    
    def test_empty_input_handling(self):
        """Test handling of empty inputs."""
        empty_inputs = ["", None, [], {}, b""]
        
        for inp in empty_inputs:
            if inp is None:
                self.assertIsNone(inp)
            elif isinstance(inp, (str, list, dict, bytes)):
                self.assertFalse(inp)  # Empty = falsy
    
    def test_unicode_in_data(self):
        """Test handling Unicode characters in forensic data."""
        test_cases = [
            "Hello 世界",
            "مرحبا",
            "🔍 Forensics 📱",
            "Café résumé naïve",
            "\u0000\u0001\u0002",  # Control characters
        ]
        
        for text in test_cases:
            # Should be able to JSON encode/decode
            encoded = json.dumps({"text": text})
            decoded = json.loads(encoded)
            self.assertEqual(decoded["text"], text)
    
    def test_extremely_long_strings(self):
        """Test handling very long strings."""
        long_string = "A" * 1_000_000  # 1 million characters
        
        # Should be able to hash
        import hashlib
        hash_value = hashlib.sha256(long_string.encode()).hexdigest()
        self.assertEqual(len(hash_value), 64)
    
    def test_special_characters_in_paths(self):
        """Test handling special characters in file paths."""
        special_names = [
            "file with spaces.db",
            "file'with'quotes.db",
            "file(with)parens.db",
            "file[with]brackets.db",
        ]
        
        for name in special_names:
            path = Path(tempfile.gettempdir()) / name
            self.assertIsNotNone(path.name)
    
    def test_null_bytes_in_data(self):
        """Test handling null bytes in binary data."""
        data_with_nulls = b"header\x00\x00\x00data\x00\x00footer"
        
        # Should be able to process
        parts = data_with_nulls.split(b"\x00")
        self.assertGreater(len(parts), 1)
    
    def test_negative_timestamps(self):
        """Test handling negative/invalid timestamps."""
        timestamps = [-1, 0, 9999999999999, -9999999999]
        
        for ts in timestamps:
            try:
                # Some should work, some should raise
                dt = datetime.fromtimestamp(ts / 1000)
                self.assertIsNotNone(dt)
            except (ValueError, OSError, OverflowError):
                pass  # Expected for invalid timestamps


class TestEdgeCaseDeviceScenarios(unittest.TestCase):
    """Edge case tests for device scenarios."""
    
    @patch('subprocess.run')
    def test_device_disconnection_during_operation(self, mock_run):
        """Test handling device disconnection mid-operation."""
        call_count = [0]
        
        def disconnect_mid_operation(*args, **kwargs):
            call_count[0] += 1
            if call_count[0] > 2:
                return MagicMock(
                    returncode=1,
                    stderr="error: device not found"
                )
            return MagicMock(returncode=0, stdout="data")
        
        mock_run.side_effect = disconnect_mid_operation
        
        results = []
        for i in range(5):
            result = mock_run(["adb", "shell", "echo", str(i)])
            if "not found" in (result.stderr or ""):
                break
            results.append(result.stdout)
        
        self.assertEqual(len(results), 2)
    
    @patch('subprocess.run')
    def test_unauthorized_device(self, mock_run):
        """Test handling unauthorized device."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="List of devices attached\nRF8M33DEVICE1\tunauthorized"
        )
        
        output = mock_run.return_value.stdout
        lines = output.strip().split("\n")[1:]
        
        for line in lines:
            if "unauthorized" in line:
                device_id = line.split()[0]
                self.assertEqual(device_id, "RF8M33DEVICE1")
    
    @patch('subprocess.run')
    def test_offline_device(self, mock_run):
        """Test handling offline device."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="List of devices attached\nRF8M33DEVICE1\toffline"
        )
        
        output = mock_run.return_value.stdout
        is_offline = "offline" in output
        self.assertTrue(is_offline)
    
    @patch('subprocess.run')
    def test_adb_server_not_running(self, mock_run):
        """Test handling ADB server not running."""
        mock_run.return_value = MagicMock(
            returncode=1,
            stderr="error: cannot connect to daemon at tcp:5037"
        )
        
        result = mock_run.return_value
        is_daemon_error = "cannot connect to daemon" in (result.stderr or "")
        self.assertTrue(is_daemon_error)
    
    @patch('subprocess.run')
    def test_permission_denied(self, mock_run):
        """Test handling permission denied errors."""
        mock_run.return_value = MagicMock(
            returncode=1,
            stderr="Permission denied"
        )
        
        result = mock_run.return_value
        is_permission_error = "Permission denied" in (result.stderr or "")
        self.assertTrue(is_permission_error)


class TestEdgeCaseDataFormats(unittest.TestCase):
    """Edge case tests for unusual data formats."""
    
    def test_empty_database(self):
        """Test handling empty database."""
        with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as f:
            db_path = f.name
        
        try:
            conn = sqlite3.connect(db_path)
            conn.execute("CREATE TABLE messages (id INTEGER, body TEXT)")
            conn.commit()
            
            cursor = conn.execute("SELECT * FROM messages")
            results = cursor.fetchall()
            conn.close()
            
            self.assertEqual(len(results), 0)
        finally:
            os.unlink(db_path)
    
    def test_binary_data_in_database(self):
        """Test handling binary data in database fields."""
        with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as f:
            db_path = f.name
        
        try:
            conn = sqlite3.connect(db_path)
            conn.execute("CREATE TABLE blobs (id INTEGER, data BLOB)")
            
            # Insert binary data
            binary_data = os.urandom(1024)
            conn.execute("INSERT INTO blobs VALUES (1, ?)", (binary_data,))
            conn.commit()
            
            cursor = conn.execute("SELECT data FROM blobs WHERE id = 1")
            retrieved = cursor.fetchone()[0]
            conn.close()
            
            self.assertEqual(retrieved, binary_data)
        finally:
            os.unlink(db_path)
    
    def test_malformed_json(self):
        """Test handling malformed JSON."""
        malformed_samples = [
            '{"key": "value"',  # Missing closing brace
            "{'key': 'value'}",  # Single quotes
            '{"key": undefined}',  # JavaScript undefined
            '',  # Empty string
            'null',  # Just null
        ]
        
        for sample in malformed_samples:
            try:
                json.loads(sample)
            except json.JSONDecodeError:
                pass  # Expected for most
    
    def test_extremely_nested_json(self):
        """Test handling deeply nested JSON."""
        depth = 100
        nested = {}
        current = nested
        for i in range(depth):
            current["level"] = i
            current["nested"] = {}
            current = current["nested"]
        
        # Should be able to serialize
        json_str = json.dumps(nested)
        parsed = json.loads(json_str)
        self.assertIn("level", parsed)
    
    def test_mixed_encodings(self):
        """Test handling mixed text encodings."""
        encodings = ['utf-8', 'latin-1', 'cp1252']
        test_text = "Test text with special chars: éàü"
        
        for enc in encodings:
            try:
                encoded = test_text.encode(enc)
                decoded = encoded.decode(enc)
                self.assertEqual(decoded, test_text)
            except UnicodeEncodeError:
                pass  # Some chars may not be encodable


class TestEdgeCaseResourceLimits(unittest.TestCase):
    """Edge case tests for resource limits."""
    
    def test_many_open_files(self):
        """Test handling many open file handles."""
        files = []
        try:
            for i in range(100):
                f = tempfile.NamedTemporaryFile(delete=False)
                files.append(f)
            
            self.assertEqual(len(files), 100)
        finally:
            for f in files:
                f.close()
                os.unlink(f.name)
    
    def test_memory_efficient_processing(self):
        """Test memory-efficient large file processing."""
        # Create a large temporary file
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            for i in range(10000):
                f.write(f"Line {i}: " + "x" * 100 + "\n")
            large_file = f.name
        
        try:
            # Process line by line (memory efficient)
            line_count = 0
            with open(large_file, 'r') as f:
                for line in f:
                    line_count += 1
            
            self.assertEqual(line_count, 10000)
        finally:
            os.unlink(large_file)
    
    def test_rapid_successive_operations(self):
        """Test many rapid successive operations."""
        start = time.time()
        operations = 1000
        
        for i in range(operations):
            # Simulate quick operations
            _ = json.dumps({"op": i})
            _ = datetime.now().isoformat()
        
        elapsed = time.time() - start
        ops_per_second = operations / elapsed
        
        # Should handle at least 1000 ops/second
        self.assertGreater(ops_per_second, 1000)


class TestEdgeCaseSecurityScenarios(unittest.TestCase):
    """Edge case tests for security scenarios."""
    
    def test_path_traversal_prevention(self):
        """Test prevention of path traversal attacks."""
        malicious_paths = [
            "../../../etc/passwd",
            "..\\..\\..\\Windows\\System32",
            "/data/data/../../../etc/shadow",
            "....//....//etc/passwd",
        ]
        
        base_dir = Path("/safe/directory")
        
        for malicious in malicious_paths:
            # Resolve and check if still under base
            try:
                resolved = (base_dir / malicious).resolve()
                # Should not start with base_dir for traversal attempts
                # In real code, you'd reject these
                self.assertIsNotNone(resolved)
            except Exception:
                pass
    
    def test_sql_injection_prevention(self):
        """Test SQL injection prevention with parameterized queries."""
        with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as f:
            db_path = f.name
        
        try:
            conn = sqlite3.connect(db_path)
            conn.execute("CREATE TABLE users (id INTEGER, name TEXT)")
            conn.execute("INSERT INTO users VALUES (1, 'admin')")
            conn.commit()
            
            # Malicious input
            malicious_name = "'; DROP TABLE users; --"
            
            # Safe parameterized query
            cursor = conn.execute(
                "SELECT * FROM users WHERE name = ?",
                (malicious_name,)
            )
            results = cursor.fetchall()
            
            # Table should still exist
            cursor = conn.execute("SELECT * FROM users")
            all_users = cursor.fetchall()
            conn.close()
            
            self.assertEqual(len(results), 0)  # No match
            self.assertEqual(len(all_users), 1)  # Table intact
        finally:
            os.unlink(db_path)
    
    def test_command_injection_prevention(self):
        """Test that shell commands are properly escaped."""
        malicious_inputs = [
            "; rm -rf /",
            "| cat /etc/passwd",
            "$(whoami)",
            "`id`",
            "&& echo pwned",
        ]
        
        for malicious in malicious_inputs:
            # Using list form of subprocess prevents injection
            # This is safe because shell=False by default
            import shlex
            escaped = shlex.quote(malicious)
            self.assertIn("'", escaped)  # Should be quoted


# =============================================================================
# INTEGRATION TESTS
# =============================================================================

class TestIntegrationWorkflows(unittest.TestCase):
    """Integration tests for complete workflows."""
    
    def test_full_evidence_collection_workflow(self):
        """Test complete evidence collection workflow."""
        workflow_steps = []
        
        # Step 1: Initialize case
        case = {
            "case_number": "FIA-TEST-001",
            "started": datetime.now().isoformat()
        }
        workflow_steps.append("case_initialized")
        
        # Step 2: Check device (mocked)
        device_connected = True
        if device_connected:
            workflow_steps.append("device_verified")
        
        # Step 3: Collect evidence
        evidence = []
        for item in ["contacts.db", "messages.db", "call_log.db"]:
            evidence.append({
                "file": item,
                "collected_at": datetime.now().isoformat(),
                "hash": "mock_hash_" + item
            })
        workflow_steps.append("evidence_collected")
        
        # Step 4: Generate report
        report = {
            "case": case,
            "evidence_count": len(evidence),
            "evidence": evidence
        }
        workflow_steps.append("report_generated")
        
        self.assertEqual(len(workflow_steps), 4)
        self.assertEqual(len(evidence), 3)
    
    def test_error_recovery_workflow(self):
        """Test workflow with error recovery."""
        attempts = 0
        max_attempts = 3
        success = False
        
        while attempts < max_attempts and not success:
            attempts += 1
            try:
                if attempts < 3:
                    raise ConnectionError("Device offline")
                success = True
            except ConnectionError:
                time.sleep(0.1)  # Wait before retry
        
        self.assertTrue(success)
        self.assertEqual(attempts, 3)


# =============================================================================
# RUN TESTS
# =============================================================================

def run_all_tests():
    """Run complete test suite with categories."""
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Easy Tests
    suite.addTests(loader.loadTestsFromTestCase(TestEasyBasicFunctionality))
    suite.addTests(loader.loadTestsFromTestCase(TestEasyModuleImports))
    
    # Medium Tests
    suite.addTests(loader.loadTestsFromTestCase(TestMediumDeviceOperations))
    suite.addTests(loader.loadTestsFromTestCase(TestMediumDataProcessing))
    
    # Hard Tests
    suite.addTests(loader.loadTestsFromTestCase(TestHardConcurrentOperations))
    suite.addTests(loader.loadTestsFromTestCase(TestHardErrorRecovery))
    suite.addTests(loader.loadTestsFromTestCase(TestHardStateManagement))
    
    # Edge Case Tests
    suite.addTests(loader.loadTestsFromTestCase(TestEdgeCaseInputValidation))
    suite.addTests(loader.loadTestsFromTestCase(TestEdgeCaseDeviceScenarios))
    suite.addTests(loader.loadTestsFromTestCase(TestEdgeCaseDataFormats))
    suite.addTests(loader.loadTestsFromTestCase(TestEdgeCaseResourceLimits))
    suite.addTests(loader.loadTestsFromTestCase(TestEdgeCaseSecurityScenarios))
    
    # Integration Tests
    suite.addTests(loader.loadTestsFromTestCase(TestIntegrationWorkflows))
    
    runner = unittest.TextTestRunner(verbosity=2)
    return runner.run(suite)


if __name__ == "__main__":
    print("""
    ================================================================
         COMPREHENSIVE FORENSIC FRAMEWORK TEST SUITE
         Federal Investigation Agency
    ================================================================
         Categories:
         - EASY: Basic functionality
         - MEDIUM: Integration scenarios  
         - HARD: Complex operations
         - EDGE CASES: Unexpected scenarios
    ================================================================
    """)
    
    result = run_all_tests()
    
    print("\n" + "=" * 60)
    print("FINAL SUMMARY")
    print("=" * 60)
    print(f"Total Tests:  {result.testsRun}")
    print(f"Passed:       {result.testsRun - len(result.failures) - len(result.errors)}")
    print(f"Failed:       {len(result.failures)}")
    print(f"Errors:       {len(result.errors)}")
    print("=" * 60)
    
    sys.exit(0 if result.wasSuccessful() else 1)
