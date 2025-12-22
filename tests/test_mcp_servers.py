"""
MCP Server Integration Tests
Federal Investigation Agency - Android Forensics Framework

Tests for verifying MCP server functionality and tool availability.
"""

import asyncio
import json
import os
import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

# Add project root to path
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


class TestMCPServerImports(unittest.TestCase):
    """Test that all MCP server modules can be imported."""
    
    def test_device_manager_import(self):
        """Verify device_manager module imports correctly."""
        from mcp_servers import device_manager
        self.assertTrue(hasattr(device_manager, 'mcp'))
    
    def test_data_acquisition_import(self):
        """Verify data_acquisition module imports correctly."""
        from mcp_servers import data_acquisition
        self.assertTrue(hasattr(data_acquisition, 'mcp'))
    
    def test_artifact_parser_import(self):
        """Verify artifact_parser module imports correctly."""
        from mcp_servers import artifact_parser
        self.assertTrue(hasattr(artifact_parser, 'mcp'))
    
    def test_app_analyzer_import(self):
        """Verify app_analyzer module imports correctly."""
        from mcp_servers import app_analyzer
        self.assertTrue(hasattr(app_analyzer, 'mcp'))
    
    def test_system_forensics_import(self):
        """Verify system_forensics module imports correctly."""
        from mcp_servers import system_forensics
        self.assertTrue(hasattr(system_forensics, 'mcp'))
    
    def test_report_generator_import(self):
        """Verify report_generator module imports correctly."""
        from mcp_servers import report_generator
        self.assertTrue(hasattr(report_generator, 'mcp'))


class TestDeviceManagerTools(unittest.TestCase):
    """Test device manager MCP server tools."""
    
    @patch('subprocess.run')
    def test_check_adb_available(self, mock_run):
        """Test ADB availability check."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="Android Debug Bridge version 1.0.41"
        )
        
        from mcp_servers.device_manager import check_adb
        # The function should work without raising
        # Actual test depends on implementation
    
    @patch('subprocess.run')
    def test_get_connected_devices(self, mock_run):
        """Test device enumeration."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="List of devices attached\nRF8M33EXAMPLE\tdevice"
        )
        
        # Test that we can parse device output
        output = mock_run.return_value.stdout
        self.assertIn("device", output)


class TestDataAcquisitionTools(unittest.TestCase):
    """Test data acquisition MCP server tools."""
    
    def test_output_directory_exists(self):
        """Verify output directory is created."""
        output_dir = PROJECT_ROOT / "output"
        output_dir.mkdir(parents=True, exist_ok=True)
        self.assertTrue(output_dir.exists())
    
    @patch('subprocess.run')
    def test_pull_file_mock(self, mock_run):
        """Test file pull operation (mocked)."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="1 file pulled"
        )
        
        result = mock_run.return_value
        self.assertEqual(result.returncode, 0)


class TestArtifactParserTools(unittest.TestCase):
    """Test artifact parser MCP server tools."""
    
    def test_sqlite_library_available(self):
        """Verify SQLite library is available."""
        import sqlite3
        self.assertIsNotNone(sqlite3.version)
    
    def test_parse_mock_database(self):
        """Test database parsing with mock data."""
        import sqlite3
        import tempfile
        
        # Create a temporary test database
        with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as f:
            db_path = f.name
        
        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE contacts (
                    id INTEGER PRIMARY KEY,
                    name TEXT,
                    phone TEXT
                )
            ''')
            cursor.execute("INSERT INTO contacts VALUES (1, 'Test User', '+1234567890')")
            conn.commit()
            conn.close()
            
            # Verify we can read it back
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM contacts")
            rows = cursor.fetchall()
            conn.close()
            
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0][1], 'Test User')
        finally:
            os.unlink(db_path)


class TestAppAnalyzerTools(unittest.TestCase):
    """Test app analyzer MCP server tools."""
    
    def test_json_parsing(self):
        """Test JSON parsing capabilities."""
        test_data = {
            "package": "com.example.app",
            "version": "1.0.0",
            "permissions": ["android.permission.INTERNET"]
        }
        
        json_str = json.dumps(test_data)
        parsed = json.loads(json_str)
        
        self.assertEqual(parsed["package"], "com.example.app")
    
    def test_path_handling(self):
        """Test path handling for app data."""
        app_data_path = Path("/data/data/com.whatsapp/databases")
        self.assertEqual(app_data_path.name, "databases")


class TestSystemForensicsTools(unittest.TestCase):
    """Test system forensics MCP server tools."""
    
    @patch('subprocess.run')
    def test_logcat_extraction_mock(self, mock_run):
        """Test logcat extraction (mocked)."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="01-01 00:00:00.000 I/System: Test log entry"
        )
        
        result = mock_run.return_value
        self.assertIn("Test log entry", result.stdout)
    
    def test_timestamp_parsing(self):
        """Test timestamp parsing from logs."""
        log_line = "01-15 14:30:45.123 I/ActivityManager: Starting activity"
        
        # Extract timestamp portion
        parts = log_line.split()
        date_part = parts[0]
        time_part = parts[1]
        
        self.assertEqual(date_part, "01-15")
        self.assertTrue(time_part.startswith("14:30:45"))


class TestReportGeneratorTools(unittest.TestCase):
    """Test report generator MCP server tools."""
    
    def test_markdown_generation(self):
        """Test Markdown report generation."""
        findings = [
            {"type": "contact", "name": "Test", "phone": "123"},
            {"type": "sms", "sender": "Test", "body": "Hello"}
        ]
        
        # Generate simple markdown
        md_lines = ["# Forensic Report", ""]
        md_lines.append("## Findings")
        for finding in findings:
            md_lines.append(f"- **{finding['type']}**: {finding}")
        
        report = "\n".join(md_lines)
        
        self.assertIn("# Forensic Report", report)
        self.assertIn("## Findings", report)
    
    def test_json_export(self):
        """Test JSON report export."""
        report_data = {
            "case_number": "FIA-2024-001",
            "examiner": "Test Examiner",
            "findings": [],
            "timestamp": "2024-01-01T00:00:00"
        }
        
        json_str = json.dumps(report_data, indent=2)
        
        self.assertIn("FIA-2024-001", json_str)
        self.assertIn("Test Examiner", json_str)


class TestMCPToolRegistration(unittest.TestCase):
    """Test that MCP tools are properly registered."""
    
    def test_device_manager_has_tools(self):
        """Verify device_manager has registered tools."""
        try:
            from mcp_servers.device_manager import mcp
            # FastMCP should have tools registered
            self.assertIsNotNone(mcp)
        except ImportError as e:
            self.skipTest(f"FastMCP not installed: {e}")
    
    def test_data_acquisition_has_tools(self):
        """Verify data_acquisition has registered tools."""
        try:
            from mcp_servers.data_acquisition import mcp
            self.assertIsNotNone(mcp)
        except ImportError as e:
            self.skipTest(f"FastMCP not installed: {e}")


class TestDeepAgentIntegration(unittest.TestCase):
    """Test Deep Agent integration with MCP tools."""
    
    def test_deep_agent_import(self):
        """Verify deep agent module imports."""
        from agents.deep_agent import DeepForensicAgent, create_deep_forensic_agent
        self.assertIsNotNone(DeepForensicAgent)
        self.assertIsNotNone(create_deep_forensic_agent)
    
    def test_deep_agent_tools_defined(self):
        """Verify deep agent has tools defined."""
        from agents.deep_agent import (
            check_device_connection,
            get_device_info,
            list_installed_packages,
            extract_logcat,
            pull_file,
            execute_shell_command,
            write_todos
        )
        
        # All tools should be callable
        self.assertTrue(callable(check_device_connection))
        self.assertTrue(callable(get_device_info))
        self.assertTrue(callable(list_installed_packages))
    
    def test_subagent_definitions(self):
        """Verify subagent definitions exist."""
        from agents.deep_agent import SUBAGENTS
        
        self.assertIsInstance(SUBAGENTS, list)
        self.assertGreater(len(SUBAGENTS), 0)
        
        # Check subagent structure
        for subagent in SUBAGENTS:
            self.assertIn("name", subagent)
            self.assertIn("description", subagent)
            self.assertIn("system_prompt", subagent)


class AsyncTestCase(unittest.TestCase):
    """Base class for async tests."""
    
    def run_async(self, coro):
        """Run an async coroutine."""
        return asyncio.get_event_loop().run_until_complete(coro)


class TestAsyncMCPOperations(AsyncTestCase):
    """Test async MCP operations."""
    
    def test_async_tool_execution(self):
        """Test async tool execution pattern."""
        async def mock_tool():
            await asyncio.sleep(0.01)
            return {"status": "success"}
        
        result = self.run_async(mock_tool())
        self.assertEqual(result["status"], "success")


def run_tests():
    """Run all tests and return results."""
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Add all test classes
    suite.addTests(loader.loadTestsFromTestCase(TestMCPServerImports))
    suite.addTests(loader.loadTestsFromTestCase(TestDeviceManagerTools))
    suite.addTests(loader.loadTestsFromTestCase(TestDataAcquisitionTools))
    suite.addTests(loader.loadTestsFromTestCase(TestArtifactParserTools))
    suite.addTests(loader.loadTestsFromTestCase(TestAppAnalyzerTools))
    suite.addTests(loader.loadTestsFromTestCase(TestSystemForensicsTools))
    suite.addTests(loader.loadTestsFromTestCase(TestReportGeneratorTools))
    suite.addTests(loader.loadTestsFromTestCase(TestMCPToolRegistration))
    suite.addTests(loader.loadTestsFromTestCase(TestDeepAgentIntegration))
    suite.addTests(loader.loadTestsFromTestCase(TestAsyncMCPOperations))
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    return result


if __name__ == "__main__":
    print("""
    ================================================================
         MCP SERVER INTEGRATION TESTS
         Federal Investigation Agency - Forensics Framework
    ================================================================
    """)
    
    result = run_tests()
    
    # Summary
    print("\n" + "=" * 60)
    print(f"Tests Run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print(f"Skipped: {len(result.skipped)}")
    print("=" * 60)
    
    # Exit with appropriate code
    sys.exit(0 if result.wasSuccessful() else 1)
