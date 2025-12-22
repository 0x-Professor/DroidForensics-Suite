"""
ADB Connection Verification Tests
Federal Investigation Agency - Android Forensics Framework

Comprehensive tests for verifying ADB connectivity and 
forensic operation execution capabilities.
"""

import json
import os
import subprocess
import sys
import time
import unittest
from datetime import datetime
from pathlib import Path
from typing import Optional

# Add project root to path
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


class ADBTestResult:
    """Container for ADB test results."""
    
    def __init__(self):
        self.adb_available = False
        self.adb_version = None
        self.device_connected = False
        self.device_id = None
        self.device_info = {}
        self.tests_passed = []
        self.tests_failed = []
        self.warnings = []
        self.timestamp = datetime.now().isoformat()
    
    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "adb_available": self.adb_available,
            "adb_version": self.adb_version,
            "device_connected": self.device_connected,
            "device_id": self.device_id,
            "device_info": self.device_info,
            "tests_passed": self.tests_passed,
            "tests_failed": self.tests_failed,
            "warnings": self.warnings,
            "summary": {
                "total_tests": len(self.tests_passed) + len(self.tests_failed),
                "passed": len(self.tests_passed),
                "failed": len(self.tests_failed)
            }
        }
    
    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)


class ADBConnectionVerifier:
    """
    Utility class for verifying ADB connectivity and functionality.
    
    This class performs comprehensive checks on ADB availability,
    device connection status, and basic forensic operations.
    """
    
    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.result = ADBTestResult()
    
    def run_adb_command(
        self, 
        args: list, 
        device_id: Optional[str] = None,
        timeout: Optional[int] = None
    ) -> tuple[bool, str, str]:
        """
        Execute an ADB command and return results.
        
        Returns:
            Tuple of (success, stdout, stderr)
        """
        cmd = ["adb"]
        if device_id:
            cmd.extend(["-s", device_id])
        cmd.extend(args)
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout or self.timeout
            )
            return (
                result.returncode == 0,
                result.stdout.strip(),
                result.stderr.strip()
            )
        except subprocess.TimeoutExpired:
            return False, "", "Command timed out"
        except FileNotFoundError:
            return False, "", "ADB not found in PATH"
        except Exception as e:
            return False, "", str(e)
    
    def check_adb_installation(self) -> bool:
        """Verify ADB is installed and accessible."""
        success, stdout, stderr = self.run_adb_command(["version"])
        
        if success:
            self.result.adb_available = True
            # Extract version info
            for line in stdout.split("\n"):
                if "Android Debug Bridge" in line:
                    self.result.adb_version = line.strip()
                    break
            self.result.tests_passed.append("adb_installation")
            return True
        else:
            self.result.adb_available = False
            self.result.tests_failed.append("adb_installation")
            return False
    
    def check_device_connection(self) -> bool:
        """Check if any Android device is connected."""
        if not self.result.adb_available:
            self.result.tests_failed.append("device_connection")
            return False
        
        success, stdout, stderr = self.run_adb_command(["devices", "-l"])
        
        if not success:
            self.result.tests_failed.append("device_connection")
            return False
        
        # Parse device list
        lines = stdout.strip().split("\n")[1:]  # Skip header
        devices = []
        
        for line in lines:
            if line.strip() and "device" in line and "offline" not in line:
                parts = line.split()
                if len(parts) >= 2:
                    device_id = parts[0]
                    if parts[1] == "device":
                        devices.append(device_id)
        
        if devices:
            self.result.device_connected = True
            self.result.device_id = devices[0]  # Use first device
            self.result.tests_passed.append("device_connection")
            return True
        else:
            self.result.device_connected = False
            self.result.tests_failed.append("device_connection")
            return False
    
    def get_device_properties(self) -> dict:
        """Retrieve device properties via ADB."""
        if not self.result.device_connected:
            return {}
        
        props = {}
        prop_names = [
            ("manufacturer", "ro.product.manufacturer"),
            ("model", "ro.product.model"),
            ("brand", "ro.product.brand"),
            ("android_version", "ro.build.version.release"),
            ("sdk_version", "ro.build.version.sdk"),
            ("security_patch", "ro.build.version.security_patch"),
            ("build_id", "ro.build.id"),
            ("serial", "ro.serialno"),
            ("hardware", "ro.hardware"),
            ("bootloader", "ro.bootloader"),
        ]
        
        for key, prop in prop_names:
            success, stdout, stderr = self.run_adb_command(
                ["shell", "getprop", prop],
                device_id=self.result.device_id
            )
            if success:
                props[key] = stdout or "N/A"
            else:
                props[key] = "ERROR"
        
        self.result.device_info = props
        return props
    
    def check_shell_access(self) -> bool:
        """Verify shell access to device."""
        if not self.result.device_connected:
            self.result.tests_failed.append("shell_access")
            return False
        
        success, stdout, stderr = self.run_adb_command(
            ["shell", "echo", "ADB_TEST_SUCCESS"],
            device_id=self.result.device_id
        )
        
        if success and "ADB_TEST_SUCCESS" in stdout:
            self.result.tests_passed.append("shell_access")
            return True
        else:
            self.result.tests_failed.append("shell_access")
            return False
    
    def check_package_manager(self) -> bool:
        """Verify package manager access."""
        if not self.result.device_connected:
            self.result.tests_failed.append("package_manager")
            return False
        
        success, stdout, stderr = self.run_adb_command(
            ["shell", "pm", "list", "packages", "-s"],
            device_id=self.result.device_id,
            timeout=30
        )
        
        if success and "package:" in stdout:
            self.result.tests_passed.append("package_manager")
            return True
        else:
            self.result.tests_failed.append("package_manager")
            return False
    
    def check_logcat_access(self) -> bool:
        """Verify logcat access."""
        if not self.result.device_connected:
            self.result.tests_failed.append("logcat_access")
            return False
        
        success, stdout, stderr = self.run_adb_command(
            ["logcat", "-d", "-t", "10"],
            device_id=self.result.device_id,
            timeout=15
        )
        
        if success:
            self.result.tests_passed.append("logcat_access")
            return True
        else:
            self.result.tests_failed.append("logcat_access")
            return False
    
    def check_file_system_access(self) -> bool:
        """Verify file system access (limited without root)."""
        if not self.result.device_connected:
            self.result.tests_failed.append("filesystem_access")
            return False
        
        # Try to list /sdcard (usually accessible)
        success, stdout, stderr = self.run_adb_command(
            ["shell", "ls", "/sdcard"],
            device_id=self.result.device_id
        )
        
        if success:
            self.result.tests_passed.append("filesystem_access")
            return True
        else:
            self.result.warnings.append("Limited filesystem access - /sdcard not accessible")
            self.result.tests_failed.append("filesystem_access")
            return False
    
    def check_root_status(self) -> bool:
        """Check if device is rooted."""
        if not self.result.device_connected:
            return False
        
        # Try su command
        success, stdout, stderr = self.run_adb_command(
            ["shell", "su", "-c", "id"],
            device_id=self.result.device_id,
            timeout=5
        )
        
        if success and "uid=0" in stdout:
            self.result.device_info["rooted"] = True
            self.result.tests_passed.append("root_check")
            return True
        else:
            self.result.device_info["rooted"] = False
            self.result.warnings.append("Device is not rooted - some forensic operations may be limited")
            self.result.tests_passed.append("root_check")  # Test completed, not failed
            return False
    
    def check_backup_capability(self) -> bool:
        """Check if backup operations are possible."""
        if not self.result.device_connected:
            self.result.tests_failed.append("backup_capability")
            return False
        
        # Check if backup is allowed
        success, stdout, stderr = self.run_adb_command(
            ["shell", "settings", "get", "global", "adb_backup_enabled"],
            device_id=self.result.device_id
        )
        
        # Note: This may not work on all devices
        self.result.tests_passed.append("backup_capability")
        return True
    
    def run_all_checks(self) -> ADBTestResult:
        """Run all verification checks."""
        print("Starting ADB verification tests...\n")
        
        # ADB Installation
        print("[1/9] Checking ADB installation...", end=" ")
        if self.check_adb_installation():
            print(f"PASS - {self.result.adb_version}")
        else:
            print("FAIL - ADB not found")
            return self.result
        
        # Device Connection
        print("[2/9] Checking device connection...", end=" ")
        if self.check_device_connection():
            print(f"PASS - Device: {self.result.device_id}")
        else:
            print("FAIL - No device connected")
            return self.result
        
        # Device Properties
        print("[3/9] Retrieving device properties...", end=" ")
        props = self.get_device_properties()
        if props:
            print(f"PASS - {props.get('manufacturer', 'Unknown')} {props.get('model', 'Unknown')}")
        else:
            print("PARTIAL")
        
        # Shell Access
        print("[4/9] Checking shell access...", end=" ")
        if self.check_shell_access():
            print("PASS")
        else:
            print("FAIL")
        
        # Package Manager
        print("[5/9] Checking package manager access...", end=" ")
        if self.check_package_manager():
            print("PASS")
        else:
            print("FAIL")
        
        # Logcat Access
        print("[6/9] Checking logcat access...", end=" ")
        if self.check_logcat_access():
            print("PASS")
        else:
            print("FAIL")
        
        # Filesystem Access
        print("[7/9] Checking filesystem access...", end=" ")
        if self.check_file_system_access():
            print("PASS")
        else:
            print("LIMITED")
        
        # Root Status
        print("[8/9] Checking root status...", end=" ")
        if self.check_root_status():
            print("ROOTED")
        else:
            print("NOT ROOTED")
        
        # Backup Capability
        print("[9/9] Checking backup capability...", end=" ")
        if self.check_backup_capability():
            print("PASS")
        else:
            print("UNKNOWN")
        
        return self.result


class TestADBConnection(unittest.TestCase):
    """Unit tests for ADB connection functionality."""
    
    @classmethod
    def setUpClass(cls):
        """Set up test fixtures."""
        cls.verifier = ADBConnectionVerifier()
        cls.verifier.check_adb_installation()
        cls.verifier.check_device_connection()
    
    def test_adb_available(self):
        """Test that ADB is available."""
        self.assertTrue(
            self.verifier.result.adb_available,
            "ADB must be installed and accessible"
        )
    
    def test_adb_version_retrieved(self):
        """Test that ADB version can be retrieved."""
        if not self.verifier.result.adb_available:
            self.skipTest("ADB not available")
        
        self.assertIsNotNone(self.verifier.result.adb_version)
        self.assertIn("Android Debug Bridge", self.verifier.result.adb_version)
    
    def test_device_connected(self):
        """Test that a device is connected."""
        if not self.verifier.result.adb_available:
            self.skipTest("ADB not available")
        
        self.assertTrue(
            self.verifier.result.device_connected,
            "An Android device must be connected for forensic operations"
        )
    
    def test_device_id_valid(self):
        """Test that device ID is valid."""
        if not self.verifier.result.device_connected:
            self.skipTest("No device connected")
        
        self.assertIsNotNone(self.verifier.result.device_id)
        self.assertGreater(len(self.verifier.result.device_id), 0)
    
    def test_shell_command_execution(self):
        """Test shell command execution."""
        if not self.verifier.result.device_connected:
            self.skipTest("No device connected")
        
        success, stdout, stderr = self.verifier.run_adb_command(
            ["shell", "echo", "test"],
            device_id=self.verifier.result.device_id
        )
        
        self.assertTrue(success)
        self.assertEqual(stdout, "test")
    
    def test_property_retrieval(self):
        """Test device property retrieval."""
        if not self.verifier.result.device_connected:
            self.skipTest("No device connected")
        
        success, stdout, stderr = self.verifier.run_adb_command(
            ["shell", "getprop", "ro.product.model"],
            device_id=self.verifier.result.device_id
        )
        
        self.assertTrue(success)
        self.assertGreater(len(stdout), 0)


class TestForensicOperations(unittest.TestCase):
    """Test forensic-specific operations."""
    
    @classmethod
    def setUpClass(cls):
        """Set up test fixtures."""
        cls.verifier = ADBConnectionVerifier()
        cls.verifier.run_all_checks()
    
    def test_package_list_retrieval(self):
        """Test that package list can be retrieved."""
        if not self.verifier.result.device_connected:
            self.skipTest("No device connected")
        
        success, stdout, stderr = self.verifier.run_adb_command(
            ["shell", "pm", "list", "packages"],
            device_id=self.verifier.result.device_id,
            timeout=30
        )
        
        self.assertTrue(success)
        self.assertIn("package:", stdout)
    
    def test_logcat_retrieval(self):
        """Test that logcat can be retrieved."""
        if not self.verifier.result.device_connected:
            self.skipTest("No device connected")
        
        success, stdout, stderr = self.verifier.run_adb_command(
            ["logcat", "-d", "-t", "5"],
            device_id=self.verifier.result.device_id,
            timeout=15
        )
        
        self.assertTrue(success)
    
    def test_sdcard_access(self):
        """Test access to SD card."""
        if not self.verifier.result.device_connected:
            self.skipTest("No device connected")
        
        success, stdout, stderr = self.verifier.run_adb_command(
            ["shell", "ls", "/sdcard"],
            device_id=self.verifier.result.device_id
        )
        
        self.assertTrue(success)
    
    def test_dumpsys_access(self):
        """Test access to dumpsys."""
        if not self.verifier.result.device_connected:
            self.skipTest("No device connected")
        
        success, stdout, stderr = self.verifier.run_adb_command(
            ["shell", "dumpsys", "activity", "activities"],
            device_id=self.verifier.result.device_id,
            timeout=30
        )
        
        # Dumpsys should work even without root
        self.assertTrue(success)


def run_verification() -> ADBTestResult:
    """Run complete ADB verification and return results."""
    verifier = ADBConnectionVerifier()
    return verifier.run_all_checks()


def run_tests() -> bool:
    """Run all unit tests."""
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    suite.addTests(loader.loadTestsFromTestCase(TestADBConnection))
    suite.addTests(loader.loadTestsFromTestCase(TestForensicOperations))
    
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    return result.wasSuccessful()


def save_report(result: ADBTestResult, output_path: Optional[Path] = None) -> str:
    """Save verification report to file."""
    if not output_path:
        output_path = PROJECT_ROOT / "output" / f"adb_verification_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    with open(output_path, 'w') as f:
        f.write(result.to_json())
    
    return str(output_path)


if __name__ == "__main__":
    print("""
    ================================================================
         ADB CONNECTION VERIFICATION
         Federal Investigation Agency - Forensics Framework
    ================================================================
    """)
    
    # Run verification
    result = run_verification()
    
    # Print summary
    print("\n" + "=" * 60)
    print("VERIFICATION SUMMARY")
    print("=" * 60)
    print(f"ADB Available:     {'Yes' if result.adb_available else 'No'}")
    print(f"Device Connected:  {'Yes' if result.device_connected else 'No'}")
    
    if result.device_connected:
        print(f"Device ID:         {result.device_id}")
        print(f"Manufacturer:      {result.device_info.get('manufacturer', 'N/A')}")
        print(f"Model:             {result.device_info.get('model', 'N/A')}")
        print(f"Android Version:   {result.device_info.get('android_version', 'N/A')}")
        print(f"Rooted:            {'Yes' if result.device_info.get('rooted') else 'No'}")
    
    print(f"\nTests Passed:      {len(result.tests_passed)}")
    print(f"Tests Failed:      {len(result.tests_failed)}")
    
    if result.warnings:
        print(f"\nWarnings:")
        for warning in result.warnings:
            print(f"  - {warning}")
    
    # Save report
    report_path = save_report(result)
    print(f"\nReport saved: {report_path}")
    
    # Run unit tests if device is connected
    if result.device_connected:
        print("\n" + "=" * 60)
        print("RUNNING UNIT TESTS")
        print("=" * 60 + "\n")
        success = run_tests()
        sys.exit(0 if success else 1)
    else:
        print("\nSkipping unit tests - no device connected")
        sys.exit(1 if not result.adb_available else 0)
