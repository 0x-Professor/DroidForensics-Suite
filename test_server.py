"""
Quick test script for Android Forensics MCP Server
Run this to verify the server is working correctly
"""

import subprocess
import sys


def test_adb_available():
    """Test if ADB is available in system PATH"""
    print("Testing ADB availability...")
    try:
        result = subprocess.run(
            ["adb", "version"],
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode == 0:
            print("✅ ADB is available")
            print(f"   Version: {result.stdout.split()[4]}")
            return True
        else:
            print("❌ ADB command failed")
            return False
    except FileNotFoundError:
        print("❌ ADB not found in PATH")
        print("   Please install Android Platform Tools")
        print("   Download: https://developer.android.com/tools/releases/platform-tools")
        return False
    except Exception as e:
        print(f"❌ Error testing ADB: {e}")
        return False


def test_python_version():
    """Test Python version"""
    print("\nTesting Python version...")
    version = sys.version_info
    if version.major == 3 and version.minor >= 13:
        print(f"✅ Python {version.major}.{version.minor}.{version.micro}")
        return True
    else:
        print(f"❌ Python {version.major}.{version.minor}.{version.micro}")
        print("   Python 3.13+ required")
        return False


def test_imports():
    """Test if all required modules can be imported"""
    print("\nTesting imports...")
    required_modules = [
        ("mcp.server.fastmcp", "FastMCP"),
        ("cryptography.hazmat.primitives.ciphers", "Cipher"),
        ("pydantic", "BaseModel"),
    ]
    
    all_ok = True
    for module_name, class_name in required_modules:
        try:
            module = __import__(module_name, fromlist=[class_name])
            getattr(module, class_name)
            print(f"✅ {module_name}.{class_name}")
        except ImportError as e:
            print(f"❌ {module_name}.{class_name}: {e}")
            all_ok = False
    
    return all_ok


def test_server_syntax():
    """Test if main.py has valid syntax"""
    print("\nTesting main.py syntax...")
    try:
        with open("main.py", "r") as f:
            code = f.read()
        compile(code, "main.py", "exec")
        print("✅ main.py syntax is valid")
        return True
    except SyntaxError as e:
        print(f"❌ Syntax error in main.py: {e}")
        return False
    except Exception as e:
        print(f"❌ Error reading main.py: {e}")
        return False


def main():
    """Run all tests"""
    print("=" * 60)
    print("Android Forensics MCP Server - System Check")
    print("=" * 60)
    
    results = {
        "Python Version": test_python_version(),
        "ADB Available": test_adb_available(),
        "Module Imports": test_imports(),
        "Server Syntax": test_server_syntax(),
    }
    
    print("\n" + "=" * 60)
    print("Summary:")
    print("=" * 60)
    
    for test_name, result in results.items():
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{test_name:.<40} {status}")
    
    all_passed = all(results.values())
    
    print("\n" + "=" * 60)
    if all_passed:
        print("✅ All tests passed! Server is ready to use.")
        print("\nNext steps:")
        print("1. Connect Android device with USB debugging enabled")
        print("2. Run: uv run mcp dev main.py")
        print("3. Or integrate with Claude Desktop (see README.md)")
    else:
        print("❌ Some tests failed. Please fix the issues above.")
    print("=" * 60)
    
    return 0 if all_passed else 1


if __name__ == "__main__":
    sys.exit(main())
