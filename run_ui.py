"""
FIA Android Forensics Framework - Web UI Launcher
Quick start script for launching the interactive investigation interface.
"""

import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from ui.app import launch_ui


def main():
    """Main entry point for the UI."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="FIA Android Digital Forensics - Interactive Web UI"
    )
    parser.add_argument(
        "--port", "-p",
        type=int,
        default=7860,
        help="Port to run the web UI on (default: 7860)"
    )
    parser.add_argument(
        "--share", "-s",
        action="store_true",
        help="Create a public shareable link"
    )
    
    args = parser.parse_args()
    
    print("""
    ╔═══════════════════════════════════════════════════════════════╗
    ║     FIA Android Digital Forensics Framework                   ║
    ║     Interactive Investigation Console                         ║
    ╠═══════════════════════════════════════════════════════════════╣
    ║  Features:                                                    ║
    ║  • Device connection monitoring                               ║
    ║  • Human-in-the-loop tool approval                            ║
    ║  • AI-powered forensic analysis                               ║
    ║  • Interactive investigation workflow                         ║
    ╚═══════════════════════════════════════════════════════════════╝
    """)
    
    launch_ui(share=args.share, port=args.port)


if __name__ == "__main__":
    main()
