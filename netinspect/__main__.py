#!/usr/bin/env python3
"""
net-inspect - Network Security Intelligence Tool
Entry point for running as a module: python3 -m netinspect
"""

def main():
    """Main entry point for net-inspect."""
    from netinspect._netinspect_main import main as _main
    import sys
    return _main()

if __name__ == "__main__":
    import sys
    sys.exit(main())
