#!/usr/bin/env python3
"""
Development helper script for Proxmox Range Management System.

This script provides utilities for development and testing without
requiring actual Proxmox credentials or connection.
"""

import os
import sys
from typing import Dict, Any


def check_secrets_file() -> bool:
    """Check if secrets.toml exists and provide setup guidance."""
    secrets_path = "secrets.toml"
    example_path = "secrets.toml.example"
    
    if os.path.exists(secrets_path):
        print("✓ Configuration file 'secrets.toml' found")
        return True
    else:
        print("✗ Configuration file 'secrets.toml' not found")
        if os.path.exists(example_path):
            print(f"  → Copy {example_path} to {secrets_path} and update with your values")
        else:
            print("  → Create secrets.toml with your Proxmox configuration")
        return False


def check_dependencies() -> bool:
    """Check if required dependencies are installed."""
    required_packages = ['flask', 'proxmoxer', 'tomli', 'requests']
    missing_packages = []
    
    for package in required_packages:
        try:
            __import__(package)
            print(f"✓ {package} is installed")
        except ImportError:
            print(f"✗ {package} is missing")
            missing_packages.append(package)
    
    if missing_packages:
        print(f"\nInstall missing packages with: pip install {' '.join(missing_packages)}")
        return False
    return True


def run_syntax_check() -> bool:
    """Check Python syntax for all Python files."""
    import py_compile
    
    python_files = ['web.py', 'tui.py']
    python_files.extend([f"scripts/{f}" for f in os.listdir('scripts') if f.endswith('.py')])
    
    all_good = True
    for file_path in python_files:
        if os.path.exists(file_path):
            try:
                py_compile.compile(file_path, doraise=True)
                print(f"✓ {file_path} syntax OK")
            except py_compile.PyCompileError as e:
                print(f"✗ {file_path} syntax error: {e}")
                all_good = False
        else:
            print(f"⚠ {file_path} not found")
    
    return all_good


def show_dev_info():
    """Show development information and tips."""
    print("\n" + "="*50)
    print("Proxmox Range Management - Development Info")
    print("="*50)
    
    print("\nKey Files:")
    print("  web.py          - Main Flask application")
    print("  tui.py          - Text-based user interface")
    print("  scripts/        - Utility scripts for Proxmox management")
    print("  templates/      - HTML templates for web interface")
    print("  secrets.toml    - Configuration file (not in git)")
    
    print("\nDevelopment Commands:")
    print("  python web.py              - Start web server (localhost:7878)")
    print("  python dev.py check        - Run development checks")
    print("  python -m py_compile *.py  - Check syntax")
    
    print("\nAPI Endpoints:")
    print("  GET  /                - Home page")
    print("  GET  /health          - Health check and system status")
    print("  GET  /clone           - VM cloning form")
    print("  POST /clone           - Create VM clone")
    print("  GET  /login           - Admin login")
    print("  GET  /admin           - Admin dashboard")
    print("  POST /range           - Bulk VM cloning (admin)")
    print("  POST /ensure          - User management (admin)")


def main():
    """Main development script entry point."""
    if len(sys.argv) > 1 and sys.argv[1] == "check":
        print("Running development environment checks...\n")
        
        deps_ok = check_dependencies()
        secrets_ok = check_secrets_file()
        syntax_ok = run_syntax_check()
        
        print(f"\nSummary:")
        print(f"  Dependencies: {'✓' if deps_ok else '✗'}")
        print(f"  Configuration: {'✓' if secrets_ok else '✗'}")  
        print(f"  Syntax: {'✓' if syntax_ok else '✗'}")
        
        if deps_ok and syntax_ok:
            print("\n✓ Ready for development!")
            if not secrets_ok:
                print("  → Configure secrets.toml to connect to Proxmox")
        else:
            print("\n✗ Setup required before development")
            sys.exit(1)
    else:
        show_dev_info()


if __name__ == "__main__":
    main()