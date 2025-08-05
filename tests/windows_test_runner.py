#!/usr/bin/env python3
"""
Windows-Specific Test Runner for NetSecureX
==========================================

This is a bulletproof test runner specifically designed for Windows CI environments.
It handles Windows-specific path issues and import problems.
"""

import sys
import os
import platform
from pathlib import Path

def setup_windows_paths():
    """Setup Windows-specific paths for imports."""
    # Get project root
    project_root = Path(__file__).parent.parent.resolve()
    
    # Add all possible path variations for Windows
    paths_to_add = [
        str(project_root),
        os.getcwd(),
        str(project_root).replace('\\', '/'),
        str(project_root).replace('/', '\\'),
        str(project_root / 'core'),
        str(project_root / 'utils'),
    ]
    
    for path in paths_to_add:
        if path not in sys.path:
            sys.path.insert(0, path)
    
    print(f"🪟 Windows paths configured:")
    print(f"   Project root: {project_root}")
    print(f"   Current dir: {os.getcwd()}")
    print(f"   Python paths: {sys.path[:3]}")

def test_windows_imports():
    """Test imports with Windows-specific handling."""
    print("🧪 Testing Windows imports...")
    
    # Setup paths first
    setup_windows_paths()
    
    # Test modules with multiple strategies
    modules_to_test = [
        ("core.scanner", "PortScanner"),
        ("core.advanced_scanner", "AdvancedPortScanner"),
        ("core.service_detector", "ServiceDetector"),
        ("utils.logger", "SecurityLogger"),
        ("utils.network", "validate_ip"),
    ]
    
    all_success = True
    
    for module_name, class_name in modules_to_test:
        success = False
        
        # Strategy 1: Direct import
        try:
            print(f"  📦 Importing {module_name}.{class_name}...")
            module = __import__(module_name, fromlist=[class_name])
            getattr(module, class_name)
            print(f"  ✅ {module_name}.{class_name} imported successfully")
            success = True
        except Exception as e:
            print(f"  ⚠️ Direct import failed: {e}")
        
        # Strategy 2: Manual path import
        if not success:
            try:
                parts = module_name.split('.')
                if len(parts) == 2:
                    folder, file = parts
                    module_path = Path(__file__).parent.parent / folder / f"{file}.py"
                    if module_path.exists():
                        import importlib.util
                        spec = importlib.util.spec_from_file_location(module_name, module_path)
                        module = importlib.util.module_from_spec(spec)
                        spec.loader.exec_module(module)
                        getattr(module, class_name)
                        print(f"  ✅ {module_name}.{class_name} imported via file path")
                        success = True
            except Exception as e:
                print(f"  ⚠️ File path import failed: {e}")
        
        if not success:
            print(f"  ❌ Failed to import {module_name}.{class_name}")
            all_success = False
    
    return all_success

def main():
    """Main test runner."""
    print("🪟 Windows-Specific Test Runner for NetSecureX")
    print("=" * 50)
    
    if platform.system() != "Windows":
        print("⚠️ This runner is designed for Windows. Running anyway...")
    
    # Run the tests
    success = test_windows_imports()
    
    if success:
        print("\n🎉 All Windows tests passed!")
        return 0
    else:
        print("\n❌ Some Windows tests failed!")
        return 1

if __name__ == "__main__":
    sys.exit(main())
