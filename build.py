#!/usr/bin/env python3
"""
NetSecureX Cross-Platform Build Script
======================================

This script builds NetSecureX for multiple platforms and creates
distribution packages for Windows, macOS, and Linux.
"""

import os
import sys
import shutil
import subprocess
import platform
import argparse
from pathlib import Path

class NetSecureXBuilder:
    """Cross-platform builder for NetSecureX."""
    
    def __init__(self):
        self.root_dir = Path(__file__).parent
        self.build_dir = self.root_dir / 'build'
        self.dist_dir = self.root_dir / 'dist'
        self.platform = platform.system().lower()
        self.arch = platform.machine().lower()
        
    def clean(self):
        """Clean build and dist directories."""
        print("🧹 Cleaning build directories...")
        
        for directory in [self.build_dir, self.dist_dir]:
            if directory.exists():
                shutil.rmtree(directory)
                print(f"   Removed {directory}")
        
        # Remove PyInstaller cache
        pycache_dirs = list(self.root_dir.rglob('__pycache__'))
        for cache_dir in pycache_dirs:
            shutil.rmtree(cache_dir)
        
        print("✅ Clean completed")
    
    def install_dependencies(self):
        """Install build dependencies."""
        print("📦 Installing build dependencies...")
        
        dependencies = [
            'pyinstaller>=5.0',
            'setuptools>=65.0',
            'wheel>=0.38.0',
            'twine>=4.0.0',
        ]
        
        for dep in dependencies:
            print(f"   Installing {dep}...")
            subprocess.run([sys.executable, '-m', 'pip', 'install', dep], 
                         check=True, capture_output=True)
        
        print("✅ Dependencies installed")
    
    def build_executable(self):
        """Build standalone executable using PyInstaller."""
        print(f"🔨 Building executable for {self.platform}-{self.arch}...")
        
        # Run PyInstaller
        cmd = [
            sys.executable, '-m', 'PyInstaller',
            '--clean',
            '--noconfirm',
            'netsecurex.spec'
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode != 0:
            print(f"❌ Build failed:")
            print(result.stderr)
            return False
        
        print("✅ Executable built successfully")
        return True
    
    def build_wheel(self):
        """Build Python wheel package."""
        print("🎯 Building Python wheel...")
        
        cmd = [sys.executable, 'setup.py', 'bdist_wheel']
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode != 0:
            print(f"❌ Wheel build failed:")
            print(result.stderr)
            return False
        
        print("✅ Wheel built successfully")
        return True
    
    def build_source_dist(self):
        """Build source distribution."""
        print("📄 Building source distribution...")
        
        cmd = [sys.executable, 'setup.py', 'sdist']
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode != 0:
            print(f"❌ Source distribution build failed:")
            print(result.stderr)
            return False
        
        print("✅ Source distribution built successfully")
        return True
    
    def create_installer(self):
        """Create platform-specific installer."""
        print(f"📦 Creating installer for {self.platform}...")
        
        if self.platform == 'windows':
            return self._create_windows_installer()
        elif self.platform == 'darwin':
            return self._create_macos_installer()
        elif self.platform == 'linux':
            return self._create_linux_installer()
        else:
            print(f"⚠️ No installer support for {self.platform}")
            return True
    
    def _create_windows_installer(self):
        """Create Windows installer using NSIS or Inno Setup."""
        print("   Creating Windows installer...")
        
        # Check if NSIS is available
        try:
            subprocess.run(['makensis', '/VERSION'], 
                         capture_output=True, check=True)
            return self._create_nsis_installer()
        except (subprocess.CalledProcessError, FileNotFoundError):
            print("   NSIS not found, creating ZIP archive...")
            return self._create_zip_archive()
    
    def _create_nsis_installer(self):
        """Create NSIS installer script and build."""
        nsis_script = self.root_dir / 'installer.nsi'
        
        nsis_content = f'''
!define APPNAME "NetSecureX"
!define COMPANYNAME "NetSecureX Team"
!define DESCRIPTION "Unified Cybersecurity Toolkit"
!define VERSIONMAJOR 1
!define VERSIONMINOR 0
!define VERSIONBUILD 0

Name "${{APPNAME}}"
OutFile "dist/NetSecureX-Setup-Windows.exe"
InstallDir "$PROGRAMFILES64\\${{APPNAME}}"
RequestExecutionLevel admin

Page directory
Page instfiles

Section "install"
    SetOutPath $INSTDIR
    File /r "dist\\netsecurex\\*"
    
    # Create uninstaller
    WriteUninstaller "$INSTDIR\\uninstall.exe"
    
    # Add to Add/Remove Programs
    WriteRegStr HKLM "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\${{APPNAME}}" "DisplayName" "${{APPNAME}}"
    WriteRegStr HKLM "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\${{APPNAME}}" "UninstallString" "$INSTDIR\\uninstall.exe"
    
    # Create Start Menu shortcut
    CreateDirectory "$SMPROGRAMS\\${{APPNAME}}"
    CreateShortCut "$SMPROGRAMS\\${{APPNAME}}\\${{APPNAME}}.lnk" "$INSTDIR\\netsecurex.exe"
SectionEnd

Section "uninstall"
    Delete "$INSTDIR\\uninstall.exe"
    RMDir /r "$INSTDIR"
    RMDir /r "$SMPROGRAMS\\${{APPNAME}}"
    DeleteRegKey HKLM "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\${{APPNAME}}"
SectionEnd
'''
        
        with open(nsis_script, 'w') as f:
            f.write(nsis_content)
        
        # Build installer
        result = subprocess.run(['makensis', str(nsis_script)], 
                              capture_output=True, text=True)
        
        if result.returncode == 0:
            print("   ✅ Windows installer created")
            return True
        else:
            print(f"   ❌ NSIS build failed: {result.stderr}")
            return False
    
    def _create_macos_installer(self):
        """Create macOS installer package."""
        print("   Creating macOS installer...")
        
        # Create DMG using hdiutil
        dmg_path = self.dist_dir / 'NetSecureX-macOS.dmg'
        app_path = self.dist_dir / 'NetSecureX.app'
        
        if app_path.exists():
            cmd = [
                'hdiutil', 'create',
                '-volname', 'NetSecureX',
                '-srcfolder', str(app_path),
                '-ov', '-format', 'UDZO',
                str(dmg_path)
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                print("   ✅ macOS DMG created")
                return True
            else:
                print(f"   ❌ DMG creation failed: {result.stderr}")
                return False
        else:
            print("   ⚠️ App bundle not found, creating TAR archive...")
            return self._create_tar_archive()
    
    def _create_linux_installer(self):
        """Create Linux installer packages."""
        print("   Creating Linux packages...")
        
        # Create TAR.GZ archive
        success = self._create_tar_archive()
        
        # Try to create DEB package if dpkg-deb is available
        try:
            subprocess.run(['dpkg-deb', '--version'], 
                         capture_output=True, check=True)
            success &= self._create_deb_package()
        except (subprocess.CalledProcessError, FileNotFoundError):
            print("   dpkg-deb not found, skipping DEB package")
        
        # Try to create RPM package if rpmbuild is available
        try:
            subprocess.run(['rpmbuild', '--version'], 
                         capture_output=True, check=True)
            success &= self._create_rpm_package()
        except (subprocess.CalledProcessError, FileNotFoundError):
            print("   rpmbuild not found, skipping RPM package")
        
        return success
    
    def _create_zip_archive(self):
        """Create ZIP archive."""
        archive_path = self.dist_dir / f'NetSecureX-{self.platform}-{self.arch}.zip'
        source_dir = self.dist_dir / 'netsecurex'
        
        if source_dir.exists():
            shutil.make_archive(str(archive_path.with_suffix('')), 'zip', source_dir)
            print(f"   ✅ ZIP archive created: {archive_path}")
            return True
        return False
    
    def _create_tar_archive(self):
        """Create TAR.GZ archive."""
        archive_path = self.dist_dir / f'NetSecureX-{self.platform}-{self.arch}.tar.gz'
        source_dir = self.dist_dir / 'netsecurex'
        
        if source_dir.exists():
            shutil.make_archive(str(archive_path.with_suffix('.tar')), 'gztar', source_dir)
            print(f"   ✅ TAR.GZ archive created: {archive_path}")
            return True
        return False
    
    def _create_deb_package(self):
        """Create Debian package."""
        print("   Creating DEB package...")
        # This would require more complex packaging setup
        print("   ⚠️ DEB package creation not implemented yet")
        return True
    
    def _create_rpm_package(self):
        """Create RPM package."""
        print("   Creating RPM package...")
        # This would require more complex packaging setup
        print("   ⚠️ RPM package creation not implemented yet")
        return True
    
    def build_all(self):
        """Build all distribution formats."""
        print("🚀 Starting NetSecureX build process...")
        print(f"Platform: {self.platform}-{self.arch}")
        print(f"Python: {sys.version}")
        print()
        
        success = True
        
        # Clean previous builds
        self.clean()
        
        # Install dependencies
        success &= self.install_dependencies()
        
        # Build executable
        success &= self.build_executable()
        
        # Build Python packages
        success &= self.build_wheel()
        success &= self.build_source_dist()
        
        # Create installer
        success &= self.create_installer()
        
        if success:
            print("\n🎉 Build completed successfully!")
            print(f"📁 Distribution files available in: {self.dist_dir}")
        else:
            print("\n❌ Build failed!")
            return 1
        
        return 0


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description='Build NetSecureX for multiple platforms')
    parser.add_argument('--clean', action='store_true', help='Clean build directories only')
    parser.add_argument('--executable-only', action='store_true', help='Build executable only')
    parser.add_argument('--packages-only', action='store_true', help='Build Python packages only')
    
    args = parser.parse_args()
    
    builder = NetSecureXBuilder()
    
    if args.clean:
        builder.clean()
        return 0
    
    if args.executable_only:
        builder.clean()
        builder.install_dependencies()
        return 0 if builder.build_executable() else 1
    
    if args.packages_only:
        builder.clean()
        success = builder.build_wheel() and builder.build_source_dist()
        return 0 if success else 1
    
    # Build everything
    return builder.build_all()


if __name__ == '__main__':
    sys.exit(main())
