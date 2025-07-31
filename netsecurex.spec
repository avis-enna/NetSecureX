# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller Spec File for NetSecureX
====================================

This spec file is used to build standalone executables for NetSecureX
that work across Windows, macOS, and Linux platforms.
"""

import os
import sys
from PyInstaller.utils.hooks import collect_data_files, collect_submodules

# Get the current directory
block_cipher = None
current_dir = os.path.dirname(os.path.abspath(SPEC))

# Collect all data files
datas = []
datas += collect_data_files('rich')
datas += collect_data_files('click')
datas += [('.env.example', '.')]
datas += [('README.md', '.')]
datas += [('VERSION', '.')]

# Collect hidden imports
hiddenimports = []
hiddenimports += collect_submodules('rich')
hiddenimports += collect_submodules('click')
hiddenimports += collect_submodules('cryptography')
hiddenimports += collect_submodules('requests')
hiddenimports += collect_submodules('aiohttp')
hiddenimports += [
    'core',
    'core.scanner',
    'core.ssl_check', 
    'core.vuln_lookup',
    'core.banner_grabber',
    'core.packet_sniffer',
    'core.ip_reputation',
    'core.firewall_tester',
    'core.cert_analyzer',
    'core.cve_lookup',
    'core.ip_reputation_new',
    'utils',
    'utils.logger',
    'utils.network',
    'ui',
    'ui.cli',
]

# Platform-specific hidden imports
if sys.platform.startswith('win'):
    hiddenimports += ['pywin32', 'wmi']
elif sys.platform == 'darwin':
    hiddenimports += ['pyobjc']
elif sys.platform.startswith('linux'):
    hiddenimports += ['scapy']

# Binaries (platform-specific)
binaries = []

# Analysis
a = Analysis(
    ['main.py'],
    pathex=[current_dir],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        'tkinter',
        'matplotlib',
        'numpy',
        'pandas',
        'scipy',
        'PIL',
        'PyQt5',
        'PyQt6',
        'PySide2',
        'PySide6',
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

# Remove duplicate entries
pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

# Executable configuration
exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='netsecurex',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon='assets/icon.ico' if os.path.exists('assets/icon.ico') else None,
)

# Collect everything into a directory
coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='netsecurex',
)

# Platform-specific app bundle (macOS)
if sys.platform == 'darwin':
    app = BUNDLE(
        coll,
        name='NetSecureX.app',
        icon='assets/icon.icns' if os.path.exists('assets/icon.icns') else None,
        bundle_identifier='dev.netsecurex.app',
        info_plist={
            'CFBundleName': 'NetSecureX',
            'CFBundleDisplayName': 'NetSecureX Cybersecurity Toolkit',
            'CFBundleVersion': '1.0.0',
            'CFBundleShortVersionString': '1.0.0',
            'NSHighResolutionCapable': True,
            'LSMinimumSystemVersion': '10.14',
        },
    )
