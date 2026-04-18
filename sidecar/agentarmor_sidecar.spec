# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller spec for the AgentArmor Studio sidecar.

Bundles main.py and all agentarmor-core dependencies into a single
.exe with no console window (suitable for sidecar launch by Tauri).

Build with:
    pyinstaller --noconfirm agentarmor_sidecar.spec
"""

import os
import importlib
import sys

# ---------------------------------------------------------------------------
# Collect agentarmor-core package data
# ---------------------------------------------------------------------------

block_cipher = None

# Attempt to find agentarmor installation to collect data files
agentarmor_datas = []
try:
    import agentarmor
    pkg_dir = os.path.dirname(agentarmor.__file__)
    agentarmor_datas = [(pkg_dir, "agentarmor")]
except ImportError:
    pass

# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------

a = Analysis(
    ["main.py"],
    pathex=[],
    binaries=[],
    datas=agentarmor_datas,
    hiddenimports=[
        "agentarmor",
        "agentarmor.core",
        "agentarmor.core.types",
        "agentarmor.core.armor",
        "agentarmor.core.config",
        "agentarmor.layers",
        "agentarmor.layers.ingestion",
        "agentarmor.layers.storage",
        "agentarmor.layers.context",
        "agentarmor.layers.planning",
        "agentarmor.layers.execution",
        "agentarmor.layers.output",
        "agentarmor.layers.interagent",
        "agentarmor.layers.identity",
        "agentarmor.audit",
        "uvicorn",
        "uvicorn.logging",
        "uvicorn.loops",
        "uvicorn.loops.auto",
        "uvicorn.protocols",
        "uvicorn.protocols.http",
        "uvicorn.protocols.http.auto",
        "uvicorn.protocols.websockets",
        "uvicorn.protocols.websockets.auto",
        "uvicorn.lifespan",
        "uvicorn.lifespan.on",
        "fastapi",
        "fastapi.middleware",
        "fastapi.middleware.cors",
        "starlette",
        "starlette.routing",
        "starlette.middleware",
        "pydantic",
        "httpx",
        "httpx._transports",
        "httpx._transports.default",
        "anyio",
        "anyio._backends",
        "anyio._backends._asyncio",
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        "tkinter",
        "matplotlib",
        "numpy",
        "scipy",
        "PIL",
        "IPython",
        "pytest",
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

# ---------------------------------------------------------------------------
# Bundle
# ---------------------------------------------------------------------------

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name="agentarmor-sidecar",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,      # No console window (windowed mode)
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=os.path.join("..", "src-tauri", "icons", "icon.ico"),
)
