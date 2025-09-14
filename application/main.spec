# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec for the AlynCoin Windows GUI bundle.

This spec includes only the tab modules that are loaded by ``main.py`` and
bundles the native ``alyncoin.exe`` node alongside the Qt application.  The
resulting build is a one-folder distribution that can run on a system without
Python installed.
"""

import os
from PyInstaller.utils.hooks import collect_submodules

block_cipher = None


# Modules that are dynamically imported by the GUI at runtime
tab_modules = [
    "dao_tab",
    "history_tab",
    "miner_tab",
    "wallet_tab",
    "send_tab",
    "stats_tab",
    "nft_tab",
    "swap_tab",
]

# Hidden imports required by PyInstaller to bundle PyQt5 and tab modules
hiddenimports = ["rpc_client", *tab_modules, *collect_submodules("PyQt5")]

# Asset files bundled next to the executable
datas = [
    ("logo.png", "."),
    ("logo.ico", "."),
    ("style.qss", "."),
    ("text.txt", "."),
]

# Bundle the native node binary if present in the application directory
binaries = []
if os.path.exists("alyncoin.exe"):
    binaries.append(("alyncoin.exe", "."))

a = Analysis(
    ["main.py"],
    pathex=["."],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    name="AlynCoin Wallet",
    icon="logo.ico",
    console=False,
    append_pkg=True,
)

