# -*- mode: python ; coding: utf-8 -*-
import os
from PyInstaller.utils.hooks import collect_submodules

block_cipher = None

tab_modules = [
    "dao_tab", "history_tab", "miner_tab",
    "wallet_tab", "send_tab", "stats_tab",
    "nft_tab", "swap_tab",
]

hiddenimports = ["rpc_client", *tab_modules, *collect_submodules("PyQt5")]

datas = [
    ("logo.png", "."),
    ("logo.ico", "."),
    ("style.qss", "."),
    ("text.txt", "."),
]

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
)

# THIS creates the onedir bundle under dist/AlynCoin Wallet/
coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    name="AlynCoin Wallet",
)
