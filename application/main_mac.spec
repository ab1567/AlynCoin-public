# -*- mode: python ; coding: utf-8 -*-
import os
from PyInstaller.utils.hooks import collect_submodules

block_cipher = None

# Tabs actually used by main.py (leave identity/peer out)
tab_modules = [
    "dao_tab", "history_tab", "miner_tab",
    "wallet_tab", "send_tab", "stats_tab",
    "nft_tab", "swap_tab",
]

hiddenimports = ["rpc_client", *tab_modules, *collect_submodules("PyQt5")]

datas = [
    ("logo.png", "."),
    ("logo.icns", "."),    # will be created below if missing
    ("style.qss", "."),
    ("text.txt", "."),
]

binaries = []
if os.path.exists("alyncoin"):        # bundle your mac node
    binaries.append(("alyncoin", ".")) # ends up in Contents/MacOS/

a = Analysis(
    ["main.py"], pathex=["."],
    binaries=binaries, datas=datas,
    hiddenimports=hiddenimports, noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz, a.scripts, a.binaries, a.zipfiles, a.datas,
    name="AlynCoin",            # app binary name
    icon="logo.icns",
    console=False,
)

# onedir stage (build folder)
coll = COLLECT(exe, a.binaries, a.zipfiles, a.datas, name="AlynCoin")

# .app bundle
app = BUNDLE(
    coll,
    name="AlynCoin.app",
    icon="logo.icns",
    bundle_identifier="com.alyncoin.app",
    info_plist={"NSHighResolutionCapable": True},
)
