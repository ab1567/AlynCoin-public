# main.spec — minimal PyQt5/Qt bundle; put `alyncoin` in Contents/MacOS only
block_cipher = None

import os
from pathlib import Path
from PyInstaller.utils.hooks import collect_dynamic_libs

# ---- Qt modules you actually use
QT_MODULES = [
    'PyQt5',              # keep 'PyQt5' to trigger runtime hook
    'PyQt5.QtCore',
    'PyQt5.QtGui',
    'PyQt5.QtWidgets',
    'PyQt5.QtNetwork',
    'PyQt5.QtPrintSupport',
]

# ---- Exclude heavy/unneeded modules
EXCLUDES = [
    'PyQt5.QtQml',
    'PyQt5.QtQuick',
    'PyQt5.QtQuickWidgets',
    'PyQt5.QtQuick3D',
    'PyQt5.Qt3DCore',
    'PyQt5.Qt3DRender',
    'PyQt5.Qt3DInput',
    'PyQt5.QtBluetooth',
    'PyQt5.QtPositioning',
]

# ---- Collect only required Qt dylibs; filter out 3D/Bluetooth/etc.
qt_bins = []
for mod in QT_MODULES[1:]:
    for src, dst in collect_dynamic_libs(mod):
        if any(x in src for x in ('Qt3D', 'Bluetooth', 'Positioning', 'Qml', 'Quick')):
            continue
        qt_bins.append((src, dst))

# De-dup destinations to avoid symlink collisions
seen = set()
qt_bins_dedup = []
for src, dst in qt_bins:
    key = (Path(dst).as_posix(), os.path.basename(src))
    if key in seen:
        continue
    seen.add(key)
    qt_bins_dedup.append((src, dst))

# ---- Copy essential Qt plugins (platforms/imageformats/styles)
plugins_pairs = []
try:
    from PyQt5.QtCore import QLibraryInfo
    def qpath(role):
        try:
            return QLibraryInfo.path(role)
        except Exception:
            return QLibraryInfo.location(role)
    plugins_dir = qpath(QLibraryInfo.PluginsPath)
    for sub in ('platforms', 'imageformats', 'styles'):
        src_dir = os.path.join(plugins_dir, sub)
        if os.path.isdir(src_dir):
            # Put under PyQt5/Qt/plugins/<sub> in the bundle
            plugins_pairs.append((src_dir, os.path.join('PyQt5', 'Qt', 'plugins', sub)))
except Exception:
    pass

a = Analysis(
    ['main.py'],
    pathex=['.'],

    # 🔴 IMPORTANT: place your node binary in Contents/MacOS
    binaries=[('alyncoin', 'MacOS')] + qt_bins_dedup,

    datas=[
        ('style.qss', '.'),
        ('logo.icns', '.'),
        ('logo.png', '.'),
        ('logo.ico', '.'),
        ('peer_tab.py', '.'),
        ('wallet_tab.py', '.'),
        ('send_tab.py', '.'),
        ('history_tab.py', '.'),
        ('miner_tab.py', '.'),
        ('dao_tab.py', '.'),
        ('stats_tab.py', '.'),
        ('nft_tab.py', '.'),
        ('swap_tab.py', '.'),
        ('rpc_client.py', '.'),
    ] + plugins_pairs,

    hiddenimports=QT_MODULES,
    hookspath=[],
    runtime_hooks=[],
    excludes=EXCLUDES,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='AlynCoin',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    icon='logo.icns',
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    name='AlynCoin'
)

app = BUNDLE(
    coll,
    name='AlynCoin.app',
    icon='logo.icns',
    bundle_identifier='com.alyncoin.wallet'
)
