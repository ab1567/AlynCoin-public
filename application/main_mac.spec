# main.spec — PyQt5 minimal; bundle `alyncoin` in MacOS *and* Resources; certifi bundled
block_cipher = None

import os
from pathlib import Path
from PyInstaller.utils.hooks import collect_dynamic_libs, collect_data_files

QT_MODULES = [
    'PyQt5', 'PyQt5.QtCore', 'PyQt5.QtGui', 'PyQt5.QtWidgets',
    'PyQt5.QtNetwork', 'PyQt5.QtPrintSupport',
]

EXCLUDES = [
    'PyQt5.QtQml', 'PyQt5.QtQuick', 'PyQt5.QtQuickWidgets',
    'PyQt5.QtQuick3D', 'PyQt5.Qt3DCore', 'PyQt5.Qt3DRender',
    'PyQt5.Qt3DInput', 'PyQt5.QtBluetooth', 'PyQt5.QtPositioning',
]

# Collect only required Qt dylibs
qt_bins = []
for mod in QT_MODULES[1:]:
    for src, dst in collect_dynamic_libs(mod):
        if any(x in src for x in ('Qt3D', 'Bluetooth', 'Positioning', 'Qml', 'Quick')):
            continue
        qt_bins.append((src, dst))

# De-dup to avoid symlink collisions
seen = set()
qt_bins_dedup = []
for src, dst in qt_bins:
    key = (Path(dst).as_posix(), os.path.basename(src))
    if key in seen:
        continue
    seen.add(key)
    qt_bins_dedup.append((src, dst))

# Essential plugins (skip qpdf to avoid QtPdf warning)
plugins_pairs = []
try:
    from PyQt5.QtCore import QLibraryInfo
    def qpath(role):
        try:
            return QLibraryInfo.path(role)
        except Exception:
            return QLibraryInfo.location(role)

    plugins_dir = qpath(QLibraryInfo.PluginsPath)

    plat_dir = os.path.join(plugins_dir, 'platforms')
    if os.path.isdir(plat_dir):
        plugins_pairs.append((plat_dir, os.path.join('PyQt5','Qt','plugins','platforms')))

    styles_dir = os.path.join(plugins_dir, 'styles')
    if os.path.isdir(styles_dir):
        plugins_pairs.append((styles_dir, os.path.join('PyQt5','Qt','plugins','styles')))

    img_dir = os.path.join(plugins_dir, 'imageformats')
    img_dst = os.path.join('PyQt5','Qt','plugins','imageformats')
    for fname in ('libqjpeg.dylib','libqico.dylib','libqsvg.dylib','libqtiff.dylib','libqgif.dylib','libqicns.dylib'):
        src = os.path.join(img_dir, fname)
        if os.path.isfile(src):
            plugins_pairs.append((src, img_dst))
except Exception:
    pass

# Bundle CA bundle for requests
certifi_datas = collect_data_files('certifi')

a = Analysis(
    ['main.py'],
    pathex=['.'],

    # Put node into Contents/MacOS (primary)
    binaries=[(os.path.abspath('alyncoin'), 'MacOS')] + qt_bins_dedup,

    # Also copy into Resources so resource_path('alyncoin') works too
    datas=[
        (os.path.abspath('alyncoin'), '.'),  # -> Contents/Resources/alyncoin
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
    ] + plugins_pairs + certifi_datas,

    hiddenimports=[
        'PyQt5','PyQt5.sip',
        'PyQt5.QtCore','PyQt5.QtGui','PyQt5.QtWidgets',
        'PyQt5.QtNetwork','PyQt5.QtPrintSupport',
        'requests','urllib3','idna','charset_normalizer','certifi',
        'sip',  # quiets rare "Hidden import 'sip' not found!" logs
    ],
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
