# -*- mode: python ; coding: utf-8 -*-

import os
from PyInstaller.utils.hooks import collect_all

datas, binaries, hiddenimports = [], [], []

# Pull in everything PyQt5 needs; dnspython is optional
for pkg in ("PyQt5",):
    da, bi, hi = collect_all(pkg)
    datas += da
    binaries += bi
    hiddenimports += hi

# Try to include 'dns' (dnspython) if installed
try:
    da, bi, hi = collect_all("dns")
    datas += da
    binaries += bi
    hiddenimports += hi
except Exception:
    pass

def add_data_if_exists(path, dest="."):
    if os.path.exists(path):
        datas.append((path, dest))

def add_dir_if_exists(path, dest):
    if os.path.isdir(path):
        datas.append((path, dest))

def add_bin_if_exists(path, dest="bin"):
    if os.path.exists(path):
        binaries.append((path, dest))

# Common assets
add_data_if_exists("logo.png", ".")
add_data_if_exists("style.qss", ".")
add_dir_if_exists("assets", "assets")

# Bundle alyncoin node if found in common places (works cross-platform)
for cand in [
    os.path.join("..", "build", "Release", "alyncoin.exe"),
    os.path.join("..", "build", "alyncoin"),
    os.path.join("bin", "alyncoin"),
    os.path.join("bin", "alyncoin.exe"),
    "alyncoin",
    "alyncoin.exe",
]:
    add_bin_if_exists(cand, "bin")

block_cipher = None

a = Analysis(
    ['main.py'],
    pathex=['.'],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe_kwargs = dict(
    name='AlynCoin',
    console=False,   # GUI app
)
if os.path.exists('logo.ico'):
    exe_kwargs['icon'] = 'logo.ico'

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    **exe_kwargs
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    name='AlynCoin'
)
