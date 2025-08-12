$ErrorActionPreference = "Stop"

# --- Paths ---
$Root       = (Resolve-Path "$PSScriptRoot\..").Path
$VcpkgRoot  = Join-Path $Root "vcpkg"
$Installed  = Join-Path $VcpkgRoot "installed\x64-windows-static"
$BuildDir   = Join-Path $Root "dist\cli\build"
$OutDir     = Join-Path $Root "dist\cli\Release"

# --- VS toolchain sanity (optional) ---
if (-not (Get-Command cl.exe -ErrorAction SilentlyContinue)) {
  Write-Warning "MSVC not detected in this shell. Use 'x64 Native Tools Command Prompt for VS 2022'."
}

# --- vcpkg checkout/bootstrap ---
if (!(Test-Path $VcpkgRoot)) {
  git clone https://github.com/microsoft/vcpkg $VcpkgRoot
}
& "$VcpkgRoot\bootstrap-vcpkg.bat"

# --- Install from THIS folder's manifest (windows\vcpkg.json) ---
$env:VCPKG_FEATURE_FLAGS   = "manifests,binarycaching"
$env:VCPKG_DEFAULT_TRIPLET = "x64-windows-static"
& "$VcpkgRoot\vcpkg.exe" install --triplet x64-windows-static --x-manifest-root "$PSScriptRoot"

# --- Clean build dir (avoid generator/cache mismatches) ---
if (Test-Path $BuildDir) { Remove-Item -Recurse -Force $BuildDir }

# --- Generator ---
$genArgs = @("-G", "Visual Studio 17 2022", "-A", "x64")

# --- Configure (repo root) ---
cmake -S "$Root" -B "$BuildDir" @genArgs `
  -DCMAKE_BUILD_TYPE=Release `
  -DCMAKE_TOOLCHAIN_FILE="$VcpkgRoot\scripts\buildsystems\vcpkg.cmake" `
  -DVCPKG_TARGET_TRIPLET=x64-windows-static `
  -DCMAKE_POLICY_DEFAULT_CMP0091=NEW `
  -DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded `
  -DCMAKE_FIND_PACKAGE_PREFER_CONFIG=ON `
  -DOPENSSL_USE_STATIC_LIBS=ON `
  -DProtobuf_USE_STATIC_LIBS=ON `
  -DOPENSSL_ROOT_DIR="$Installed" `
  -DOPENSSL_INCLUDE_DIR="$Installed\include" `
  -DOPENSSL_CRYPTO_LIBRARY="$Installed\lib\libcrypto.lib" `
  -DOPENSSL_SSL_LIBRARY="$Installed\lib\libssl.lib" `
  -Dprotobuf_DIR="$Installed\share\protobuf" `
  -Djsoncpp_DIR="$Installed\share\jsoncpp"

# --- Build ---
cmake --build "$BuildDir" --config Release --parallel --target alyncoin

# --- Stage exe(s) ---
New-Item -ItemType Directory -Force -Path "$OutDir" | Out-Null

# Prefer copying all our CLIs if present
$targets = @(
  "alyncoin.exe"
)

$found = $false
foreach ($name in $targets) {
  $p1 = Join-Path $BuildDir $name
  $p2 = Join-Path $BuildDir ("Release\" + $name)
  if (Test-Path $p1) {
    Copy-Item $p1 (Join-Path $OutDir $name) -Force
    $found = $true
  } elseif (Test-Path $p2) {
    Copy-Item $p2 (Join-Path $OutDir $name) -Force
    $found = $true
  }
}

if (-not $found) {
  throw "No CLI exe found in $BuildDir (looked for: $($targets -join ', '))"
}

Write-Host "✅ Binaries staged at $OutDir"
