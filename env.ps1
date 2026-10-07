# Dev shell setup for the GNU toolchain on this machine (no MSVC Build Tools).
# Usage: . .\env.ps1
$mingw = Get-ChildItem "$env:LOCALAPPDATA\Microsoft\WinGet\Packages" -Directory -Filter "BrechtSanders.WinLibs*" -ErrorAction SilentlyContinue | Select-Object -First 1
if ($mingw) { $env:PATH = (Join-Path $mingw.FullName "mingw64\bin") + ";" + $env:PATH }
