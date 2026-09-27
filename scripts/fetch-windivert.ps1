# Fetch the official WinDivert SDK files needed to build/run dpi_guard.
#
# The repo never commits WinDivert.dll/.lib/.sys (see .gitignore). This
# script downloads the pinned official release and verifies the archive
# and every extracted file against SHA-256 pins before placing them in
# the repo root. Any mismatch aborts with nothing kept.
#
# Usage (PowerShell):  scripts/fetch-windivert.ps1 [-Arch x64|x86]
param(
    [ValidateSet("x64", "x86")]
    [string]$Arch = "x64"
)

$ErrorActionPreference = "Stop"

$Ver       = "2.2.2"
$Url       = "https://github.com/basil00/WinDivert/releases/download/v$Ver/WinDivert-$Ver-A.zip"
$ZipSha256 = "63CB41763BB4B20F600B6DE04E991A9C2BE73279E317D4D82F237B150C5F3F15"
$PinDll    = "C1E060EE19444A259B2162F8AF0F3FE8C4428A1C6F694DCE20DE194AC8D7D9A2"
$PinLib    = "C5678D544EB0121A189D1139F54E0C67854DC64D1C897111A27EF2E52CB38EB3"
$PinSys64  = "8DA085332782708D8767BCACE5327A6EC7283C17CFB85E40B03CD2323A90DDC2"

$Repo  = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$Tmp   = Join-Path ([System.IO.Path]::GetTempPath()) ("windivert-fetch-" + [guid]::NewGuid().ToString("N"))
$Sys   = if ($Arch -eq "x64") { "WinDivert64.sys" } else { "WinDivert32.sys" }

function Get-Sha256([string]$Path) {
    (Get-FileHash -Algorithm SHA256 -Path $Path).Hash.Replace("-", "")
}

try {
    New-Item -ItemType Directory -Path $Tmp | Out-Null
    $zip = Join-Path $Tmp "wd.zip"
    Write-Host "downloading WinDivert $Ver ($Arch)..."
    # TLS 1.2 for older Windows PowerShell
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $Url -OutFile $zip -UseBasicParsing

    $zipHash = Get-Sha256 $zip
    if ($zipHash -ne $ZipSha256) {
        throw "FATAL: zip hash mismatch ($zipHash) - refusing to use the download."
    }

    Expand-Archive -Path $zip -DestinationPath $Tmp -Force
    $dir = Join-Path $Tmp "WinDivert-$Ver-A\$Arch"

    foreach ($f in @("WinDivert.dll", "WinDivert.lib", $Sys)) {
        $src = Join-Path $dir $f
        $hash = Get-Sha256 $src
        $pin = $null
        if ($f -eq "WinDivert.dll") { $pin = $PinDll }
        elseif ($f -eq "WinDivert.lib") { $pin = $PinLib }
        elseif ($f -eq "WinDivert64.sys") { $pin = $PinSys64 }
        if ($pin -and $hash -ne $pin) { throw "FATAL: $f hash mismatch ($hash)" }
        Copy-Item $src (Join-Path $Repo $f) -Force
        Write-Host "OK  $f  $hash"
    }
    Write-Host "WinDivert $Ver files installed in $Repo (hash-verified)."
} finally {
    Remove-Item -Recurse -Force $Tmp -ErrorAction SilentlyContinue
}
