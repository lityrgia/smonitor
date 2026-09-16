[CmdletBinding()]
param(
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Release",

    [switch]$Clean
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repoRoot = $PSScriptRoot
$targetTriple = "x86_64-pc-windows-msvc"
$cargoProfileName = if ($Configuration -eq "Release") { "release" } else { "debug" }

function Find-VsWhere {
    $command = Get-Command "vswhere.exe" -ErrorAction SilentlyContinue
    if ($command) {
        return $command.Source
    }

    $installerRoot = ${env:ProgramFiles(x86)}
    if ($installerRoot) {
        $candidate = Join-Path $installerRoot "Microsoft Visual Studio\Installer\vswhere.exe"
        if (Test-Path -LiteralPath $candidate) {
            return $candidate
        }
    }

    throw "vswhere.exe was not found. Install Visual Studio 2022 with Desktop development with C++."
}

function Enter-BuildEnvironment {
    $vsWhere = Find-VsWhere
    $vsInstallPath = & $vsWhere `
        -latest `
        -products "*" `
        -requires "Microsoft.VisualStudio.Component.VC.Tools.x86.x64" `
        -property installationPath

    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($vsInstallPath)) {
        throw "Visual Studio 2022 C++ tools were not found."
    }

    $devShellModule = Join-Path $vsInstallPath "Common7\Tools\Microsoft.VisualStudio.DevShell.dll"
    if (-not (Test-Path -LiteralPath $devShellModule)) {
        throw "Visual Studio developer shell was not found at '$devShellModule'."
    }

    Import-Module $devShellModule | Out-Null
    Enter-VsDevShell `
        -VsInstallPath $vsInstallPath `
        -SkipAutomaticLocation `
        -DevCmdArguments "-no_logo -arch=x64 -host_arch=x64" | Out-Null

    $msBuildPath = Join-Path $vsInstallPath "MSBuild\Current\Bin\MSBuild.exe"
    if (-not (Test-Path -LiteralPath $msBuildPath)) {
        throw "MSBuild.exe was not found at '$msBuildPath'."
    }

    return $msBuildPath
}

function Require-Command([string]$Name, [string]$InstallHint) {
    if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
        throw "'$Name' was not found. $InstallHint"
    }
}

$msBuild = Enter-BuildEnvironment
Require-Command "cargo.exe" "Install Rust from https://rustup.rs/."
Require-Command "rustup.exe" "Install Rust from https://rustup.rs/."

$installedTargets = @(& rustup target list --installed)
if ($LASTEXITCODE -ne 0 -or $installedTargets -notcontains $targetTriple) {
    throw "Rust target '$targetTriple' is missing. Run: rustup target add $targetTriple"
}

$driverSolution = Join-Path $repoRoot "driver\etw_hook.sln"
$msBuildTargets = if ($Clean) { "Clean;Build" } else { "Build" }
$msBuildArguments = @(
    $driverSolution,
    "/m",
    "/nologo",
    "/t:$msBuildTargets",
    "/p:Configuration=$Configuration",
    "/p:Platform=x64",
    "/p:SignMode=Off"
)

Write-Host "Building swatcher.sys ($Configuration)..."
& $msBuild @msBuildArguments
if ($LASTEXITCODE -ne 0) {
    throw "Driver build failed with exit code $LASTEXITCODE."
}

$cargoArguments = @(
    "build",
    "--locked",
    "--manifest-path", (Join-Path $repoRoot "Cargo.toml"),
    "--target", $targetTriple
)
if ($Configuration -eq "Release") {
    $cargoArguments += "--release"
}

if ($Clean) {
    & cargo clean --manifest-path (Join-Path $repoRoot "Cargo.toml") --target $targetTriple
    if ($LASTEXITCODE -ne 0) {
        throw "Cargo clean failed with exit code $LASTEXITCODE."
    }
}

Write-Host "Building smonitor.exe ($Configuration)..."
& cargo @cargoArguments
if ($LASTEXITCODE -ne 0) {
    throw "GUI build failed with exit code $LASTEXITCODE."
}

$driverSource = Join-Path $repoRoot "driver\outputs\x64\$Configuration\swatcher.sys"
$guiSource = Join-Path $repoRoot "target\$targetTriple\$cargoProfileName\smonitor.exe"
$distDirectory = Join-Path $repoRoot "dist"

foreach ($artifact in @($driverSource, $guiSource)) {
    if (-not (Test-Path -LiteralPath $artifact)) {
        throw "Expected build artifact was not produced: $artifact"
    }
}

New-Item -ItemType Directory -Path $distDirectory -Force | Out-Null
Copy-Item -LiteralPath $driverSource -Destination (Join-Path $distDirectory "swatcher.sys") -Force
Copy-Item -LiteralPath $guiSource -Destination (Join-Path $distDirectory "smonitor.exe") -Force
$filterExampleDestination = Join-Path $distDirectory "filters.example.json"
if (-not (Test-Path -LiteralPath $filterExampleDestination)) {
    Copy-Item -LiteralPath (Join-Path $repoRoot "filters.example.json") `
        -Destination $filterExampleDestination
}
$filterDestination = Join-Path $distDirectory "filters.json"
if (-not (Test-Path -LiteralPath $filterDestination)) {
    Copy-Item -LiteralPath (Join-Path $repoRoot "filters.example.json") `
        -Destination $filterDestination
}

Write-Host "Built artifacts:"
@(
    Get-Item (Join-Path $distDirectory "smonitor.exe")
    Get-Item (Join-Path $distDirectory "swatcher.sys")
    Get-Item $filterExampleDestination
    Get-Item $filterDestination
) | Select-Object Name, Length, LastWriteTime
