<#
.SYNOPSIS
    VulnFlow launcher and automation orchestrator for Windows PowerShell.
.DESCRIPTION
    Launches VulnFlow autonomous remediation engine, local development servers,
    or runs security scans directly from PowerShell.
.EXAMPLE
    .\run.ps1
    .\run.ps1 scan --repo fake-vuln-repo --mode report
    .\run.ps1 serve
    .\run.ps1 install
#>
[CmdletBinding()]
param(
    [Parameter(Position=0)]
    [string]$Action = "",
    [Parameter(ValueFromRemainingArguments=$true)]
    [string[]]$RemainingArgs
)

if (-not $Action) {
    # Determine script root
    $ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
    $VulnFlowRoot = $ScriptDir
    if (Test-Path (Join-Path $VulnFlowRoot "vulnflow")) {
        $VulnFlowRoot = Join-Path $VulnFlowRoot "vulnflow"
    }
    $PythonExe = if (Get-Command python -ErrorAction SilentlyContinue) { "python" } elseif (Get-Command py -ErrorAction SilentlyContinue) { "py" } else { "python3" }
    $Env:PYTHONPATH = "$(Join-Path $VulnFlowRoot 'src');$VulnFlowRoot;$($Env:PYTHONPATH)"
    & $PythonExe (Join-Path $VulnFlowRoot "src\vulnflow\cli.py")
    exit 0
}

$ErrorActionPreference = "Stop"

# Determine script root
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$VulnFlowRoot = $ScriptDir
if (Test-Path (Join-Path $VulnFlowRoot "vulnflow")) {
    $VulnFlowRoot = Join-Path $VulnFlowRoot "vulnflow"
}

# Preserve caller working directory
$CallerDir = (Get-Location).Path

# Detect Python interpreter (prefer python, fallback to py or python3)
$PythonExe = $null
if (Get-Command python -ErrorAction SilentlyContinue) {
    $PythonExe = "python"
} elseif (Get-Command py -ErrorAction SilentlyContinue) {
    $PythonExe = "py"
} elseif (Get-Command python3 -ErrorAction SilentlyContinue) {
    $PythonExe = "python3"
} else {
    Write-Error "Python 3.11+ is required but was not found in PATH. Please install Python from https://python.org."
    exit 1
}

# Setup PYTHONPATH
$SrcDir = Join-Path $VulnFlowRoot "src"
$Env:PYTHONPATH = "$SrcDir;$VulnFlowRoot;$($Env:PYTHONPATH)"

# Banner
function Show-Banner {
    Write-Host "====================================================================" -ForegroundColor Cyan
    Write-Host "🛡️   VulnFlow AI - Autonomous Security Remediation Platform" -ForegroundColor Cyan
    Write-Host "====================================================================" -ForegroundColor Cyan
}

# Build full argument list for CLI invocations
$AllArgs = @()
$BuiltinActions = @("serve", "dev", "build", "docker", "docker-compose", "compose", "install", "help", "-h", "--help")
if ($Action -and -not ($BuiltinActions -contains $Action.ToLower())) {
    $AllArgs += $Action
}
if ($RemainingArgs) {
    $AllArgs += $RemainingArgs
}

switch ($Action.ToLower()) {
    "serve" {
        Show-Banner
        $UiDist = Join-Path $VulnFlowRoot "ui\dist\index.html"
        if (-not (Test-Path $UiDist)) {
            Write-Host "📦 First-time run: Building frontend Web Dashboard..." -ForegroundColor Yellow
            Push-Location (Join-Path $VulnFlowRoot "ui")
            npm run build
            Pop-Location
            Write-Host "✅ Frontend built successfully.`n" -ForegroundColor Green
        }
        $CliScript = Join-Path $VulnFlowRoot "src\vulnflow\cli.py"
        & $PythonExe $CliScript serve --open @RemainingArgs
        break
    }
    "dev" {
        Show-Banner
        Write-Host "🚀 Starting in Development Mode (Vite HMR on :5173 + API on :8000)`n" -ForegroundColor Cyan
        $CliScript = Join-Path $VulnFlowRoot "src\vulnflow\cli.py"
        & $PythonExe $CliScript serve --dev @RemainingArgs
        break
    }
    "build" {
        Show-Banner
        Write-Host "📦 Building frontend UI bundle (Vite + React)..." -ForegroundColor Cyan
        Push-Location (Join-Path $VulnFlowRoot "ui")
        npm run build
        Pop-Location
        Write-Host "✅ Frontend build complete in ui/dist/" -ForegroundColor Green
        break
    }
    "docker" {
        Show-Banner
        Write-Host "🐳 Building and running VulnFlow Docker container..." -ForegroundColor Cyan
        docker build -t vulnflow:latest $VulnFlowRoot
        docker run --rm -it -p 8000:8000 -v "$VulnFlowRoot\.vulnflow:/app/.vulnflow" vulnflow:latest
        break
    }
    "docker-compose" {
        Show-Banner
        Write-Host "🐳 Launching with Docker Compose..." -ForegroundColor Cyan
        docker compose -f (Join-Path $VulnFlowRoot "docker-compose.yml") up --build
        break
    }
    "compose" {
        Show-Banner
        Write-Host "🐳 Launching with Docker Compose..." -ForegroundColor Cyan
        docker compose -f (Join-Path $VulnFlowRoot "docker-compose.yml") up --build
        break
    }
    "install" {
        Show-Banner
        $InstallDir = Join-Path $HOME ".local\bin"
        if (-not (Test-Path $InstallDir)) {
            New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
        }
        
        # Create vulnflow.cmd for CMD / PowerShell
        $CmdFile = Join-Path $InstallDir "vulnflow.cmd"
        $BatTarget = Join-Path $ScriptDir "run.bat"
        "@echo off`r`ncall `"$BatTarget`" %*" | Out-File -FilePath $CmdFile -Encoding ascii -Force

        # Create vulnflow.ps1 for PowerShell
        $Ps1File = Join-Path $InstallDir "vulnflow.ps1"
        $Ps1Target = Join-Path $ScriptDir "run.ps1"
        "& `"$Ps1Target`" `$args" | Out-File -FilePath $Ps1File -Encoding utf8 -Force

        Write-Host "✅ Successfully installed VulnFlow CLI wrappers to: $InstallDir" -ForegroundColor Green
        
        # Verify / Update user environment Path
        $UserPath = [Environment]::GetEnvironmentVariable("Path", "User")
        if ($UserPath -notlike "*$InstallDir*") {
            Write-Host "`nAdding $InstallDir to User PATH..." -ForegroundColor Cyan
            [Environment]::SetEnvironmentVariable("Path", "$UserPath;$InstallDir", "User")
            $Env:Path = "$Env:Path;$InstallDir"
            Write-Host "✅ Added $InstallDir to User PATH." -ForegroundColor Green
        }
        Write-Host "`nYou can now run 'vulnflow' directly from any PowerShell or CMD terminal!" -ForegroundColor Green
        Write-Host "Examples:"
        Write-Host "  vulnflow scan --repo fake-vuln-repo --mode report" -ForegroundColor Cyan
        Write-Host "  vulnflow serve" -ForegroundColor Cyan
        Write-Host "  vulnflow --help`n" -ForegroundColor Cyan
        break
    }
    { $_ -in @("help", "-h", "--help") } {
        Push-Location $CallerDir
        $CliScript = Join-Path $VulnFlowRoot "src\vulnflow\cli.py"
        & $PythonExe $CliScript --help
        Pop-Location
        break
    }
    default {
        # Pass directly to VulnFlow CLI from original caller directory
        Push-Location $CallerDir
        $CliScript = Join-Path $VulnFlowRoot "src\vulnflow\cli.py"
        & $PythonExe $CliScript @AllArgs
        Pop-Location
        break
    }
}
