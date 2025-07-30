# NetSecureX Installation Script for Windows PowerShell
# ===================================================

param(
    [switch]$Force,
    [string]$InstallPath = "$env:ProgramFiles\NetSecureX",
    [switch]$NoDesktopShortcut,
    [switch]$NoStartMenu
)

# Set execution policy for this session
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force

# Configuration
$RepoUrl = "https://github.com/netsecurex/netsecurex"
$PythonMinVersion = [Version]"3.8.0"
$RequiredModules = @(
    "click>=8.0.0",
    "rich>=13.0.0", 
    "requests>=2.31.0",
    "aiohttp>=3.8.0",
    "cryptography>=41.0.0",
    "python-dotenv>=1.0.0",
    "netaddr>=0.8.0",
    "tabulate>=0.9.0",
    "python-dateutil>=2.8.0",
    "pywin32>=227"
)

# Functions
function Write-Header {
    Write-Host ""
    Write-Host "╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Blue
    Write-Host "║                    NetSecureX Installer                     ║" -ForegroundColor Blue
    Write-Host "║              Unified Cybersecurity Toolkit                  ║" -ForegroundColor Blue
    Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Blue
    Write-Host ""
}

function Write-Step {
    param([string]$Message)
    Write-Host "[INFO] $Message" -ForegroundColor Blue
}

function Write-Success {
    param([string]$Message)
    Write-Host "[SUCCESS] $Message" -ForegroundColor Green
}

function Write-Warning {
    param([string]$Message)
    Write-Host "[WARNING] $Message" -ForegroundColor Yellow
}

function Write-Error {
    param([string]$Message)
    Write-Host "[ERROR] $Message" -ForegroundColor Red
}

function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-Python {
    Write-Step "Checking Python installation..."
    
    $pythonCommands = @("python", "python3", "py")
    $pythonCmd = $null
    
    foreach ($cmd in $pythonCommands) {
        try {
            $version = & $cmd --version 2>$null
            if ($version -match "Python (\d+\.\d+\.\d+)") {
                $pythonVersion = [Version]$matches[1]
                if ($pythonVersion -ge $PythonMinVersion) {
                    $pythonCmd = $cmd
                    Write-Success "Python $pythonVersion found using '$cmd'"
                    break
                }
            }
        }
        catch {
            continue
        }
    }
    
    if (-not $pythonCmd) {
        Write-Error "Python $PythonMinVersion or later is required but not found."
        Write-Host "Please install Python from https://python.org/downloads/" -ForegroundColor Yellow
        exit 1
    }
    
    return $pythonCmd
}

function Install-PythonDependencies {
    param([string]$PythonCmd)
    
    Write-Step "Installing Python dependencies..."
    
    # Upgrade pip
    & $PythonCmd -m pip install --upgrade pip
    
    # Install dependencies
    foreach ($module in $RequiredModules) {
        Write-Host "  Installing $module..." -ForegroundColor Gray
        & $PythonCmd -m pip install $module
        if ($LASTEXITCODE -ne 0) {
            Write-Warning "Failed to install $module"
        }
    }
    
    Write-Success "Python dependencies installed"
}

function Download-NetSecureX {
    Write-Step "Downloading NetSecureX..."
    
    $tempDir = New-TemporaryFile | ForEach-Object { Remove-Item $_; New-Item -ItemType Directory -Path $_ }
    $zipPath = Join-Path $tempDir "netsecurex.zip"
    
    try {
        # Download ZIP archive
        $downloadUrl = "$RepoUrl/archive/main.zip"
        Invoke-WebRequest -Uri $downloadUrl -OutFile $zipPath -UseBasicParsing
        
        # Extract ZIP
        Expand-Archive -Path $zipPath -DestinationPath $tempDir -Force
        
        $extractedDir = Join-Path $tempDir "netsecurex-main"
        Write-Success "NetSecureX downloaded to $extractedDir"
        
        return $extractedDir
    }
    catch {
        Write-Error "Failed to download NetSecureX: $($_.Exception.Message)"
        exit 1
    }
}

function Install-NetSecureX {
    param([string]$SourcePath, [string]$DestinationPath)
    
    Write-Step "Installing NetSecureX to $DestinationPath..."
    
    # Create installation directory
    if (Test-Path $DestinationPath) {
        if (-not $Force) {
            $response = Read-Host "Installation directory exists. Overwrite? (y/N)"
            if ($response -ne "y" -and $response -ne "Y") {
                Write-Host "Installation cancelled."
                exit 0
            }
        }
        Remove-Item $DestinationPath -Recurse -Force
    }
    
    New-Item -ItemType Directory -Path $DestinationPath -Force | Out-Null
    
    # Copy files
    Copy-Item -Path "$SourcePath\*" -Destination $DestinationPath -Recurse -Force
    
    Write-Success "NetSecureX installed to $DestinationPath"
}

function Add-ToPath {
    param([string]$InstallPath)
    
    Write-Step "Adding NetSecureX to PATH..."
    
    $currentPath = [Environment]::GetEnvironmentVariable("PATH", "Machine")
    if ($currentPath -notlike "*$InstallPath*") {
        $newPath = "$currentPath;$InstallPath"
        [Environment]::SetEnvironmentVariable("PATH", $newPath, "Machine")
        Write-Success "Added to system PATH"
    } else {
        Write-Success "Already in system PATH"
    }
}

function Create-BatchFiles {
    param([string]$InstallPath)
    
    Write-Step "Creating batch files..."
    
    # Create netsecurex.bat
    $batchContent = @"
@echo off
python "$InstallPath\main.py" %*
"@
    $batchPath = Join-Path $InstallPath "netsecurex.bat"
    Set-Content -Path $batchPath -Value $batchContent
    
    # Create nsx.bat (short alias)
    $shortBatchPath = Join-Path $InstallPath "nsx.bat"
    Set-Content -Path $shortBatchPath -Value $batchContent
    
    Write-Success "Batch files created"
}

function Create-StartMenuShortcut {
    param([string]$InstallPath)
    
    if ($NoStartMenu) {
        return
    }
    
    Write-Step "Creating Start Menu shortcut..."
    
    $startMenuPath = "$env:ProgramData\Microsoft\Windows\Start Menu\Programs"
    $shortcutPath = Join-Path $startMenuPath "NetSecureX.lnk"
    
    $WshShell = New-Object -comObject WScript.Shell
    $Shortcut = $WshShell.CreateShortcut($shortcutPath)
    $Shortcut.TargetPath = "cmd.exe"
    $Shortcut.Arguments = "/k `"cd /d `"$InstallPath`" && netsecurex --help`""
    $Shortcut.WorkingDirectory = $InstallPath
    $Shortcut.Description = "NetSecureX Cybersecurity Toolkit"
    $Shortcut.Save()
    
    Write-Success "Start Menu shortcut created"
}

function Create-DesktopShortcut {
    param([string]$InstallPath)
    
    if ($NoDesktopShortcut) {
        return
    }
    
    Write-Step "Creating Desktop shortcut..."
    
    $desktopPath = [Environment]::GetFolderPath("Desktop")
    $shortcutPath = Join-Path $desktopPath "NetSecureX.lnk"
    
    $WshShell = New-Object -comObject WScript.Shell
    $Shortcut = $WshShell.CreateShortcut($shortcutPath)
    $Shortcut.TargetPath = "cmd.exe"
    $Shortcut.Arguments = "/k `"cd /d `"$InstallPath`" && netsecurex --help`""
    $Shortcut.WorkingDirectory = $InstallPath
    $Shortcut.Description = "NetSecureX Cybersecurity Toolkit"
    $Shortcut.Save()
    
    Write-Success "Desktop shortcut created"
}

function Setup-Environment {
    param([string]$InstallPath)
    
    Write-Step "Setting up environment..."
    
    # Create .env.example
    $envExample = Join-Path $InstallPath ".env.example"
    $envContent = @"
# NetSecureX API Keys Configuration
# Copy this file to .env and add your actual API keys

# AbuseIPDB API Key
ABUSEIPDB_API_KEY=your_abuseipdb_api_key_here

# IPQualityScore API Key  
IPQUALITYSCORE_API_KEY=your_ipqualityscore_api_key_here

# VirusTotal API Key
VIRUSTOTAL_API_KEY=your_virustotal_api_key_here

# Vulners API Key
VULNERS_API_KEY=your_vulners_api_key_here
"@
    
    Set-Content -Path $envExample -Value $envContent
    
    Write-Success "Environment setup completed"
}

function Show-CompletionMessage {
    param([string]$InstallPath)
    
    Write-Host ""
    Write-Success "NetSecureX installation completed successfully!"
    Write-Host ""
    Write-Host "Usage:" -ForegroundColor Green
    Write-Host "  netsecurex --help          # Show help"
    Write-Host "  netsecurex version         # Show version"
    Write-Host "  netsecurex scan --help     # Port scanning"
    Write-Host "  netsecurex cert --help     # Certificate analysis"
    Write-Host "  netsecurex cve --help      # CVE lookup"
    Write-Host "  netsecurex iprep --help    # IP reputation"
    Write-Host ""
    Write-Host "Configuration:" -ForegroundColor Yellow
    Write-Host "  Edit $InstallPath\.env to add API keys"
    Write-Host ""
    Write-Host "Documentation:" -ForegroundColor Blue
    Write-Host "  https://docs.netsecurex.dev"
    Write-Host ""
    Write-Host "Note: You may need to restart your command prompt for PATH changes to take effect." -ForegroundColor Yellow
}

# Main installation process
function Main {
    Write-Header
    
    Write-Step "Starting NetSecureX installation..."
    
    # Check administrator privileges
    if (-not (Test-Administrator)) {
        Write-Warning "Running without administrator privileges. Some features may not work correctly."
        $response = Read-Host "Continue anyway? (y/N)"
        if ($response -ne "y" -and $response -ne "Y") {
            exit 0
        }
    }
    
    # Check Python
    $pythonCmd = Test-Python
    
    # Install Python dependencies
    Install-PythonDependencies -PythonCmd $pythonCmd
    
    # Download NetSecureX
    $sourcePath = Download-NetSecureX
    
    # Install NetSecureX
    Install-NetSecureX -SourcePath $sourcePath -DestinationPath $InstallPath
    
    # Add to PATH
    if (Test-Administrator) {
        Add-ToPath -InstallPath $InstallPath
    }
    
    # Create batch files
    Create-BatchFiles -InstallPath $InstallPath
    
    # Create shortcuts
    Create-StartMenuShortcut -InstallPath $InstallPath
    Create-DesktopShortcut -InstallPath $InstallPath
    
    # Setup environment
    Setup-Environment -InstallPath $InstallPath
    
    # Cleanup
    Remove-Item $sourcePath -Recurse -Force
    
    # Show completion message
    Show-CompletionMessage -InstallPath $InstallPath
}

# Run main function
try {
    Main
}
catch {
    Write-Error "Installation failed: $($_.Exception.Message)"
    exit 1
}
