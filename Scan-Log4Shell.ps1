# Log4Shell YARA Scanner for Windows
# Optimized for specific file extensions to save scanning time

param(
    [string]$ScanPath = (Get-Location).Path,
    [string]$YaraPath = "yara64.exe",
    [string]$RulesPath = "$PSScriptRoot\detection-rules",
    [switch]$QuickScan,
    [switch]$DeepScan,
    [switch]$ExportResults
)

Write-Host "=====================================" -ForegroundColor Cyan
Write-Host "Log4Shell YARA Scanner for Windows" -ForegroundColor Cyan
Write-Host "=====================================" -ForegroundColor Cyan
Write-Host ""

# Check if YARA is available
try {
    $null = Get-Command $YaraPath -ErrorAction Stop
} catch {
    Write-Host "[ERROR] YARA not found. Please install YARA first." -ForegroundColor Red
    Write-Host "Download from: https://github.com/virustotal/yara/releases" -ForegroundColor Yellow
    Write-Host "Or install with: winget install VirusTotal.Yara" -ForegroundColor Yellow
    exit 1
}

# Define file extensions by priority
$QuickExtensions = @(
    "*.log",
    "*.txt",
    "*.out",
    "*.err",
    "*.json",
    "*.xml"
)

$WebExtensions = @(
    "*.jsp",
    "*.jspx",
    "*.html",
    "*.htm",
    "*.aspx",
    "*.asp"
)

$JavaExtensions = @(
    "*.jar",
    "*.war",
    "*.ear",
    "*.class",
    "*.properties",
    "*.java"
)

$MemoryExtensions = @(
    "*.dmp",
    "*.mdmp",
    "*.hdmp"
)

# Build extension list based on scan type
if ($QuickScan) {
    Write-Host "[Mode] Quick Scan - Log files only" -ForegroundColor Green
    $Extensions = $QuickExtensions
} elseif ($DeepScan) {
    Write-Host "[Mode] Deep Scan - All file types" -ForegroundColor Yellow
    $Extensions = $QuickExtensions + $WebExtensions + $JavaExtensions + $MemoryExtensions
} else {
    Write-Host "[Mode] Standard Scan - Logs and Java files" -ForegroundColor Green
    $Extensions = $QuickExtensions + $JavaExtensions
}

Write-Host "Scan Path: $ScanPath" -ForegroundColor Gray
Write-Host "Extensions: $($Extensions -join ', ')" -ForegroundColor Gray
Write-Host ""

# Collect files to scan
Write-Host "[*] Collecting files..." -ForegroundColor Cyan
$FilesToScan = @()

foreach ($ext in $Extensions) {
    $files = Get-ChildItem -Path $ScanPath -Filter $ext -Recurse -ErrorAction SilentlyContinue
    $FilesToScan += $files
    if ($files.Count -gt 0) {
        Write-Host "  Found $($files.Count) $ext files" -ForegroundColor Gray
    }
}

# Add common log directories on Windows
$LogDirectories = @(
    "C:\inetpub\logs\LogFiles",
    "C:\Windows\System32\LogFiles",
    "C:\ProgramData\Apache*\logs",
    "C:\ProgramData\nginx\logs",
    "C:\Program Files\Apache*\logs",
    "C:\Program Files (x86)\Apache*\logs",
    "$env:TEMP",
    "$env:USERPROFILE\AppData\Local\Temp"
)

foreach ($dir in $LogDirectories) {
    if (Test-Path $dir) {
        Write-Host "  Checking log directory: $dir" -ForegroundColor Gray
        $logFiles = Get-ChildItem -Path $dir -Recurse -ErrorAction SilentlyContinue |
                    Where-Object { !$_.PSIsContainer }
        $FilesToScan += $logFiles
    }
}

$TotalFiles = $FilesToScan.Count
Write-Host ""
Write-Host "[*] Total files to scan: $TotalFiles" -ForegroundColor Cyan
Write-Host ""

if ($TotalFiles -eq 0) {
    Write-Host "[WARNING] No files found to scan!" -ForegroundColor Yellow
    exit 0
}

# Prepare output
$Results = @()
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"

# Run YARA scans
$RuleFiles = @(
    "$RulesPath\log4shell.yar",
    "$RulesPath\log4shell-enhanced.yar"
)

foreach ($ruleFile in $RuleFiles) {
    if (Test-Path $ruleFile) {
        $ruleName = (Get-Item $ruleFile).BaseName
        Write-Host "[*] Scanning with $ruleName rules..." -ForegroundColor Cyan

        # Create temporary file list
        $tempFile = "$env:TEMP\yara_files_$([System.Guid]::NewGuid()).txt"
        $FilesToScan.FullName | Out-File -FilePath $tempFile -Encoding UTF8

        # Run YARA
        try {
            $yaraOutput = & $YaraPath -r $ruleFile $tempFile 2>&1

            if ($yaraOutput) {
                Write-Host "[!] DETECTIONS FOUND:" -ForegroundColor Red
                $yaraOutput | ForEach-Object {
                    Write-Host "  $_" -ForegroundColor Yellow
                    $Results += $_
                }
            } else {
                Write-Host "  No detections" -ForegroundColor Green
            }
        } catch {
            Write-Host "[ERROR] Failed to run YARA: $_" -ForegroundColor Red
        }

        # Cleanup
        Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
    } else {
        Write-Host "[WARNING] Rule file not found: $ruleFile" -ForegroundColor Yellow
    }
    Write-Host ""
}

# Export results if requested
if ($ExportResults -and $Results.Count -gt 0) {
    $OutputFile = "$PSScriptRoot\yara_results_$Timestamp.txt"
    $Results | Out-File -FilePath $OutputFile -Encoding UTF8
    Write-Host "[*] Results exported to: $OutputFile" -ForegroundColor Green
}

# Summary
Write-Host "=====================================" -ForegroundColor Cyan
Write-Host "Scan Summary" -ForegroundColor Cyan
Write-Host "=====================================" -ForegroundColor Cyan
Write-Host "Files Scanned: $TotalFiles"
Write-Host "Detections: $($Results.Count)"

if ($Results.Count -gt 0) {
    Write-Host ""
    Write-Host "[!] Log4Shell indicators detected! Review the results above." -ForegroundColor Red
    Write-Host ""
    Write-Host "Recommended Actions:" -ForegroundColor Yellow
    Write-Host "1. Update Log4j to version 2.17.1 or later" -ForegroundColor Yellow
    Write-Host "2. Remove JndiLookup.class from log4j-core JAR files" -ForegroundColor Yellow
    Write-Host "3. Set system property: -Dlog4j2.formatMsgNoLookups=true" -ForegroundColor Yellow
    Write-Host "4. Review detected files for exploitation attempts" -ForegroundColor Yellow
} else {
    Write-Host ""
    Write-Host "[✓] No Log4Shell indicators detected" -ForegroundColor Green
}

Write-Host ""
Write-Host "For deeper analysis, run:" -ForegroundColor Gray
Write-Host "  .\Scan-Log4Shell.ps1 -DeepScan -ExportResults" -ForegroundColor Gray
Write-Host ""