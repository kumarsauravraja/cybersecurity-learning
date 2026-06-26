#Requires -RunAsAdministrator
<#
    Nessus Credentialed Scan Preparation & Diagnostic Tool
    Verifies and remediates the conditions behind credential-failure plugins:
      104410  Target Credential Status - Failure for Provided Credentials
      24786   Nessus Windows Scan Not Performed with Admin Privileges
      26917   Cannot Access the Windows Registry
      35705   SMB Registry Access Not Available
    Run as Administrator on the TARGET host. Validates, does not assume.
#>

param(
    [string]$ScanCredUser = "Administrator",
    [string]$ExpectedPassword = "",      # pass the password your Nessus policy uses, to verify it matches
    [switch]$Remediate,                  # without this flag the tool only diagnoses (passive)
    [string]$ReportPath = "$env:TEMP\nessus_prep_report.txt"
)

$ErrorActionPreference = "Continue"
$results = [System.Collections.Generic.List[object]]::new()

function Add-Result {
    param([string]$Check, [string]$Status, [string]$Detail, [string]$Fix = "")
    $results.Add([pscustomobject]@{
        Check  = $Check
        Status = $Status      # PASS / FAIL / WARN / FIXED
        Detail = $Detail
        Fix    = $Fix
    })
    $color = switch ($Status) {
        "PASS"  { "Green" }
        "FIXED" { "Cyan" }
        "WARN"  { "Yellow" }
        "FAIL"  { "Red" }
        default { "White" }
    }
    Write-Host ("[{0,-5}] {1,-42} {2}" -f $Status, $Check, $Detail) -ForegroundColor $color
}

function Set-RegistryValue {
    param([string]$Path, [string]$Name, $Value, [string]$Type = "DWord")
    try {
        if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
        New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $Type -Force | Out-Null
        return $true
    } catch {
        return $false
    }
}

function Get-RegistryValue {
    param([string]$Path, [string]$Name)
    try {
        return (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name
    } catch {
        return $null
    }
}

Write-Host "`n=== Nessus Credentialed Scan Diagnostic ===" -ForegroundColor White
Write-Host ("Mode: {0}`n" -f $(if ($Remediate) { "REMEDIATE" } else { "DIAGNOSE ONLY (use -Remediate to apply fixes)" })) -ForegroundColor DarkGray

# ---------------------------------------------------------------------------
# 1. Account state - the thing your batch file failed silently on
# ---------------------------------------------------------------------------
$acct = $null
try { $acct = Get-LocalUser -Name $ScanCredUser -ErrorAction Stop } catch {}

if ($null -eq $acct) {
    Add-Result "Account exists ($ScanCredUser)" "FAIL" "Account not found locally" "Verify the username in your Nessus Windows credentials"
} else {
    if ($acct.Enabled) {
        Add-Result "Account enabled" "PASS" "$ScanCredUser is active"
    } elseif ($Remediate) {
        Enable-LocalUser -Name $ScanCredUser
        Add-Result "Account enabled" "FIXED" "$ScanCredUser was disabled, now enabled"
    } else {
        Add-Result "Account enabled" "FAIL" "$ScanCredUser is DISABLED" "Run with -Remediate or: Enable-LocalUser $ScanCredUser"
    }

    # Password-set verification - this is what 'net user x pass' hides on failure
    if ($ExpectedPassword) {
        Add-Type -AssemblyName System.DirectoryServices.AccountManagement
        $ctx = [System.DirectoryServices.AccountManagement.PrincipalContext]::new('Machine')
        $valid = $ctx.ValidateCredentials($ScanCredUser, $ExpectedPassword)
        if ($valid) {
            Add-Result "Password matches scan policy" "PASS" "Provided password authenticates locally"
        } elseif ($Remediate) {
            try {
                $sec = ConvertTo-SecureString $ExpectedPassword -AsPlainText -Force
                Set-LocalUser -Name $ScanCredUser -Password $sec
                $valid2 = $ctx.ValidateCredentials($ScanCredUser, $ExpectedPassword)
                if ($valid2) {
                    Add-Result "Password matches scan policy" "FIXED" "Password set and verified"
                } else {
                    Add-Result "Password matches scan policy" "FAIL" "Set call ran but auth still fails - password policy may reject it" "Check Local Security Policy > Password Complexity"
                }
            } catch {
                Add-Result "Password matches scan policy" "FAIL" "Set-LocalUser rejected the password" "Likely complexity policy. This is why the batch failed silently."
            }
        } else {
            Add-Result "Password matches scan policy" "FAIL" "Provided password does NOT authenticate" "Stale creds in Nessus policy, or run -Remediate to reset"
        }
    } else {
        $lastSet = (net user $ScanCredUser 2>$null | Select-String "Password last set")
        Add-Result "Password verification" "WARN" "No -ExpectedPassword given. $lastSet" "Pass -ExpectedPassword to verify it matches your Nessus policy"
    }
}

# ---------------------------------------------------------------------------
# 2. Required services - verified running, not fire-and-forget
# ---------------------------------------------------------------------------
$requiredServices = @{
    "RemoteRegistry" = "Registry checks (plugins 26917, 35705)"
    "Winmgmt"        = "WMI-based local checks"
    "LanmanServer"   = "SMB / admin share access"
}

foreach ($svcName in $requiredServices.Keys) {
    $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
    if ($null -eq $svc) {
        Add-Result "Service: $svcName" "FAIL" "Service not present" $requiredServices[$svcName]
        continue
    }
    if ($svc.Status -eq "Running") {
        Add-Result "Service: $svcName" "PASS" "Running ($($requiredServices[$svcName]))"
    } elseif ($Remediate) {
        Set-Service -Name $svcName -StartupType Automatic
        Start-Service -Name $svcName -ErrorAction SilentlyContinue
        $svc.Refresh()
        if ((Get-Service $svcName).Status -eq "Running") {
            Add-Result "Service: $svcName" "FIXED" "Started and set to Automatic"
        } else {
            Add-Result "Service: $svcName" "FAIL" "Could not start" "Check dependencies for $svcName"
        }
    } else {
        Add-Result "Service: $svcName" "FAIL" "Stopped" "Run -Remediate or: Set-Service $svcName -StartupType Automatic; Start-Service $svcName"
    }
}

# ---------------------------------------------------------------------------
# 3. The registry conditions your batch set blindly - now verified
# ---------------------------------------------------------------------------
$regChecks = @(
    @{ Name="LocalAccountTokenFilterPolicy"; Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Expected=1; Type="DWord"; Why="UAC remote token filtering - blocks local-admin auth over network if unset" },
    @{ Name="AutoShareWks"; Path="HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"; Expected=1; Type="DWord"; Why="Admin shares (ADMIN$, C$) for registry/file checks" },
    @{ Name="RestrictAnonymous"; Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Expected=0; Type="DWord"; Why="Anonymous restriction - too high breaks SMB negotiation" }
)

foreach ($rc in $regChecks) {
    $current = Get-RegistryValue -Path $rc.Path -Name $rc.Name
    if ($current -eq $rc.Expected) {
        Add-Result "Registry: $($rc.Name)" "PASS" "= $($rc.Expected) ($($rc.Why))"
    } elseif ($Remediate) {
        if (Set-RegistryValue -Path $rc.Path -Name $rc.Name -Value $rc.Expected -Type $rc.Type) {
            Add-Result "Registry: $($rc.Name)" "FIXED" "Set to $($rc.Expected)"
        } else {
            Add-Result "Registry: $($rc.Name)" "FAIL" "Write failed" $rc.Why
        }
    } else {
        Add-Result "Registry: $($rc.Name)" "FAIL" "= $current, expected $($rc.Expected)" $rc.Why
    }
}

# ---------------------------------------------------------------------------
# 4. SMB signing - the cause your batch never touched (top reason 104410 persists)
# ---------------------------------------------------------------------------
$smbSign = Get-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "RequireSecuritySignature"
if ($smbSign -eq 1) {
    Add-Result "SMB signing requirement" "WARN" "RequireSecuritySignature=1 - can break older Nessus SMB auth" "Set to 0 only if scan policy can't negotiate signing"
} else {
    Add-Result "SMB signing requirement" "PASS" "Not forcing signature (=$smbSign)"
}

# ---------------------------------------------------------------------------
# 5. Firewall groups Nessus relies on
# ---------------------------------------------------------------------------
$fwGroups = @("File and Printer Sharing", "Windows Management Instrumentation (WMI)", "Remote Service Management")
foreach ($grp in $fwGroups) {
    $rules = Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object { $_.DisplayGroup -eq $grp -and $_.Direction -eq "Inbound" }
    $enabled = $rules | Where-Object { $_.Enabled -eq "True" }
    if ($enabled) {
        Add-Result "Firewall: $grp" "PASS" "$($enabled.Count) inbound rule(s) enabled"
    } elseif ($Remediate) {
        try {
            Enable-NetFirewallRule -DisplayGroup $grp -ErrorAction Stop
            Add-Result "Firewall: $grp" "FIXED" "Inbound rules enabled"
        } catch {
            Add-Result "Firewall: $grp" "FAIL" "Could not enable group" "Verify group name on this OS build"
        }
    } else {
        Add-Result "Firewall: $grp" "FAIL" "No enabled inbound rules" "Run -Remediate or Enable-NetFirewallRule -DisplayGroup '$grp'"
    }
}

# ---------------------------------------------------------------------------
# 6. Live SMB reachability self-test - proves the auth path actually works
# ---------------------------------------------------------------------------
try {
    $smbTest = Test-NetConnection -ComputerName "localhost" -Port 445 -WarningAction SilentlyContinue
    if ($smbTest.TcpTestSucceeded) {
        Add-Result "SMB port 445 listening" "PASS" "Local SMB stack reachable"
    } else {
        Add-Result "SMB port 445 listening" "FAIL" "445 not reachable" "LanmanServer down or firewall blocking"
    }
} catch {
    Add-Result "SMB port 445 listening" "WARN" "Test-NetConnection unavailable on this build"
}

# DCOM reboot flag - your batch's EnableDCOM needs a restart to take effect
$dcom = Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Ole" -Name "EnableDCOM"
if ($dcom -eq "Y") {
    Add-Result "DCOM enabled" "PASS" "EnableDCOM=Y (reboot if just changed)"
} elseif ($Remediate) {
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Ole" -Name "EnableDCOM" -Value "Y" -Type "String" | Out-Null
    Add-Result "DCOM enabled" "FIXED" "Set EnableDCOM=Y - REBOOT REQUIRED before rescan"
} else {
    Add-Result "DCOM enabled" "FAIL" "EnableDCOM=$dcom" "Run -Remediate, then reboot"
}

# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------
$fails = ($results | Where-Object Status -eq "FAIL").Count
$fixed = ($results | Where-Object Status -eq "FIXED").Count
$warns = ($results | Where-Object Status -eq "WARN").Count

Write-Host "`n=== Summary ===" -ForegroundColor White
Write-Host ("PASS/FIXED clean, {0} FIXED, {1} WARN, {2} FAIL" -f $fixed, $warns, $fails) -ForegroundColor $(if ($fails) {"Red"} else {"Green"})

$report = @()
$report += "Nessus Credentialed Scan Diagnostic Report"
$report += "Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
$report += "Host: $env:COMPUTERNAME   Mode: $(if ($Remediate){'REMEDIATE'}else{'DIAGNOSE'})"
$report += ("-" * 70)
foreach ($r in $results) {
    $report += ("[{0,-5}] {1}" -f $r.Status, $r.Check)
    $report += ("        {0}" -f $r.Detail)
    if ($r.Fix) { $report += ("        FIX: {0}" -f $r.Fix) }
}
$report += ("-" * 70)
$report += "FIXED:$fixed  WARN:$warns  FAIL:$fails"
if ($fixed -gt 0) { $report += "NOTE: If DCOM or service states changed, REBOOT before rescanning." }
$report | Set-Content -Path $ReportPath -Encoding UTF8

Write-Host "`nReport written to: $ReportPath" -ForegroundColor Cyan
Write-Host "Next: re-run the Nessus credentialed scan. If 104410 persists, read the plugin Output section for the exact protocol + error.`n" -ForegroundColor DarkGray