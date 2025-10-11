#        2025 10 11

#        Phone Link Troubleshooter
#        Author: Kate
#        AI-assisted design: Microsoft Copilot

# This script audits settings that could potentially block Phone Link.
# It was developed because the author got a, "This app has been blocked by your system administrator" message in Phone Link on her home machine. :)


# === Elevation check and relaunch if needed ===

if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "[INFO] Relaunching script as administrator..." -ForegroundColor Yellow
    Start-Process powershell "-ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
}

# === Ensure global scope for log ===
$global:log = @()

# === Variables ===
$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$logPath = "$PSScriptRoot\PhoneLinkAudit-$timestamp.txt"

function Log {
    param(
        [string]$msg,
        [string]$type = "INFO",
        [string]$remediation = $null,
        [switch]$Pause
    )

    $color = switch ($type) {
        "INFO" { "White" }
        "WARN" { "Yellow" }
        "ERROR" { "Red" }
        "OK"   { "Green" }
        default { "Gray" }
    }

    $fullMsg = "[$type] $msg"
    if ($remediation) {
        $fullMsg += "Suggested fix: $remediation"
    }

    if ($Pause) {
        $null = Read-Host "$fullMsg (press Enter to continue)"
    } else {
        Write-Host $fullMsg -ForegroundColor $color
    }

    $global:log += $fullMsg
}

function Check-RegistryBlock {
    Log "Checking registry keys for Phone Link blocks..." "INFO"
    $paths = @(
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
    )
    $keys = @("EnableMmx", "DisallowYourPhone", "DisablePhoneLink")

    foreach ($path in $paths) {
        foreach ($key in $keys) {
            try {
                $value = Get-ItemProperty -Path $path -Name $key -ErrorAction SilentlyContinue
                if ($value) {
                    Log "Found registry key '$key' in $path with value: $($value.$key)" "WARN" "Delete this key to re-enable Phone Link" -Pause
                }
            } catch {
                # No key found
            }
        }
    }
}

function Check-AppxStatus {
    Log "Checking Phone Link Appx package status..." "INFO"
    $pkg = Get-AppxPackage -Name "Microsoft.YourPhone" -ErrorAction SilentlyContinue
    if ($pkg) {
        Log "Phone Link is installed. Version: $($pkg.Version)" "OK"
        Log "Install location: $($pkg.InstallLocation)" "INFO"
    } else {
        Log "Phone Link is NOT installed." "ERROR" "Reinstall via Microsoft Store or use: winget install Microsoft.YourPhone" -Pause
    }
}

function Check-URIHandlers {
    Log "Checking URI handler registration for ms-phone:..." "INFO"
    $uriKey = "HKCU:\Software\Classes\ms-phone"
    if (Test-Path $uriKey) {
        $default = Get-ItemProperty -Path $uriKey -Name "(default)" -ErrorAction SilentlyContinue
        Log "ms-phone URI handler is registered: $($default.'(default)')" "OK"
    } else {
        Log "ms-phone URI handler is missing." "WARN" "Re-register handler via registry or reinstall Phone Link with winget install Microsoft.YourPhone" -Pause
    }
}

function Check-SystemComponent {
    Log "Checking System Components status (Phone Link)..." "INFO"
    $componentKey = "HKLM:\Software\Microsoft\Windows\CurrentVersion\SystemComponents"
    if (Test-Path $componentKey) {
        $value = Get-ItemProperty -Path $componentKey -Name "Microsoft.YourPhone" -ErrorAction SilentlyContinue
        if ($value) {
            Log "System Component flag found: $($value.'Microsoft.YourPhone')" "WARN" "Set value to 0 or remove key to unblock visibility" -Pause
        } else {
            Log "No System Component block detected." "OK"
        }
    } else {
        Log "SystemComponents key not found." "INFO"
    }
}

function Check-GPO {
    Log "Checking for local Group Policy remnants..." "INFO"
    $policyPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Group Policy"
    if (Test-Path $policyPath) {
        Log "Group Policy key exists. May contain legacy settings." "WARN" "Review with gpedit.msc or delete legacy keys if obsolete.`n *enable phone-pc linking*`nLocation: Computer Configuration > Administrative Templates > System > Group Policy.`n Policy: Phone-PC linking on this device.`n Recommended setting: Enabled.`n`n*allow microsoft consumer features*`nLocation: Computer Configuration > Administrative Templates > Windows Components > Cloud Content.`nPolicy:Turn off Microsoft consumer experiences.`nRecommended setting: Disabled or Not Configured.`n`n*enable microsoft store*`nLocation: Computer Configuration > Administrative Templates > Windows Components > Store.`nPolicy:Turn off the Store application.`nRecommended Setting:Disabled or Not Configured.`n`n*allow microsoft account sign-in*`nLocation: Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options`nPolicy:- Accounts: Block Microsoft accounts`nRecommended setting: Disabled`n`n*After editing group policy*`n'PS> gpupdate /force', or restart the system." -Pause
    } else {
        Log "No Group Policy remnants detected." "OK"
    }
}

# Run all checks
Check-RegistryBlock
Check-AppxStatus
Check-URIHandlers
Check-SystemComponent
Check-GPO

# Save log
$global:log | Out-File -FilePath $logPath -Encoding UTF8
Log "Audit complete. Log saved to: $logPath" "INFO"

read-host