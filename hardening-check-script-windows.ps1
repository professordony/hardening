# Create a log file for the script execution
$logFile = "C:\Windows\Logs\WindowsHardeningCheck.log"
New-Item -ItemType File -Path $logFile -Force
Start-Transcript -Path $logFile -Append

Write-Host "======================================"
Write-Host "Windows Hardening Verification Script"
Write-Host "Date: $(Get-Date)"
Write-Host "======================================"

# Function to check if script is running as Administrator
function Check-Administrator {
    Write-Host "Checking if the script is running as Administrator..."
    if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Host "This script must be run as Administrator."
        exit
    }
}

# Function to check password policy settings
function Check-PasswordPolicy {
    Write-Host "Checking password policies..."
    Get-LocalUser | Select-Object Name, PasswordRequired, PasswordExpires, PasswordLastSet, Enabled
    Get-LocalGroupMember -Group "Administrators"
    net accounts
}

# Function to check account lockout policy
function Check-AccountLockoutPolicy {
    Write-Host "Checking account lockout policies..."
    Get-ADDefaultDomainPasswordPolicy | Select-Object LockoutThreshold, LockoutObservationWindow, LockoutDuration
}

# Function to check Windows Defender status
function Check-WindowsDefender {
    Write-Host "Checking Windows Defender status..."
    Get-MpPreference
    Get-MpComputerStatus
}

# Function to check firewall status
function Check-FirewallStatus {
    Write-Host "Checking Firewall status..."
    Get-NetFirewallProfile -Profile Domain, Public, Private | Select-Object Name, Enabled
}

# Function to check for open ports
function Check-OpenPorts {
    Write-Host "Checking open ports..."
    Get-NetTCPConnection | Where-Object { $_.State -eq 'Listen' } | Select-Object LocalAddress, LocalPort, OwningProcess
}

# Function to check if BitLocker is enabled
function Check-BitLocker {
    Write-Host "Checking BitLocker status..."
    Get-BitLockerVolume | Select-Object MountPoint, ProtectionStatus
}

# Function to check Windows updates
function Check-WindowsUpdates {
    Write-Host "Checking for pending Windows updates..."
    Install-Module PSWindowsUpdate -Force -Confirm:$false -AllowClobber
    Get-WindowsUpdate
}

# Function to check audit policies
function Check-AuditPolicies {
    Write-Host "Checking audit policies..."
    Get-AuditPolicy -Category * | Format-Table
}

# Function to check UAC (User Account Control) settings
function Check-UAC {
    Write-Host "Checking UAC (User Account Control) settings..."
    Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA"
    Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin"
}

# Function to check for SMBv1 protocol (should be disabled)
function Check-SMBv1 {
    Write-Host "Checking if SMBv1 is disabled..."
    Get-WindowsFeature FS-SMB1 | Select-Object Name, InstallState
}

# Function to check Remote Desktop settings
function Check-RemoteDesktop {
    Write-Host "Checking Remote Desktop settings..."
    Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections"
}

# Function to check services status
function Check-Services {
    Write-Host "Checking unnecessary services..."
    $unnecessaryServices = "Telnet", "RemoteRegistry", "SSDPDiscovery", "LDPService", "WSearch", "TrkWks", "XboxGipSvc"
    foreach ($service in $unnecessaryServices) {
        Get-Service -Name $service | Select-Object Name, Status
    }
}

# Function to check guest account status
function Check-GuestAccount {
    Write-Host "Checking guest account status..."
    Get-LocalUser -Name "Guest" | Select-Object Name, Enabled
}

# Function to check encryption settings (EFS)
function Check-EFS {
    Write-Host "Checking if Encrypting File System (EFS) is enabled..."
    fsutil behavior query disableencryption
}

# Function to check registry permissions
function Check-RegistryPermissions {
    Write-Host "Checking registry permissions on sensitive keys..."
    Get-Acl -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer" | Format-List
    Get-Acl -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation" | Format-List
}

# Function to check anonymous access restrictions
function Check-AnonymousAccess {
    Write-Host "Checking anonymous access restrictions..."
    Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymous"
}

# Function to check Windows services that are set to start automatically
function Check-AutomaticServices {
    Write-Host "Checking services set to start automatically..."
    Get-Service | Where-Object {$_.StartType -eq 'Automatic'} | Select-Object Name, Status
}

# Main function to execute all checks
function Main {
    Check-Administrator
    Check-PasswordPolicy
    Check-AccountLockoutPolicy
    Check-WindowsDefender
    Check-FirewallStatus
    Check-OpenPorts
    Check-BitLocker
    Check-WindowsUpdates
    Check-AuditPolicies
    Check-UAC
    Check-SMBv1
    Check-RemoteDesktop
    Check-Services
    Check-GuestAccount
    Check-EFS
    Check-RegistryPermissions
    Check-AnonymousAccess
    Check-AutomaticServices
}

# Start the script
Main

Stop-Transcript
Write-Host "Windows hardening check completed. Please review the log file: $logFile"
