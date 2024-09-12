# Define o arquivo de log HTML
$logFile = "C:\Windows\Logs\WindowsHardeningCheck.html"
New-Item -ItemType File -Path $logFile -Force

# Função para iniciar o log em formato HTML
function Start-HTMLLog {
    $htmlHeader = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Windows Hardening Report</title>
    <style>
        body { font-family: Arial, sans-serif; }
        table { width: 100%; border-collapse: collapse; }
        th, td { border: 1px solid #ddd; padding: 8px; }
        th { background-color: #f2f2f2; }
        tr:nth-child(even) { background-color: #f9f9f9; }
    </style>
</head>
<body>
    <h1>Windows Hardening Verification Report</h1>
    <p><strong>Date:</strong> $(Get-Date)</p>
    <table>
        <thead>
            <tr>
                <th>Check</th>
                <th>Result</th>
            </tr>
        </thead>
        <tbody>
"@
    $htmlHeader | Out-File -FilePath $logFile -Append
}

# Função para finalizar o log HTML
function End-HTMLLog {
    $htmlFooter = @"
        </tbody>
    </table>
</body>
</html>
"@
    $htmlFooter | Out-File -FilePath $logFile -Append
}

# Função para adicionar entradas de log em HTML
function Add-HTMLLogEntry {
    param (
        [string]$check,
        [string]$result
    )

    $htmlRow = "<tr><td>$check</td><td>$result</td></tr>"
    $htmlRow | Out-File -FilePath $logFile -Append
}

# Função para verificar se o script está sendo executado como Administrador
function Check-Administrator {
    $check = "Administrator Check"
    if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        $result = "FAIL: This script must be run as Administrator."
        Add-HTMLLogEntry -check $check -result $result
        Write-Host $result
        exit
    } else {
        $result = "PASS: Script running with Administrator privileges."
        Add-HTMLLogEntry -check $check -result $result
        Write-Host $result
    }
}

# Função para verificar políticas de senha
function Check-PasswordPolicy {
    $check = "Password Policy"
    $result = Get-LocalUser | Format-Table Name, PasswordRequired, PasswordExpires, PasswordLastSet, Enabled | Out-String
    Add-HTMLLogEntry -check $check -result ($result -replace "`r`n", "<br>")
}

# Função para verificar política de bloqueio de conta
function Check-AccountLockoutPolicy {
    $check = "Account Lockout Policy"
    $result = Get-ADDefaultDomainPasswordPolicy | Select-Object LockoutThreshold, LockoutObservationWindow, LockoutDuration | Out-String
    Add-HTMLLogEntry -check $check -result ($result -replace "`r`n", "<br>")
}

# Função para verificar status do Windows Defender
function Check-WindowsDefender {
    $check = "Windows Defender Status"
    $result = Get-MpComputerStatus | Format-List | Out-String
    Add-HTMLLogEntry -check $check -result ($result -replace "`r`n", "<br>")
}

# Função para verificar status do firewall
function Check-FirewallStatus {
    $check = "Firewall Status"
    $result = Get-NetFirewallProfile -Profile Domain, Public, Private | Format-Table Name, Enabled | Out-String
    Add-HTMLLogEntry -check $check -result ($result -replace "`r`n", "<br>")
}

# Função para verificar portas abertas
function Check-OpenPorts {
    $check = "Open Ports"
    $result = Get-NetTCPConnection | Where-Object { $_.State -eq 'Listen' } | Select-Object LocalAddress, LocalPort, OwningProcess | Out-String
    Add-HTMLLogEntry -check $check -result ($result -replace "`r`n", "<br>")
}

# Função para verificar status do BitLocker
function Check-BitLocker {
    $check = "BitLocker Status"
    $result = Get-BitLockerVolume | Select-Object MountPoint, ProtectionStatus | Out-String
    Add-HTMLLogEntry -check $check -result ($result -replace "`r`n", "<br>")
}

# Função para verificar atualizações do Windows
function Check-WindowsUpdates {
    $check = "Windows Updates"
    Install-Module PSWindowsUpdate -Force -Confirm:$false -AllowClobber | Out-Null
    $result = Get-WindowsUpdate | Out-String
    Add-HTMLLogEntry -check $check -result ($result -replace "`r`n", "<br>")
}

# Função para verificar políticas de auditoria
function Check-AuditPolicies {
    $check = "Audit Policies"
    $result = Get-AuditPolicy -Category * | Format-Table | Out-String
    Add-HTMLLogEntry -check $check -result ($result -replace "`r`n", "<br>")
}

# Função para verificar configurações do UAC
function Check-UAC {
    $check = "UAC (User Account Control)"
    $result = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA"
    Add-HTMLLogEntry -check $check -result "EnableLUA: $result"
}

# Função para verificar se SMBv1 está desabilitado
function Check-SMBv1 {
    $check = "SMBv1 Disabled"
    $result = Get-WindowsFeature FS-SMB1 | Select-Object Name, InstallState | Out-String
    Add-HTMLLogEntry -check $check -result ($result -replace "`r`n", "<br>")
}

# Função para verificar configurações de Remote Desktop
function Check-RemoteDesktop {
    $check = "Remote Desktop"
    $result = Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections"
    Add-HTMLLogEntry -check $check -result "fDenyTSConnections: $result"
}

# Função para verificar serviços desnecessários
function Check-Services {
    $check = "Unnecessary Services"
    $unnecessaryServices = "Telnet", "RemoteRegistry", "SSDPDiscovery", "LDPService", "WSearch", "TrkWks", "XboxGipSvc"
    foreach ($service in $unnecessaryServices) {
        $result = Get-Service -Name $service | Select-Object Name, Status | Out-String
        Add-HTMLLogEntry -check "$service Service" -result ($result -replace "`r`n", "<br>")
    }
}

# Função para verificar status da conta Guest
function Check-GuestAccount {
    $check = "Guest Account"
    $result = Get-LocalUser -Name "Guest" | Select-Object Name, Enabled | Out-String
    Add-HTMLLogEntry -check $check -result ($result -replace "`r`n", "<br>")
}

# Função para verificar EFS (Encrypting File System)
function Check-EFS {
    $check = "EFS Status"
    $result = fsutil behavior query disableencryption | Out-String
    Add-HTMLLogEntry -check $check -result ($result -replace "`r`n", "<br>")
}

# Função para iniciar todas as verificações
function Main {
    Start-HTMLLog
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
    End-HTMLLog
}

# Executar o script
Main
Write-Host "Windows hardening check completed. Please review the HTML log file: $logFile"
