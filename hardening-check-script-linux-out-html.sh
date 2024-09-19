#!/bin/bash

#Este script foi criado para funcionar como uma base para aplicar verificações de hardening em sistemas Linux usando as boas práticas do CIS Benchmark. 
# Incluido até o momento apenas alguns testes. Você pode modificar e expandir as verificações dos testes CIS.

# Define o arquivo de log HTML
log_file="/var/log/linux_hardening_check.html"

# Função para iniciar o log HTML
start_html_log() {
    cat <<EOF > "$log_file"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Linux Hardening Report</title>
    <style>
        body { font-family: Arial, sans-serif; }
        table { width: 100%; border-collapse: collapse; }
        th, td { border: 1px solid #ddd; padding: 8px; }
        th { background-color: #f2f2f2; }
        tr:nth-child(even) { background-color: #f9f9f9; }
    </style>
</head>
<body>
    <h1>Linux Hardening Verification Report</h1>
    <p><strong>Date:</strong> $(date)</p>
    <table>
        <thead>
            <tr>
                <th>Check</th>
                <th>Result</th>
            </tr>
        </thead>
        <tbody>
EOF
}

# Função para finalizar o log HTML
end_html_log() {
    cat <<EOF >> "$log_file"
        </tbody>
    </table>
</body>
</html>
EOF
}

# Função para adicionar uma entrada de log em HTML
add_html_log_entry() {
    local check="$1"
    local result="$2"
    echo "<tr><td>$check</td><td>$result</td></tr>" >> "$log_file"
}

# Função para verificar configurações de senha
check_password_policy() {
    local check="Password Policy"
    local result
    result=$(cat /etc/login.defs | grep -E 'PASS_MAX_DAYS|PASS_MIN_DAYS|PASS_WARN_AGE' | sed ':a;N;$!ba;s/\n/<br>/g')
    add_html_log_entry "$check" "$result"
}

# Função para verificar bloqueio de conta
check_account_lockout_policy() {
    local check="Account Lockout Policy"
    local result
    if [ -f /etc/pam.d/common-auth ]; then
        result=$(grep 'pam_tally2' /etc/pam.d/common-auth || echo "No account lockout policy found")
    else
        result="No account lockout policy found"
    fi
    add_html_log_entry "$check" "$result"
}

# Função para verificar permissões em arquivos importantes
check_important_file_permissions() {
    local check="Important File Permissions"
    local result
    result=$(stat -c "%A %n" /etc/passwd /etc/shadow /etc/gshadow /etc/group /etc/fstab 2>/dev/null | sed ':a;N;$!ba;s/\n/<br>/g')
    add_html_log_entry "$check" "$result"
}

# Função para verificar o status do firewall
check_firewall_status() {
    local check="Firewall Status"
    local result
    if command -v ufw >/dev/null 2>&1; then
        result=$(ufw status | sed ':a;N;$!ba;s/\n/<br>/g')
    elif command -v firewall-cmd >/dev/null 2>&1; then
        result=$(firewall-cmd --state 2>/dev/null || echo "FirewallD is not running")
    else
        result="No firewall installed"
    fi
    add_html_log_entry "$check" "$result"
}

# Função para verificar serviços desnecessários
check_unnecessary_services() {
    local check="Unnecessary Services"
    local result
    local services=("telnet" "ftp" "rsh" "rlogin" "rexec")
    result=""
    for service in "${services[@]}"; do
        if systemctl is-active --quiet "$service"; then
            result+="$service is running<br>"
        else
            result+="$service is not running<br>"
        fi
    done
    add_html_log_entry "$check" "$result"
}

# Função para verificar se SELinux está habilitado (se disponível)
check_selinux() {
    local check="SELinux Status"
    local result
    if command -v sestatus >/dev/null 2>&1; then
        result=$(sestatus | sed ':a;N;$!ba;s/\n/<br>/g')
    else
        result="SELinux is not installed"
    fi
    add_html_log_entry "$check" "$result"
}

# Função para verificar portas abertas
check_open_ports() {
    local check="Open Ports"
    local result
    result=$(ss -tuln | grep LISTEN | sed ':a;N;$!ba;s/\n/<br>/g')
    add_html_log_entry "$check" "$result"
}

# Função para verificar permissões em arquivos de inicialização
check_bootloader_permissions() {
    local check="Bootloader Permissions"
    local result
    result=$(stat -c "%A %n" /boot/grub2/grub.cfg /boot/grub/grub.cfg 2>/dev/null | sed ':a;N;$!ba;s/\n/<br>/g')
    add_html_log_entry "$check" "$result"
}

# Função para verificar pacotes instalados de segurança
check_installed_security_updates() {
    local check="Installed Security Updates"
    local result
    if command -v yum >/dev/null 2>&1; then
        result=$(yum updateinfo list security installed | sed ':a;N;$!ba;s/\n/<br>/g')
    elif command -v apt-get >/dev/null 2>&1; then
        result=$(apt list --installed 2>/dev/null | grep -i sec | sed ':a;N;$!ba;s/\n/<br>/g')
    else
        result="Package manager not supported"
    fi
    add_html_log_entry "$check" "$result"
}

# Função para verificar se o IP forwarding está desabilitado
check_ip_forwarding() {
    local check="IP Forwarding"
    local result
    result=$(sysctl net.ipv4.ip_forward | sed ':a;N;$!ba;s/\n/<br>/g')
    add_html_log_entry "$check" "$result"
}

# Função para verificar a configuração de logs do sistema
check_log_config() {
    local check="Log Configuration"
    local result
    if [ -f /etc/rsyslog.conf ]; then
        result=$(grep -E -v "^#|^$" /etc/rsyslog.conf | sed ':a;N;$!ba;s/\n/<br>/g')
    else
        result="Rsyslog is not installed"
    fi
    add_html_log_entry "$check" "$result"
}

# Função principal para executar todas as verificações
main() {
    start_html_log
    check_password_policy
    check_account_lockout_policy
    check_important_file_permissions
    check_firewall_status
    check_unnecessary_services
    check_selinux
    check_open_ports
    check_bootloader_permissions
    check_installed_security_updates
    check_ip_forwarding
    check_log_config
    end_html_log
}

# Executa o script
main

echo "Linux hardening check completed. Please review the HTML log file: $log_file"
