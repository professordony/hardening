#!/bin/bash

#This script was create to works likea a base to apply hardening verifications on the Linux Systems using CIS Benchmark good pratices. 
#Include now only a few tests. You can modify and expand CIS tests verifications.

# Define a log file for the script execution
LOGFILE="/var/log/cis_hardening_check.log"
exec > >(tee -a ${LOGFILE}) 2>&1

echo "======================================="
echo "CIS Basic Hardening Verification Script"
echo "Date: $(date)"
echo "======================================="

# Function to check if the user is root
check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo "This script must be run as root."
        exit 1
    fi
}

# Function to check password policies
check_password_policy() {
    echo "Checking password policies..."
    grep ^PASS_MAX_DAYS /etc/login.defs
    grep ^PASS_MIN_DAYS /etc/login.defs
    grep ^PASS_WARN_AGE /etc/login.defs
}

# Function to check for secure password hashing algorithms
check_password_hashing() {
    echo "Checking password hashing algorithm..."
    if command -v authconfig &> /dev/null; then
        authconfig --test | grep hashing
    else
        grep pam_unix.so /etc/pam.d/* | grep sha512
    fi
}

# Function to check SSH configuration
check_ssh_config() {
    echo "Checking SSH configuration..."
    sshd_config="/etc/ssh/sshd_config"
    grep "^PermitRootLogin no" $sshd_config
    grep "^Protocol 2" $sshd_config
    grep "^X11Forwarding no" $sshd_config
    grep "^MaxAuthTries 4" $sshd_config
    grep "^AllowTcpForwarding no" $sshd_config
    grep "^PermitEmptyPasswords no" $sshd_config
    grep "^ClientAliveInterval" $sshd_config
}

# Function to check file permissions on sensitive files
check_file_permissions() {
    echo "Checking file permissions..."
    ls -l /etc/passwd
    ls -l /etc/shadow
    ls -l /etc/gshadow
    ls -l /etc/group

    # Check for world-writable files
    echo "Checking for world-writable files..."
    find / -xdev -type f -perm -002 -exec ls -ld {} \;

    # Check for unowned files and directories
    echo "Checking for unowned files and directories..."
    find / -xdev \( -nouser -o -nogroup \) -exec ls -ld {} \;
}

# Function to check for unwanted services
check_services() {
    echo "Checking unwanted services..."
    systemctl list-unit-files --type=service | grep enabled | grep -E 'telnet|rsh|nfs|vsftpd|smb|snmp'
}

# Function to check firewall configuration
check_firewall() {
    echo "Checking firewall configuration..."
    if command -v firewall-cmd &> /dev/null; then
        firewall-cmd --state
    elif command -v ufw &> /dev/null; then
        ufw status
    elif command -v iptables &> /dev/null; then
        iptables -L
    else
        echo "No firewall management tool found."
    fi
}

# Function to check auditd service
check_auditd() {
    echo "Checking auditd service..."
    systemctl is-enabled auditd
    systemctl status auditd
}

# Function to check if system is up-to-date
check_updates() {
    echo "Checking for available updates..."
    if command -v yum &> /dev/null; then
        yum check-update
    elif command -v apt &> /dev/null; then
        apt update && apt list --upgradable
    elif command -v dnf &> /dev/null; then
        dnf check-update
    else
        echo "No package management tool found."
    fi
}

# Function to check core dump restrictions
check_core_dumps() {
    echo "Checking for core dump restrictions..."
    grep "hard core" /etc/security/limits.conf
    sysctl fs.suid_dumpable
}

# Function to check for inactive users
check_inactive_users() {
    echo "Checking for inactive users..."
    lastlog | grep -v 'Never logged in'
}

# Function to check for open ports
check_open_ports() {
    echo "Checking for open ports..."
    ss -tuln
}

# Function to check if SELinux is enabled (for systems with SELinux)
check_selinux() {
    if command -v getenforce &> /dev/null; then
        echo "Checking SELinux status..."
        getenforce
    fi
}

# Function to check AppArmor status (for systems with AppArmor)
check_apparmor() {
    if command -v apparmor_status &> /dev/null; then
        echo "Checking AppArmor status..."
        apparmor_status
    fi
}

# Function to check for system accounts
check_system_accounts() {
    echo "Checking for system accounts without shell access..."
    awk -F: '($3 < 1000 && $7 != "/sbin/nologin" && $7 != "/bin/false") {print}' /etc/passwd
}

# Function to disable unused filesystems
check_unused_filesystems() {
    echo "Checking for unused filesystems..."
    echo "Disabling cramfs, freevxfs, jffs2, hfs, hfsplus, squashfs, udf..."
    for fs in cramfs freevxfs jffs2 hfs hfsplus squashfs udf; do
        lsmod | grep $fs
    done
}

# Function to enforce permissions on cron jobs
check_cron_permissions() {
    echo "Checking cron job permissions..."
    ls -l /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.monthly /etc/cron.weekly
    ls -l /etc/crontab
}

# Main execution function
main() {
    check_root
    check_password_policy
    check_password_hashing
    check_ssh_config
    check_file_permissions
    check_services
    check_firewall
    check_auditd
    check_updates
    check_core_dumps
    check_inactive_users
    check_open_ports
    check_selinux
    check_apparmor
    check_system_accounts
    check_unused_filesystems
    check_cron_permissions
}

# Start the script
main

echo "CIS hardening check completed. Please review the log file: $LOGFILE"
