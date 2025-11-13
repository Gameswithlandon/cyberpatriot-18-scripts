#!/bin/bash

if [ "$EUID" -ne 0 ]; then
  echo "Please run this script as root (e.g., sudo ./cp_harden_mint.sh)"
  exit 1
fi

update_system() {
    echo "--- [1] Starting System Update & Upgrade ---"
    apt update
    apt upgrade -y
    apt autoremove -y
    apt clean
    echo "--- [1] System Update Finished ---"
}

remove_packages() {
    echo "--- [2] Removing Insecure/Unnecessary Packages ---"
    INSECURE_PACKAGES=(
        telnetd
        nis
        rsh-server
        rsh-client
        xinetd
        nmap
        john
        hydra
        wireshark-qt
        ophcrack
    )

    for pkg in "${INSECURE_PACKAGES[@]}"; do
        if dpkg -l | grep -q " $pkg "; then
            echo "Removing $pkg..."
            apt remove --purge "$pkg" -y
        else
            echo "$pkg not found."
        fi
    done
    echo "--- [2] Package Removal Finished ---"
}

install_tools() {
    echo "--- [3] Installing Security Tools ---"
    apt install ufw fail2ban clamav-daemon libpam-pwquality -y
    echo "Updating ClamAV definitions..."
    freshclam
    echo "--- [3] Security Tools Installed ---"
}

configure_auto_updates() {
    echo "--- [4] Configuring Automatic Security Updates ---"
    cat <<EOF > /etc/apt/apt.conf.d/20auto-upgrades
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF
    echo "Created /etc/apt/apt.conf.d/20auto-upgrades for automatic security updates."
    echo "--- [4] Auto Updates Configured ---"
}


configure_firewall() {
    echo "--- [5] Configuring Firewall (UFW) ---"
    ufw default deny incoming
    ufw default allow outgoing
    
    ufw allow ssh
    
    echo "y" | ufw enable
    
    echo "Firewall enabled. Status:"
    ufw status verbose
    echo "--- [5] Firewall Configuration Finished ---"
}

harden_ssh() {
    echo "--- [6] Hardening SSH Configuration ---"
    SSH_CONFIG="/etc/ssh/sshd_config"
    cp "$SSH_CONFIG" "$SSH_CONFIG.bak"
    echo "Backup of sshd_config created at $SSH_CONFIG.bak"

    sed -i 's/.*PermitRootLogin.*/PermitRootLogin no/' "$SSH_CONFIG"
    sed -i 's/.*#Protocol.*/Protocol 2/' "$SSH_CONFIG"
    sed -i 's/.*X11Forwarding.*/X11Forwarding no/' "$SSH_CONFIG"
    sed -i 's/.*LoginGraceTime.*/LoginGraceTime 60/' "$SSH_CONFIG"
    sed -i 's/.*PermitEmptyPasswords.*/PermitEmptyPasswords no/' "$SSH_CONFIG"
    sed -i 's/.*PasswordAuthentication.*/PasswordAuthentication yes/' "$SSH_CONFIG"
    sed -i 's/.*UsePAM.*/UsePAM yes/' "$SSH_CONFIG"
    
    if ! grep -q "^UsePrivilegeSeparation" "$SSH_CONFIG"; then
        echo "UsePrivilegeSeparation yes" >> "$SSH_CONFIG"
    fi
    
    sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin no/' "$SSH_CONFIG"

    systemctl restart sshd
    echo "SSH service hardened and restarted."
    echo "--- [6] SSH Hardening Finished ---"
}

enforce_password_policy() {
    echo "--- [7] Enforcing Strong Password Policy (PAM) ---"
    PWQUALITY_CONF="/etc/pam.d/common-password"
    PWQUALITY_LINE="password    requisite    pam_pwquality.so retry=3 minlen=12 difok=3 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1"

    if ! grep -q "pam_pwquality.so" "$PWQUALITY_CONF"; then
        sed -i "/^password.*pam_unix.so/i $PWQUALITY_LINE" "$PWQUALITY_CONF"
        echo "Password policy added to $PWQUALITY_CONF."
    else
        sed -i "s/password.*pam_pwquality.so.*/$PWQUALITY_LINE/" "$PWQUALITY_CONF"
        echo "Password policy updated in $PWQUALITY_CONF."
    fi
    echo "--- [7] Password Policy Enforced ---"
}

harden_login_defs() {
    echo "--- [8] Hardening /etc/login.defs ---"
    LOGIN_DEFS="/etc/login.defs"
    cp "$LOGIN_DEFS" "$LOGIN_DEFS.bak"
    echo "Backup of login.defs created at $LOGIN_DEFS.bak"

    sed -i 's/.*FAILLOG_ENAB.*/FAILLOG_ENAB yes/' "$LOGIN_DEFS"
    sed -i 's/.*LOG_UNKFAIL_ENAB.*/LOG_UNKFAIL_ENAB yes/' "$LOGIN_DEFS"
    sed -i 's/.*SYSLOG_SU_ENAB.*/SYSLOG_SU_ENAB yes/' "$LOGIN_DEFS"
    sed -i 's/.*SYSLOG_SG_ENAB.*/SYSLOG_SG_ENAB yes/' "$LOGIN_DEFS"
    sed -i 's/.*PASS_MAX_DAYS.*/PASS_MAX_DAYS 60/' "$LOGIN_DEFS"
    sed -i 's/.*PASS_MIN_DAYS.*/PASS_MIN_DAYS 7/' "$LOGIN_DEFS"
    sed -i 's/.*PASS_WARN_AGE.*/PASS_WARN_AGE 7/' "$LOGIN_DEFS"
    
    echo "Updated PASS_MAX_DAYS, PASS_MIN_DAYS, PASS_WARN_AGE, and logging in $LOGIN_DEFS."
    echo "--- [8] login.defs Hardened ---"
}

secure_file_permissions() {
    echo "--- [9] Securing Critical File Permissions ---"
    chmod 644 /etc/passwd
    chmod 640 /etc/shadow
    chmod 644 /etc/group
    chmod 600 /etc/gshadow
    chmod 755 /etc/sudoers.d
    chmod 440 /etc/sudoers
    echo "Permissions set for /etc/passwd (644), /etc/shadow (640), /etc/group (644), /etc/gshadow (600), /etc/sudoers (440)"
    echo "--- [9] File Permissions Secured ---"
}

harden_login_screen() {
    echo "--- [10] Hardening Login Screen (LightDM) ---"
    LIGHTDM_CONF_DIR="/etc/lightdm/lightdm.conf.d"
    LIGHTDM_CONF_FILE="$LIGHTDM_CONF_DIR/50-cyberpatriot.conf"
    
    mkdir -p "$LIGHTDM_CONF_DIR"
    
    if [ ! -f "$LIGHTDM_CONF_FILE" ]; then
        echo "[SeatDefaults]" > "$LIGHTDM_CONF_FILE"
    fi

    if grep -q "allow-guest=" "$LIGHTDM_CONF_FILE"; then
        sed -i 's/allow-guest=.*/allow-guest=false/' "$LIGHTDM_CONF_FILE"
    else
        echo "allow-guest=false" >> "$LIGHTDM_CONF_FILE"
    fi
    echo "Guest account disabled."

    if grep -q "autologin-user=" "$LIGHTDM_CONF_FILE"; then
        sed -i 's/autologin-user=.*/autologin-user=/' "$LIGHTDM_CONF_FILE"
    else
        echo "autologin-user=" >> "$LIGHTDM_CONF_FILE"
    fi
    echo "Automatic login disabled."

    if grep -q "greeter-hide-users=" "$LIGHTDM_CONF_FILE"; then
        sed -i 's/greeter-hide-users=.*/greeter-hide-users=true/' "$LIGHTDM_CONF_FILE"
    else
        echo "greeter-hide-users=true" >> "$LIGHTDM_CONF_FILE"
    fi
    echo "User list hidden on login screen."
    
    echo "--- [10] Login Screen Hardened ---"
}

disable_root_account() {
    echo "--- [11] Disabling Root Account Login ---"
    passwd -l root
    echo "Root account password locked. Use 'sudo -i' or 'sudo su' for root access."
    echo "--- [11] Root Account Disabled ---"
}

disable_nfs_service() {
    echo "--- [12] Disabling NFS Services ---"
    systemctl disable nfs-kernel-server
    systemctl disable nfs-blkmap
    systemctl disable nfs-kernel-idmapd
    systemctl disable nfs-mountd
    systemctl disable nfsdcld
    systemctl disable nfs-server
    echo "All nfs services disabled."
    echo "--- [12] NFS Disabled ---"
}

harden_browsers() {
    echo "--- [13] Hardening Browsers (Chrome & Firefox) ---"

    CHROME_POLICY_DIR="/etc/opt/chrome/policies/managed"
    mkdir -p "$CHROME_POLICY_DIR"
    CHROME_POLICY_FILE="$CHROME_POLICY_DIR/cyberpatriot_policies.json"
    cat <<EOF > "$CHROME_POLICY_FILE"
{
  "SafeBrowsingEnabled": true,
  "SafeBrowsingProtectionLevel": 2,
  "EnableDoNotTrack": true
}
EOF
    echo "Google Chrome: 'Enhanced Safe Browsing' and 'Do Not Track' enabled."

    FIREFOX_POLICY_DIR="/etc/firefox/policies"
    mkdir -p "$FIREFOX_POLICY_DIR"
    FIREFOX_POLICY_FILE="$FIREFOX_POLICY_DIR/policies.json"
    cat <<EOF > "$FIREFOX_POLICY_FILE"
{
  "policies": {
    "DisableSafeBrowsing": false,
    "BlockDangerousContent": true,
    "BlockDangerousDownloads": true,
    "EnableDoNotTrack": true
  }
}
EOF
    echo "Firefox: Protections and 'Do Not Track' enabled."
    
    echo "--- [13] Browser Hardening Finished ---"
}

harden_sysctl() {
    echo "--- [14] Hardening Kernel Network Parameters (sysctl) ---"
    cat <<EOF > /etc/sysctl.d/99-cyberpatriot-hardening.conf
# IP Spoofing protection
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Ignore ICMP broadcast requests
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Disable source packet routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# Ignore send redirects
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# Disable ICMP redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# Enable SYN cookies
net.ipv4.tcp_syncookies = 1
EOF
    
    echo "Applying new kernel parameters..."
    sysctl -p /etc/sysctl.d/99-cyberpatriot-hardening.conf
    echo "--- [14] Kernel Hardening Finished ---"
}


find_media_files() {
    echo "--- [15] Finding Large Media Files (Manual Review) ---"
    echo "This may take a moment..."
    find / -type f -size +1M \( -name "*.mp3" -o -name "*.mp4" -o -name "*.mkv" -o -name "*.avi" -o -name "*.wav" \) -exec ls -lh {} \;
    echo "--- [15] Media File Search Finished ---"
}

review_users_and_groups() {
    echo "--- [16] User and Group Review (Manual Review) ---"
    
    echo "== Users with UID >= 1000 (Non-system) =="
    awk -F: '($3 >= 1000) { print $1 }' /etc/passwd
    echo ""

    echo "== Users with /bin/bash or /bin/sh shell (Checklist #15) =="
    grep -E '(/bin/bash|/bin/sh)$' /etc/passwd | cut -d: -f1
    echo ""

    echo "== Users with UID 0 (root privileges) =="
    awk -F: '($3 == 0) { print $1 }' /etc/passwd
    echo ""

    echo "== Users with empty passwords =="
    passwd -S -a | awk '($2 == "NP") { print $1 }'
    echo ""

    echo "== Members of 'sudo' group =="
    grep "^sudo" /etc/group
    echo ""
    
    echo "== Members of 'adm' group =="
    grep "^adm" /etc/group
    echo ""

    echo "ACTION: Review this list against the README."
    echo "ACTION: Change passwords for all authorized users (Checklist #10)."
    echo "--- [16] User Review Finished ---"
}

review_sudoers() {
    echo "--- [17] Sudoers Configuration Review (Manual Review) ---"
    echo "Checking /etc/sudoers for insecure rules like NOPASSWD..."
    grep -i "NOPASSWD" /etc/sudoers
    echo ""
    echo "Checking /etc/sudoers.d/ for insecure rules..."
    grep -i "NOPASSWD" /etc/sudoers.d/*
    echo ""
    echo "ACTION: Review the above lines. Use 'sudo visudo' to edit /etc/sudoers"
    echo "--- [17] Sudoers Review Finished ---"
}

review_installed_packages() {
    echo "--- [18] Reviewing Installed Packages (Manual Review) ---"
    
    echo "== Manually Installed Packages (apt-mark showmanual) =="
    apt-mark showmanual
    echo ""
    
    echo "== APT Installation History (last 20 installs) =="
    grep 'Commandline: apt' /var/log/apt/history.log | tail -n 20
    echo ""
    
    echo "ACTION: Review this list for unauthorized programs."
    echo "ACTION: Use 'sudo apt remove --purge <pkg_name>' to remove."
    echo "--- [18] Package Review Finished ---"
}


change_user_passwords() {
    echo "--- [19] Changing All Other User Passwords ---"
    
    echo -n "Enter the new password for all other users: "
    read -s NEW_PASSWORD
    echo
    echo -n "Confirm the new password: "
    read -s NEW_PASSWORD_CONFIRM
    echo
    
    if [ "$NEW_PASSWORD" != "$NEW_PASSWORD_CONFIRM" ]; then
        echo "Passwords do not match. Aborting password change."
        return 1
    fi

    if [ -z "$NEW_PASSWORD" ]; then
        echo "Password cannot be empty. Aborting password change."
        return 1
    fi
    
    CURRENT_USER="$SUDO_USER"
    if [ -z "$CURRENT_USER" ]; then
        echo "Could not determine the current user. Aborting."
        return 1
    fi
    
    echo "Changing passwords for all users with UID >= 1000, except for '$CURRENT_USER'..."
    
    awk -F: '($3 >= 1000) { print $1 }' /etc/passwd | while read -r user; do
        if [ "$user" != "$CURRENT_USER" ]; then
            echo "Changing password for user: $user"
            echo "$user:$NEW_PASSWORD" | chpasswd
        else
            echo "Skipping current user: $user"
        fi
    done
    
    echo "--- [19] Password Change Finished ---"
}

review_network_ports() {
    echo "--- [20] Reviewing Active Network Ports (Manual Review) ---"
    echo "Listing all listening TCP and UDP ports (ss -tuln)"
    ss -tuln
    echo ""
    echo "ACTION: Review this list for unauthorized listening services."
    echo "ACTION: Compare against allowed services in the README."
    echo "--- [20] Network Port Review Finished ---"
}

review_cron_jobs() {
    echo "--- [21] Reviewing Cron Jobs (Manual Review) ---"
    
    echo "== System-Wide Crontab (/etc/crontab) =="
    cat /etc/crontab
    echo ""
    
    echo "== System Cron Directories (/etc/cron.*) =="
    ls -l /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.monthly /etc/cron.weekly
    echo ""
    
    echo "== User Cron Jobs (/var/spool/cron/crontabs) =="
    ls -l /var/spool/cron/crontabs/
    echo ""
    
    echo "ACTION: Review all files in the directories above for suspicious commands."
    echo "--- [21] Cron Job Review Finished ---"
}

find_suid_sgid_files() {
    echo "--- [22] Finding SUID/SGID Files (Manual Review) ---"
    echo "Searching for SUID files (run as root)..."
    find / -perm -u=s -type f 2>/dev/null
    echo ""
    
    echo "Searching for SGID files (run as group)..."
    find / -perm -g=s -type f 2>/dev/null
    echo ""
    
    echo "ACTION: Review this list for non-standard programs."
    echo "ACTION: Use 'chmod -s /path/to/file' to remove SUID/SGID bit."
    echo "--- [22] SUID/SGID Search Finished ---"
}


run_all_tasks() {
    echo "--- [99] Running All Automated Hardening Tasks ---"
    update_system
    remove_packages
    install_tools
    configure_auto_updates
    configure_firewall
    harden_ssh
    enforce_password_policy
    harden_login_defs
    secure_file_permissions
    harden_login_screen
    disable_root_account
    disable_nfs_service
    harden_browsers
    harden_sysctl
    echo "#######################################"
    echo "--- ALL AUTOMATED TASKS FINISHED ---"
    echo "Run tasks 15-22 to manually review the system."
    echo "MANUAL REVIEW IS STILL REQUIRED."
    echo "#######################################"
}

show_menu() {
    echo ""
    echo "================================================="
    echo "  CyberPatriot Linux Mint Hardening Script Menu  "
    echo "================================================="
    echo "--- Automated Tasks ---"
    echo " (1) Update System (apt update/upgrade)"
    echo " (2) Remove Insecure Packages"
    echo " (3) Install Security Tools (ufw, fail2ban, clamav)"
    echo " (4) Configure Automatic Updates"
    echo " (5) Configure Firewall (ufw)"
    echo " (6) Harden SSH (Disable Root, etc.)"
    echo " (7) Enforce Strong Password Policy (pam.d)"
    echo " (8) Harden Login Config (login.defs)"
    echo " (9) Secure Critical File Permissions"
    echo " (10) Harden Login Screen (lightdm)"
    echo " (11) Disable Root Account (passwd -l)"
    echo " (12) Disable NFS Service"
    echo " (13) Harden Browsers (Chrome/Firefox)"
    echo " (14) Harden Kernel (sysctl)"
    echo ""
    echo "--- Manual Review Tasks ---"
    echo " (15) Find Large Media Files (Checklist #6)"
    echo " (16) Review Users, Groups, & Passwords (Checklist #8,9,10,15,16)"
    echo " (17) Review Sudoers Config (Checklist #24)"
    echo " (18) Review Installed Packages (Checklist #11)"
    echo " (19) Change All Other User Passwords (Checklist #10)"
    echo " (20) Review Network Ports (ss)"
    echo " (21) Review Cron Jobs"
    echo " (22) Find SUID/SGID Files"
    echo ""
    echo " (99) RUN ALL AUTOMATED TASKS (1-14)"
    echo " (0) Exit"
    echo "================================================="
    echo -n "Enter your choice [0-99]: "
}

while true; do
    show_menu
    read -r choice
    echo ""
    
    case $choice in
        1) update_system ;;
        2) remove_packages ;;
        3) install_tools ;;
        4) configure_auto_updates ;;
        5) configure_firewall ;;
        6) harden_ssh ;;
        7) enforce_password_policy ;;
        8) harden_login_defs ;;
        9) secure_file_permissions ;;
        10) harden_login_screen ;;
        11) disable_root_account ;;
        12) disable_nfs_service ;;
        13) harden_browsers ;;
        14) harden_sysctl ;;
        15) find_media_files ;;
        16) review_users_and_groups ;;
        17) review_sudoers ;;
        18) review_installed_packages ;;
        19) change_user_passwords ;;
        20) review_network_ports ;;
        21) review_cron_jobs ;;
        22) find_suid_sgid_files ;;
        99) run_all_tasks ;;
        0) echo "Exiting script. Good luck!"; exit 0 ;;
        *) echo "Invalid option. Please try again." ;;
    esac
    
    echo ""
    echo "Press [Enter] to return to the menu..."
    read -r
done


