# CyberPatriot-18 Linux Mint Hardening Script

⚠️ WARNING ⚠️

**According to the CyberPatriot rulebook, you are not allowed to use scripts made by other teams. This repository is for demonstration purposes only.**

Always read the README. This script is to help you, not replace you entirely.

## Usage
*Make sure to navigate to the directory that the script was downloaded to.*
1. Make the script executable:
```bash
chmod +x cp_harden_mint.sh
```

2. Run the script with root privileges:
```bash
sudo ./cp_harden_mint.sh```
```

Choose an option from the menu.

## Options
The script is organized into two main categories: automated hardening tasks and manual review tasks.

### Automated Tasks (Menu 1-14)
*These tasks run automatically to patch vulnerabilities and apply secure configurations.*

(1) Update System: Runs apt update, apt upgrade -y, and apt autoremove -y to apply all system patches.

(2) Remove Insecure Packages: Purges a list of common insecure or forbidden packages (e.g., telnetd, nmap, john, hydra).

(3) Install Security Tools: Installs ufw (firewall), fail2ban (brute-force protection), clamav-daemon (antivirus), and libpam-pwquality (password strength).

(4) Configure Automatic Updates: Creates a config file (/etc/apt/apt.conf.d/20auto-upgrades) to automatically install new security updates.

(5) Configure Firewall (ufw): Enables the ufw firewall, sets the default policy to deny incoming traffic, and allows SSH.

(6) Harden SSH: Modifies /etc/ssh/sshd_config to PermitRootLogin no, set Protocol 2, and apply other best practices from the checklist.

(7) Enforce Strong Password Policy: Edits /etc/pam.d/common-password to require long, complex passwords (min length, u/l/d/o-credit).

(8) Harden Login Config: Modifies /etc/login.defs to set PASS_MAX_DAYS, PASS_MIN_DAYS, and enable failure logging, as per the checklist.

(9) Secure Critical File Permissions: Sets secure permissions on /etc/passwd, /etc/shadow, /etc/sudoers, and other critical files.

(10) Harden Login Screen: Edits the lightdm configuration to disable the guest account, disable auto-login, and hide the user list.

(11) Disable Root Account: Locks the root account with passwd -l to force all admin actions through sudo.

(12) Disable NFS Service: Disables and stops all nfs related services.

(13) Harden Browsers: Creates system-wide policy files for Chrome and Firefox to enable Enhanced Safe Browsing and "Do Not Track".

(14) Harden Kernel (sysctl): Creates /etc/sysctl.d/99-cyberpatriot-hardening.conf to protect against IP spoofing, SYN floods, and ICMP redirects.

### Manual Tasks (Menu 15-22)
*These tasks run commands to find potential issues, but require your manual review and judgment to fix.*

(15) Find Large Media Files: Searches the system for common media files (.mp3, .mp4, etc.) that may be unauthorized.

(16) Review Users, Groups, & Passwords: Lists all human users, users with root privileges, users with no password, and members of the sudo and adm groups.

(17) Review Sudoers Config: Scans /etc/sudoers and /etc/sudoers.d/ for insecure NOPASSWD rules.

(18) Review Installed Packages: Lists all manually installed packages (apt-mark showmanual) and apt history to help find unauthorized software.

(19) Change All Other User Passwords: Prompts you for a new password and applies it to all human users except the user you are currently logged in as.

(20) Review Network Ports: Runs ss -tuln to show all active listening ports and services.

(21) Review Cron Jobs: Lists all system and user cron jobs, which are common hiding places for malicious scripts.

(22) Find SUID/SGID Files: Searches the filesystem for files with SUID/SGID bits set, which can be used for privilege escalation.
