# Web Server Setup and Management Toolkit
**Operating Systems Course Project**

A robust, menu-driven Bash toolkit designed for setting up, configuring, managing, and securing an Nginx web server on Ubuntu Linux. This toolkit serves as an instructional and operational platform for studying web server internals, name-based virtual hosting, TLS/HTTPS encryption, operating system access controls, and network security hardening.

---

## Table of Contents
1. [Project Overview & Learning Objectives](#project-overview--learning-objectives)
2. [Target Environment & Prerequisites](#target-environment--prerequisites)
3. [File Structure](#file-structure)
4. [Installation & Quick Start](#installation--quick-start)
5. [Menu Navigation & Feature Overview](#menu-navigation--feature-overview)
6. [Virtual Hosting Architecture](#virtual-hosting-architecture)
7. [HTTPS, TLS & Certificate Theory](#https-tls--certificate-theory)
   - [Self-Signed Certificates vs. Public CAs](#self-signed-certificates-vs-public-cas)
   - [Browser Trust Store Mechanics & Warnings](#browser-trust-store-mechanics--warnings)
   - [Local Testing with `/etc/hosts` and `curl`](#local-testing-with-etchosts-and-curl)
8. [Security Architecture & Baseline Hardening](#security-architecture--baseline-hardening)
   - [Least-Privilege File Permissions](#least-privilege-file-permissions)
   - [Information Disclosure Mitigation](#information-disclosure-mitigation)
   - [HTTP Security Headers](#http-security-headers)
   - [Directory Listing Prevention](#directory-listing-prevention)
   - [Host Firewall (UFW) Integration](#host-firewall-ufw-integration)
   - [Fail2ban Intrusion Prevention](#fail2ban-intrusion-prevention)
9. [Dry-Run Mode & Safety Mechanisms](#dry-run-mode--safety-mechanisms)
10. [Troubleshooting Guide](#troubleshooting-guide)
11. [Course Project Verification](#course-project-verification)

---

## 1. Project Overview & Learning Objectives

In modern operating systems, web servers are critical network daemons that bridge operating system kernel primitives (asynchronous socket I/O, file descriptor multiplexing via `epoll`, process/thread scheduling, virtual memory) with higher-level network protocols (HTTP/1.1, HTTP/2, TLS 1.3).

This toolkit was created to demonstrate:
- **Operating System Resource Isolation**: Managing web server user privileges (`www-data`), directory permissions, and process separation.
- **Name-Based Virtual Hosting**: Serving multiple distinct websites with unique document roots from a single IP address and port using the HTTP `Host` header and TLS Server Name Indication (SNI).
- **Transport Layer Security (TLS)**: Understanding cryptographic handshakes, X.509 certificate chains, public/private key pairs, and cipher suites.
- **Defensive Scripting & Safe System Administration**: Implementing non-destructive dry-run modes, atomic configuration testing via `nginx -t`, automated pre-modification backups, and strict secret protection.

---

## 2. Target Environment & Prerequisites

### Supported Operating Systems
- **Ubuntu 24.04 LTS (Noble Numbat)**
- **Ubuntu 22.04 LTS (Jammy Jellyfish)**
- **Ubuntu 20.04 LTS (Focal Fossa)**

### Target Environments
- Local Virtual Machine (e.g., VirtualBox, UTM, VMware, Multipass, WSL2 with systemd)
- Isolated university laboratory machine
- Authorized staging or cloud server with administrative access

### System Requirements
- **Privileges**: User account with `sudo` capabilities.
- **Disk Space**: Minimum 100 MB free space on the root filesystem.
- **Network Ports**: Inbound access to TCP port 80 (HTTP) and TCP port 443 (HTTPS).
- **Core Utilities**: Standard Linux utilities (`curl`, `openssl`, `systemctl`, `ss`, `awk`, `sed`, `grep`, `df`).

---

## 3. File Structure

```
Web-Server/
├── webserver-toolkit.sh   # Main menu-driven Bash automation program
├── README.md              # Technical documentation and operations manual
├── report-outline.md      # Academic course report structure and theory
├── test-plan.md           # Step-by-step verification and QA test suite
└── webserver-toolkit.log  # Activity and audit log (mode 0600; secrets redacted)
```

---

## 4. Installation & Quick Start

1. **Clone or transfer the toolkit** to your Ubuntu lab environment:
   ```bash
   cd ~/Documents/Web-Server
   ```

2. **Make the script executable**:
   ```bash
   chmod +x webserver-toolkit.sh
   ```

3. **Verify Bash syntax and run pre-flight checks**:
   ```bash
   # Syntax validation
   bash -n webserver-toolkit.sh

   # System checks (non-destructive)
   ./webserver-toolkit.sh --check
   ```

4. **Launch the interactive menu**:
   ```bash
   ./webserver-toolkit.sh
   ```

5. **Run in Dry-Run mode** (previews all commands and file changes without executing them):
   ```bash
   ./webserver-toolkit.sh --dry-run
   ```

---

## 5. Menu Navigation & Feature Overview

When launched without flags, the toolkit displays a numbered menu:

| Option | Name | Description |
| :---: | :--- | :--- |
| **1** | **Run Pre-flight Checks** | Inspects OS version, sudo status, tools, disk space, and Nginx status. |
| **2** | **Install & Harden Nginx** | Explains package changes, requests confirmation, installs Nginx, and disables server version headers. |
| **3** | **Create New Virtual Host** | Guides user through domain name, document root, test page, and optional self-signed HTTPS setup. |
| **4** | **List Configured Hosts** | Displays tabular overview of all sites in `sites-available` and their enabled status. |
| **5** | **Enable a Virtual Host** | Creates symlink in `sites-enabled`, validates syntax with `nginx -t`, and reloads service. |
| **6** | **Disable a Virtual Host** | Removes `sites-enabled` symlink, tests syntax, and reloads without deleting website files. |
| **7** | **Remove Virtual Host** | Validates toolkit management tag, creates timestamped backup, and safely deletes config. |
| **8** | **Run Security Audit** | Evaluates file permissions, `server_tokens`, directory listing, SSL keys, and listening ports. |
| **9** | **Check Service Status** | Reports systemd status, worker processes, and listening TCP sockets. |
| **10** | **Configure Firewall (UFW)** | Shows required UFW rules and prompts for confirmation before applying. |
| **11** | **Configure Fail2ban** | Configures automated IP-banning jail for Nginx authentication abuse and bot scans. |
| **12** | **View Backups** | Lists all automatic configuration backups stored in `/var/backups/nginx-toolkit`. |
| **13** | **Toggle Dry-Run Mode** | Switches on/off simulation mode for safe testing. |
| **0** | **Exit Toolkit** | Terminates script cleanly. |

---

## 6. Virtual Hosting Architecture

Nginx supports **Name-Based Virtual Hosting**, allowing one web server instance to host multiple distinct domains on the same IP and port:

1. **Configuration Separation**:
   - Each site receives an independent server block located at `/etc/nginx/sites-available/<domain>.conf`.
   - Sites are activated by creating a symbolic link in `/etc/nginx/sites-enabled/<domain>.conf`.
2. **Document Root Isolation**:
   - Default root: `/var/www/<domain>/`
   - Custom roots are supported with directory permissions set to `0755` and ownership set to `www-data:www-data`.
3. **Safety Marker**:
   - Toolkit-managed virtual hosts include `# Managed by Web Server Setup and Management Toolkit` in the configuration header to avoid overwriting or deleting unrelated manual configurations.

---

## 7. HTTPS, TLS & Certificate Theory

### Self-Signed Certificates vs. Public CAs

| Property | Self-Signed Certificate (Lab Mode) | Public CA (e.g., Let's Encrypt / DigiCert) |
| :--- | :--- | :--- |
| **Signer** | Generated and signed locally by the administrator | Cryptographically signed by an audited root CA |
| **Trust Root** | Unknown to operating systems and browsers | Pre-installed in OS and browser trust stores |
| **Domain Requirement** | Any name (`site1.lab`, `test.local`, `localhost`) | Registered, publicly resolvable Fully Qualified Domain Name (FQDN) |
| **Validation Method** | None (self-attested identity) | Automated domain ownership challenge (ACME HTTP-01 or DNS-01) |
| **Browser Warning** | Displays "Not Secure" / "Potential Security Risk" | Displays valid padlock icon with no warnings |
| **Use Case** | Educational labs, local development, closed networks | Production public websites |

### Browser Trust Store Mechanics & Warnings

When you connect to an HTTPS server:
1. Nginx sends the public certificate (`/etc/ssl/certs/<domain>.crt`).
2. The browser examines the **Issuer** and checks if the signing key exists in its **Certificate Trust Store**.
3. With a self-signed certificate, the Issuer is the certificate itself (root of an untrusted chain).
4. The browser triggers a warning:
   - **Chrome**: `NET::ERR_CERT_AUTHORITY_INVALID` ("Your connection is not private")
   - **Firefox**: `SEC_ERROR_UNKNOWN_ISSUER` ("Potential Security Risk Ahead")
5. **How to bypass in lab**:
   - Click **Advanced** -> **Proceed to site (unsafe)** or **Accept the Risk and Continue**.
   - Note that traffic between the browser and Nginx **remains fully encrypted** despite the trust warning; the warning concerns identity verification, not the cipher stream.

### Local Testing with `/etc/hosts` and `curl`

Because lab domain names (such as `site1.lab`) do not exist in public DNS, you must map them locally:

```bash
# Add to /etc/hosts on your lab machine or client workstation
echo "127.0.0.1  site1.lab site2.lab" | sudo tee -a /etc/hosts
```

Testing HTTP and HTTPS endpoints:
```bash
# 1. Test HTTP to HTTPS redirect:
curl -I http://site1.lab

# 2. Test HTTPS response (use -k or --insecure to bypass self-signed certificate verification):
curl -I -k https://site1.lab

# 3. Inspect full TLS handshake and cipher negotiation:
curl -v -k https://site1.lab
```

---

## 8. Security Architecture & Baseline Hardening

The toolkit implements the **Principle of Least Privilege** and defense-in-depth across multiple layers:

### Least-Privilege File Permissions
- **Document Root Directories**: `0755` (`drwxr-xr-x`), owned by `www-data:www-data`.
- **HTML / Web Assets**: `0644` (`-rw-r--r--`).
- **TLS Private Keys**: `0600` (`-rw-------`), located in `/etc/ssl/private/`, accessible only by `root`.
- **Nginx Configurations**: `0644`, owned by `root:root`.

### Information Disclosure Mitigation
- `server_tokens off;` is configured in `/etc/nginx/nginx.conf` and server blocks. This prevents Nginx from broadcasting its exact version number in HTTP `Server:` response headers and default error pages.

### HTTP Security Headers
Every generated virtual host configuration injects defense-in-depth headers:
- `X-Frame-Options "SAMEORIGIN"`: Protects against Clickjacking attacks by preventing page embedding in unauthorized iframes.
- `X-Content-Type-Options "nosniff"`: Instructs browsers not to MIME-sniff response payloads, preventing executable script execution from user uploads.
- `X-XSS-Protection "1; mode=block"`: Activates browser cross-site scripting filters.
- `Referrer-Policy "strict-origin-when-cross-origin"`: Limits referrer leakage during cross-origin requests.

### Directory Listing Prevention
- Every server block specifies `autoindex off;`. If an `index.html` file is absent, Nginx serves an HTTP 403 Forbidden rather than exposing file hierarchies.
- Hidden files and version control directories (e.g., `location ~ /\. { deny all; }`) are blocked.

### Host Firewall (UFW) Integration
- The toolkit checks UFW status and displays the exact rule required (`ufw allow 'Nginx Full'`), but **never alters rules without explicit user confirmation**.

### Fail2ban Intrusion Prevention
- Detects repeated authentication failures and malicious bot scans in Nginx error/access logs.
- Automatically inserts temporary firewall drop rules for offending IP addresses.
- Option 11 installs and configures a safe custom jail at `/etc/fail2ban/jail.d/nginx-toolkit.conf`.

---

## 9. Dry-Run Mode & Safety Mechanisms

To ensure maximum safety in instructional and shared environments:
- **Dry-Run Mode (`-d`, `--dry-run`)**: When active, all state-changing operations (file writes, package installations, service reloads, firewall updates) are logged and displayed with a `[DRY-RUN]` badge without altering the host system.
- **Atomic Validation (`nginx -t`)**: Before any service reload is executed, the toolkit runs `nginx -t`. If syntax validation fails, changes are automatically rolled back, leaving the active Nginx process completely unharmed.
- **Automatic Backups**: Prior to modifying any configuration file, a timestamped snapshot is saved to `/var/backups/nginx-toolkit/` (or `./.backups/` if unprivileged).
- **Secret Scrubbing**: Private cryptographic keys and passwords are systematically intercepted and redacted before log writes (`chmod 600` enforced on log files).
- **Zero `eval` Usage**: All shell routines use direct execution arrays and strict POSIX variable expansion to prevent code injection.

---

## 10. Troubleshooting Guide

| Issue / Symptom | Possible Cause | Resolution Steps |
| :--- | :--- | :--- |
| **`nginx: [emerg] bind() to 0.0.0.0:80 failed (98: Address already in use)`** | Another service (e.g., Apache, lighttpd) is occupying port 80. | Run `sudo ss -tulpn \| grep :80` to identify the process PID. Stop or reconfigure the competing service. |
| **`curl: (6) Could not resolve host: site1.lab`** | Domain is not registered in local DNS or hosts file. | Add `127.0.0.1 site1.lab` to `/etc/hosts`. |
| **`curl: (60) SSL certificate problem: self-signed certificate`** | `curl` strictly validates certificate trust chains by default. | Use `curl -k` or `curl --insecure` during lab testing. |
| **HTTP 403 Forbidden when opening site** | Permissions on document root are too restrictive, or index file is missing. | Verify `chmod 755 /var/www/<domain>` and ensure `index.html` exists with `0644` permissions. |
| **`nginx -t` fails with directive errors** | Syntax typo or duplicate server name directive across multiple config files. | Run `sudo nginx -t` to view the exact offending file and line number. Use Menu Option 12 to restore the backup if needed. |
| **Changes not reflected in browser** | Browser caching or service not reloaded. | Clear browser cache or run `sudo systemctl reload nginx`. Verify that the site symlink exists in `/etc/nginx/sites-enabled/`. |

---

## 11. Course Project Verification

To verify the toolkit for an Operating Systems grading submission:
1. Run syntax checks: `bash -n webserver-toolkit.sh`
2. Run automated pre-flight checks: `./webserver-toolkit.sh --check`
3. Launch dry-run mode: `./webserver-toolkit.sh --dry-run`
4. Review the test execution matrix in [`test-plan.md`](./test-plan.md).
5. Review the theoretical concepts in [`report-outline.md`](./report-outline.md).
