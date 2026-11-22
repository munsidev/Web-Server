# Quality Assurance & Test Plan
## Web Server Setup and Management Toolkit
**Course**: Operating Systems  
**Scope**: Non-destructive Verification, Virtual Hosting, TLS Encryption, and Security Hardening

---

## 1. Test Philosophy & Safety Policy
All tests in this suite adhere to standard operating systems verification principles:
1. **Host Isolation**: Tests should be performed inside an Ubuntu 20.04/22.04/24.04 LTS VM (e.g. Multipass, VirtualBox, UTM, WSL2) or an authorized laboratory workstation.
2. **Non-Destructive Development**: During initial validation, the toolkit is run with syntax checks (`bash -n`) and simulation mode (`--dry-run`).
3. **Rollback Verification**: Every state modification must verify that rollback mechanisms preserve system stability if errors occur.
4. **Secret Scrubbing**: Ensure private keys and passwords are never displayed in stdout or written to log files.

---

## 2. Test Execution Matrix

| Test ID | Test Category | Objective | Command / Procedure | Expected Outcome | Pass/Fail Criteria |
| :---: | :--- | :--- | :--- | :--- | :--- |
| **TC-01** | Syntax Validation | Verify Bash syntax and portability. | `bash -n webserver-toolkit.sh` | Zero syntax errors reported. | Exit code `0`. |
| **TC-02** | CLI Flags & Help | Test command-line interface options. | `./webserver-toolkit.sh --help`<br>`./webserver-toolkit.sh --version` | Help screen and version string displayed cleanly. | Displays flags, exit code `0`. |
| **TC-03** | Dry-Run Simulation | Verify zero modifications in dry-run mode. | `./webserver-toolkit.sh --dry-run` | All commands logged with `[DRY-RUN]` badge; no files in `/etc/nginx` created. | Filesystem remains unchanged. |
| **TC-04** | Pre-flight Checks | Test detection of OS, sudo, tools, disk. | `./webserver-toolkit.sh --check` | Accurately identifies OS name, version, tools, and disk space. | Exit code `0` with status report. |
| **TC-05** | Nginx Installation | Verify confirmation prompt and installation. | Menu Option `2` | Explains changes, asks confirmation, installs Nginx, disables `server_tokens`. | Nginx service active, version hidden. |
| **TC-06** | Virtual Host (HTTP) | Create single HTTP virtual host (`site1.lab`). | Menu Option `3`<br>Domain: `site1.lab`<br>HTTPS: `N` | Server block written to `sites-available`, symlinked to `sites-enabled`, test page created. | `curl -I http://site1.lab` returns HTTP 200. |
| **TC-07** | Virtual Host (HTTPS) | Create HTTPS virtual host (`site2.lab`). | Menu Option `3`<br>Domain: `site2.lab`<br>HTTPS: `Y` | Self-signed cert created, key set to 0600, HTTP redirects to HTTPS, port 443 active. | `curl -k -I https://site2.lab` returns HTTP 200. |
| **TC-08** | Multi-Tenancy (SNI) | Verify distinct content on shared IP. | Map `127.0.0.1 site1.lab site2.lab`<br>`curl http://site1.lab`<br>`curl -k https://site2.lab` | Each request returns its respective unique `index.html` page. | Content matches specific document root. |
| **TC-09** | Configuration Rollback | Inject syntax error into server block. | Edit `/etc/nginx/sites-available/broken.conf` with invalid directive and attempt to enable. | `nginx -t` fails; toolkit aborts reload, removes bad symlink, and preserves running process. | Nginx service remains up and active. |
| **TC-10** | Disable Virtual Host | Test site deactivation without file deletion. | Menu Option `6` -> `site1.lab` | Symlink removed from `sites-enabled`; config in `sites-available` and web files preserved. | `site1.lab` no longer routes; files intact. |
| **TC-11** | Re-enable Virtual Host | Test site reactivation. | Menu Option `5` -> `site1.lab` | Symlink recreated, `nginx -t` passes, service reloaded. | `site1.lab` accessible again. |
| **TC-12** | Host Removal Safety | Attempt to remove non-toolkit config vs. toolkit config. | Menu Option `7` -> test with default config, then `site1.lab` | Warns if file is not toolkit-managed; creates pre-removal backup before deletion. | Backup created, clean removal. |
| **TC-13** | Security Audit | Execute automated server security audit. | `./webserver-toolkit.sh --audit` | Evaluates file permissions, `server_tokens`, directory listing, SSL keys, open ports. | Generates PASS/WARN/FAIL tally. |
| **TC-14** | Firewall Safeguard | Inspect UFW handling. | Menu Option `10` | Displays rule without applying; requires explicit user `Y` before modifying UFW. | Never alters UFW without confirmation. |
| **TC-15** | Fail2ban Setup | Inspect optional Fail2ban setup. | Menu Option `11` | Explains daemon, checks Ubuntu compatibility, configures safe Nginx jail upon approval. | Jail file installed, service active. |
| **TC-16** | Secret Scrubbing | Audit log file for sensitive material. | `grep -E 'BEGIN PRIVATE KEY\|BEGIN RSA' webserver-toolkit.log` | Zero matching lines found; log entries redacted. | Strict privacy maintained. |

---

## 3. Step-by-Step Test Execution Guide

### Phase 1: Local / Host Machine Validation (Non-Destructive)
These tests can be safely executed on any development workstation (including macOS or Linux development hosts):

```bash
# 1. Syntax Check
bash -n webserver-toolkit.sh
echo "Syntax check result: $?"

# 2. Command Line Help & Information
./webserver-toolkit.sh --help
./webserver-toolkit.sh --version

# 3. Non-Destructive Environment Checks
./webserver-toolkit.sh --check

# 4. Dry-Run Menu Verification
# Launch in dry-run mode and simulate creating a virtual host
./webserver-toolkit.sh --dry-run
```

### Phase 2: Live Ubuntu Lab Machine / VM Validation

#### Prerequisites: Launching a Clean Ubuntu Test VM
If using **Multipass** (recommended for macOS/Windows/Linux):
```bash
# Launch a lightweight Ubuntu 22.04 or 24.04 instance
multipass launch 24.04 --name os-lab-vm --cpus 2 --memory 2G --disk 10G

# Mount or copy project directory into VM
multipass transfer webserver-toolkit.sh os-lab-vm:/home/ubuntu/
multipass shell os-lab-vm
```

#### Step 1: Install Nginx via Toolkit
1. Run `./webserver-toolkit.sh`.
2. Select `Option 2: Install & Harden Nginx Web Server`.
3. Review the planned package changes and confirm (`y`).
4. Select `Option 9: Check Service Status` to confirm the service is `active (running)`.

#### Step 2: Configure Virtual Hosts
1. Select `Option 3: Create New Virtual Host`:
   - Domain: `site1.lab`
   - Document root: press Enter to accept default (`/var/www/site1.lab`)
   - Enable HTTPS: `n`
2. Select `Option 3: Create New Virtual Host` again:
   - Domain: `site2.lab`
   - Document root: press Enter to accept default (`/var/www/site2.lab`)
   - Enable HTTPS: `y`
   - Review the explanation of self-signed certificate warnings.
3. Select `Option 4: List All Configured Virtual Hosts`:
   - Confirm both `site1.lab` and `site2.lab` are listed as `Enabled`.

#### Step 3: Network and Response Verification
Add domain names to `/etc/hosts`:
```bash
sudo sh -c 'echo "127.0.0.1 site1.lab site2.lab" >> /etc/hosts'
```

Verify responses:
```bash
# Verify HTTP Virtual Host
curl -Iv http://site1.lab

# Verify HTTPS Virtual Host (HTTP port 80 redirects to HTTPS 443)
curl -Iv http://site2.lab

# Verify HTTPS Response (-k allows self-signed certificate)
curl -Ivk https://site2.lab

# Verify TLS cipher and protocol details
curl -vk https://site2.lab 2>&1 | grep -E 'SSL connection using|Server certificate'
```

#### Step 4: Security Hardening Verification
1. Run security audit:
   ```bash
   ./webserver-toolkit.sh --audit
   ```
2. Verify private key permissions:
   ```bash
   ls -la /etc/ssl/private/site2.lab.key
   # Expected permissions: -rw------- (0600) owned by root:root
   ```
3. Verify `server_tokens off`:
   ```bash
   curl -I http://site1.lab | grep -i 'Server:'
   # Expected: "Server: nginx" (version number hidden)
   ```
4. Verify directory listing protection:
   ```bash
   sudo rm -f /var/www/site1.lab/index.html
   curl -I http://site1.lab
   # Expected: HTTP 403 Forbidden (directory enumeration blocked)
   ```

#### Step 5: Lifecycle & Rollback Testing
1. Disable `site1.lab`:
   - Run toolkit -> `Option 6` -> enter `site1.lab`.
   - Confirm symlink is removed from `/etc/nginx/sites-enabled`.
2. Re-enable `site1.lab`:
   - Run toolkit -> `Option 5` -> enter `site1.lab`.
   - Confirm site returns HTTP 200.
3. Test Fault Tolerance / Rollback:
   - Inject an intentional error:
     ```bash
     sudo sh -c 'echo "invalid_nginx_directive_test;" >> /etc/nginx/sites-available/site1.lab.conf'
     ```
   - Attempt to reload via toolkit or run `sudo nginx -t`.
   - Verify that the toolkit detects the error and protects the running web server.
   - Restore from backup using `Option 12`.

---

## 4. Teardown and Post-Test Cleanup
To return the lab machine to a pristine state:
1. Run toolkit -> `Option 7: Remove a Toolkit-Managed Virtual Host` for `site1.lab` and `site2.lab`.
2. Remove test mappings from `/etc/hosts`.
3. If desired, purge Nginx:
   ```bash
   sudo apt-get purge -y nginx nginx-common
   sudo apt-get autoremove -y
   ```
4. Confirm cleanup in log file:
   ```bash
   cat webserver-toolkit.log
   ```
