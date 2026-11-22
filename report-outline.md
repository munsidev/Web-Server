# Course Project Report Outline
## Web Server Setup and Management Toolkit
**Course**: Operating Systems  
**Topic**: Web Server Internals, Virtual Hosting, TLS Cryptography, and Server Hardening on Ubuntu Linux

---

## Abstract
This report documents the design, architecture, implementation, and empirical verification of the **Web Server Setup and Management Toolkit**, an automated Bash-based system administration and security framework targeting Nginx on Ubuntu Linux. The project explores the intersection of core Operating System abstractions (asynchronous I/O multiplexing, process isolation, discretionary access control, and network socket management) with production web server configuration, name-based virtual hosting, Transport Layer Security (TLS 1.3), and automated intrusion prevention.

---

## 1. Introduction and Architectural Motivation
- **1.1 The Role of the Web Server in Modern Operating Systems**:
  - Bridging kernel-space network protocols (TCP/IP) and user-space application logic.
  - Evolution from thread-per-connection / process-per-connection architectures (Apache `prefork`) to asynchronous, non-blocking event-driven architectures (Nginx).
- **1.2 Nginx Architectural Internals**:
  - **Master-Worker Process Model**: Privileged master process for port binding (ports 80/443) and configuration parsing; unprivileged worker processes (`www-data`) for connection handling.
  - **I/O Multiplexing**: Linux `epoll` system call subsystem ($O(1)$ event notifications) vs. legacy `select`/`poll` ($O(N)$ scanning).
  - Efficient file transmission via kernel-space zero-copy: `sendfile()` system call.
- **1.3 Project Scope and Core Requirements**:
  - Educational lab focus: repeatable, automated setup on Ubuntu 20.04/22.04/24.04 LTS.
  - Non-destructive execution, pre-flight safety checks, and atomic rollbacks.

---

## 2. HTTP Protocol and Virtual Hosting Internals
- **2.1 Fundamentals of the HTTP/1.1 and HTTP/2 Protocols**:
  - Request/Response lifecycle, persistent connections (`Keep-Alive`), and multiplexing.
- **2.2 Name-Based Virtual Hosting Mechanism**:
  - The challenge of IP address scarcity: multiple domains bound to a single physical network interface.
  - The role of the HTTP `Host:` request header in directing requests to distinct document roots.
- **2.3 Nginx Configuration Hierarchy**:
  - Modular organization: `/etc/nginx/nginx.conf`, `/etc/nginx/sites-available/`, and `/etc/nginx/sites-enabled/`.
  - Atomic enablement and disabling via symbolic links (`ln -s`).
  - Request routing algorithms: `server_name` resolution and `default_server` precedence.

---

## 3. Transport Layer Security (TLS) and Cryptographic Infrastructure
- **3.1 Principles of Modern Web Encryption**:
  - Symmetric encryption (AES-GCM, ChaCha20-Poly1305) vs. Asymmetric encryption (RSA, ECDSA).
  - Perfect Forward Secrecy (PFS) via Ephemeral Diffie-Hellman key exchange (ECDHE).
- **3.2 Server Name Indication (SNI)**:
  - Overcoming the historical TLS dilemma: the TLS handshake occurs before the HTTP `Host:` header is decrypted.
  - SNI extension in the TLS `ClientHello` enabling multi-tenant HTTPS on a shared IP address.
- **3.3 Public Key Infrastructure (PKI) vs. Lab Self-Signed Certificates**:
  - The Chain of Trust: Root CAs, Intermediate CAs, and end-entity certificates.
  - Cryptographic validity of Self-Signed Certificates: identical mathematical encryption strength without third-party identity attestation.
  - Analysis of browser trust warnings (`NET::ERR_CERT_AUTHORITY_INVALID`).
  - Production contrast: Automated Certificate Management Environment (ACME) protocols (Let's Encrypt), DNS-01 and HTTP-01 challenges, and reasons why private domains (`.lab`, `.local`) cannot obtain public CA certificates.

---

## 4. Operating System Security and Hardening
- **4.1 Discretionary Access Control (DAC) & Privilege Separation**:
  - Principle of Least Privilege: Dropping master privileges to `www-data`.
  - Octal permission model: directory `0755` (`rwxr-xr-x`), file `0644` (`rw-r--r--`), and TLS private key `0600` (`rw-------`).
  - Defense against unauthorized reading of RSA private keys.
- **4.2 Information Disclosure Mitigation**:
  - Hiding daemon banners: configuring `server_tokens off;` to mitigate fingerprinting and automated CVE targeting.
  - Preventing directory enumeration: enforcing `autoindex off;` across all server blocks.
- **4.3 Defense-in-Depth HTTP Response Headers**:
  - `X-Frame-Options: SAMEORIGIN` (Clickjacking mitigation).
  - `X-Content-Type-Options: nosniff` (MIME sniffing and content-type confusion protection).
  - `Referrer-Policy: strict-origin-when-cross-origin` (Information leakage across origins).
- **4.4 Network Attack Surface & Firewall Policy**:
  - Auditing listening TCP sockets using `ss -tlnp`.
  - Restricting ingress traffic via Uncomplicated Firewall (UFW) application profiles (`Nginx Full`).
- **4.5 Dynamic Intrusion Prevention with Fail2ban**:
  - Log tailing and regular expression matching against `/var/log/nginx/*error.log`.
  - Kernel-level packet filtering integration (dynamic `iptables`/`nftables` drop rules).

---

## 5. Software Engineering & Toolkit Implementation
- **5.1 Defensive Bash Scripting Paradigm**:
  - Shell environment robustness (`set -uo pipefail`).
  - Strict input sanitization and domain format validation via regular expressions.
  - Prevention of Command Injection: complete elimination of `eval` constructs.
- **5.2 Safe State Transitions and Rollback Architecture**:
  - Pre-modification snapshots: automated timestamped backups in `/var/backups/nginx-toolkit/`.
  - Atomic configuration verification: executing `nginx -t` before any reload or restart.
  - Graceful rollback: removing invalid symlinks and alerting administrators upon syntax errors.
- **5.3 Dry-Run Simulation Engine**:
  - Non-destructive execution flag (`--dry-run`) providing preview of filesystem and systemd modifications without side effects.
- **5.4 Audit Logging and Secret Redaction**:
  - Redaction of sensitive cryptographic material from persistent logs (`chmod 0600`).

---

## 6. Experimental Verification and Test Results
- **6.1 Multi-Site Virtual Hosting Verification**:
  - Configuring `site1.lab` and `site2.lab` with distinct document roots.
  - Verifying independent content delivery using `curl -H "Host: ..."` and `/etc/hosts` resolution.
- **6.2 HTTP to HTTPS Redirection and TLS Verification**:
  - Validating HTTP 301 Permanent Redirect on port 80.
  - Validating TLS 1.3 protocol negotiation, cipher suites, and certificate Common Name via `curl -v -k`.
- **6.3 Fault Injection and Rollback Resilience**:
  - Intentionally introducing syntax errors into server block files.
  - Confirming that `nginx -t` detects the error, prevents service reload, and protects the active server process.
- **6.4 Automated Security Audit Benchmark**:
  - Executing Toolkit Option 8 to verify permissions, security headers, and port listeners.

---

## 7. Discussion, Limitations, and Future Directions
- **7.1 Architectural Trade-Offs**:
  - Self-contained Bash script vs. Configuration Management systems (Ansible, Puppet, Chef).
- **7.2 Limitations of Local Lab Deployments**:
  - Inability to obtain public CA certificates without public DNS ownership.
  - Browser trust exceptions required for self-signed certificates.
- **7.3 Future Enhancements**:
  - Automated local Certificate Authority (CA) generation using `mkcert` to eliminate browser trust warnings across local test fleets.
  - Dynamic reverse proxying and FastCGI/PHP-FPM integration.
  - Containerized deployment using Docker and OCI images.

---

## 8. Conclusions
- Summary of learning outcomes in operating systems, systems administration, network security, and defensive programming.

---

## 9. References and Standards
1. Fielding, R., et al. (2022). *HTTP/1.1: Semantics and Content*, RFC 9110.
2. Rescorla, E. (2018). *The Transport Layer Security (TLS) Protocol Version 1.3*, RFC 8446.
3. Eastlake, D. (2011). *Transport Layer Security (TLS) Extensions: Extension Definitions*, RFC 6066 (Server Name Indication).
4. Nginx Documentation: *Event-driven Architecture and Module Architecture* (https://nginx.org/en/docs/).
5. Center for Internet Security (CIS): *CIS Nginx Benchmark v1.1.0*.
6. Ubuntu Server Documentation: *Security and Firewall Management (UFW & Fail2ban)*.
