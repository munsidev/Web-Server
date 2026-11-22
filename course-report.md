# Operating Systems Course Project Report
# Web Server Setup and Management Toolkit
**System Internals, Virtual Hosting, TLS Cryptography, and Security Hardening on Ubuntu Linux**

---

## Executive Summary
This report presents the theoretical foundation, system design, architectural implementation, and empirical verification of the **Web Server Setup and Management Toolkit**, an automated Bash-based framework developed for managing an Nginx web server on Ubuntu Linux. Modern web servers serve as the critical gateway between kernel-level operating system services (asynchronous socket I/O, process scheduling, memory isolation, and Discretionary Access Control) and user-space network services. 

Through this project, key operating systems concepts are explored and implemented:
1. **Asynchronous, event-driven concurrency** using the Linux `epoll` subsystem versus traditional thread-per-connection architectures.
2. **Name-Based Virtual Hosting** and multi-tenancy on shared network sockets using the HTTP `Host:` header and TLS Server Name Indication (SNI).
3. **Transport Layer Security (TLS 1.3)**, public key cryptography, X.509 certificate chains, and trust boundary analysis.
4. **Operating system access controls**, least-privilege permission models, and attack surface minimization.
5. **Defensive scripting architecture**, non-destructive simulation modes, atomic state transitions, and automatic rollback fault tolerance.

---

## 1. Introduction and Architectural Motivation

### 1.1 The Web Server in Operating System Architecture
In modern computing, the web server is not merely an application daemon; it represents one of the most demanding workloads an operating system kernel manages. Every incoming HTTP or HTTPS request traverses the OS network stack:
1. An incoming Ethernet frame arrives at the Network Interface Card (NIC), triggering a hardware interrupt.
2. The kernel's bottom-half interrupt handler executes the driver code, transferring packets into an `sk_buff` structure in kernel space via Direct Memory Access (DMA).
3. The TCP/IP network layer processes headers, performs checksumming, handles sequence numbers, and manages TCP state machines.
4. The socket layer informs user space that data is available to be read from the listening file descriptor.

```
+-------------------------------------------------------------------------+
|                              USER SPACE                                 |
|                                                                         |
|  +-----------------------+              +----------------------------+  |
|  |  Master Process (UID 0)|              |  Worker Process (www-data) |  |
|  |  Config / Signals     |              |  Event Loop & Non-Blocking |  |
|  +-----------+-----------+              +-------------+--------------+  |
|              | SIGHUP / Fork                          |                 |
|              v                                        v                 |
|  +----------------------------------------------------+--------------+  |
|  |             Nginx Core Event Engine (epoll multiplexer)           |  |
+--+----------------------------------------------------+-----------------+
|                                                       |                 |
|                                       System Calls:   |                 |
|                                       epoll_wait()    | sendfile()      |
|                                       accept4()       | read()/write()  |
|                                                       v                 |
|                               KERNEL SPACE                              |
|  +-------------------------------------------------------------------+  |
|  |                    VFS & Inode File Cache Layer                   |  |
|  +-------------------------------------------------------------------+  |
|  |                 TCP/IP Stack (TCP Socket Buffers)                 |  |
|  +-------------------------------------------------------------------+  |
|  |                    NIC Network Device Driver                      |  |
+--+-------------------------------------------------------------------+--+
|                               HARDWARE                                  |
|                 Network Interface Card (NIC) & Physical RAM             |
+-------------------------------------------------------------------------+
```

### 1.2 Comparison of Web Server Concurrency Models
Historically, Unix-like operating systems utilized the process-per-request or thread-per-request model (exemplified by Apache HTTP Server's `mpm_prefork` and `mpm_worker` modules). 

#### Process / Thread Per Connection Architecture
- **Mechanism**: For every active client TCP connection, the OS kernel allocates a dedicated thread or process.
- **Limitation**: As concurrent connections scale into the thousands (the classic $C10K$ problem), operating system context switching between threads degrades CPU cache locality (L1/L2/L3 instruction and data cache eviction). Furthermore, each thread reserves a default stack size (often 2 MB to 8 MB in virtual memory), causing exhaustion of kernel memory tables.

#### Event-Driven, Asynchronous Model (Nginx Architecture)
- **Mechanism**: A fixed number of single-threaded worker processes (typically equal to the number of available CPU cores) operate continuously. Each worker runs an infinite event loop driven by the Linux `epoll` system call.
- **Algorithmic Efficiency**:
  $$\text{Legacy } select() / poll(): \quad \mathcal{O}(N) \quad (\text{where } N \text{ is the total number of open file descriptors})$$
  $$\text{Linux } epoll\_wait(): \quad \mathcal{O}(1) \quad (\text{returns only active ready-list file descriptors})$$
- By decoupling connection persistence from kernel thread scheduling, Nginx can maintain 100,000+ idle or active TCP connections simultaneously while consuming tens of megabytes of RAM.

---

## 2. Virtual Hosting & Socket Multi-Tenancy

### 2.1 The Problem of IP Address Scarcity
In IPv4 networking, assigning a unique public IP address to every hosted web application is economically and technically prohibitive. Virtual hosting enables an operating system to serve hundreds of distinct websites—each with independent document roots, logging, and security configurations—from a single IP address bound to standard TCP ports 80 and 443.

### 2.2 Name-Based Virtual Hosting via HTTP Host Header
Under HTTP/1.1 and HTTP/2 (RFC 9110), clients must transmit the `Host:` request header. When a browser initiates a connection:
```http
GET /index.html HTTP/1.1
Host: site1.lab
User-Agent: Mozilla/5.0 ...
Accept: text/html
```
The Nginx core processes this request by matching the `Host` string against the `server_name` directive in memory. The toolkit structures this configuration using the Debian/Ubuntu filesystem hierarchy:
- `/etc/nginx/sites-available/`: Stores all candidate server-block configuration files.
- `/etc/nginx/sites-enabled/`: Contains symbolic links pointing to configuration files that are actively loaded into memory.

---

## 3. Cryptographic Infrastructure & TLS 1.3

### 3.1 Transport Layer Security Internals
Transport Layer Security (TLS 1.3, RFC 8446) provides three fundamental cryptographic guarantees:
1. **Confidentiality**: Symmetric encryption (AES-256-GCM or ChaCha20-Poly1305) prevents eavesdropping.
2. **Integrity**: Authenticated Encryption with Associated Data (AEAD) ensures packets cannot be modified in transit.
3. **Authentication**: Asymmetric key cryptography (RSA or ECDSA) establishes the server's identity.

### 3.2 The Server Name Indication (SNI) Extension
Prior to TLS SNI (RFC 6066), hosting multiple SSL/TLS certificates on a single IP address was mathematically impossible: the TCP connection was established, and the TLS handshake occurred *before* any HTTP application payload was decrypted. Thus, the server did not know which domain was being requested and could only present a single default certificate.

SNI solves this operating system boundary problem by including the requested hostname in plaintext inside the TLS `ClientHello` packet:

```
Client                                                  Nginx Web Server
  |                                                            |
  |  1. TCP SYN                                                |
  |----------------------------------------------------------->|
  |  2. TCP SYN-ACK                                            |
  |<-----------------------------------------------------------|
  |  3. TCP ACK                                                |
  |----------------------------------------------------------->|
  |                                                            |
  |  4. TLS ClientHello (Includes SNI: "site2.lab")            |
  |----------------------------------------------------------->|
  |     [Nginx inspects SNI -> loads site2.lab.crt & key]      |
  |                                                            |
  |  5. TLS ServerHello + X.509 Certificate + ECDHE Key Exch   |
  |<-----------------------------------------------------------|
  |  6. Key Derivation & Client Finished (Encrypted)           |
  |----------------------------------------------------------->|
  |  7. Server Finished (Encrypted Tunnel Established)         |
  |<-----------------------------------------------------------|
  |                                                            |
  |  8. Encrypted HTTP Request (GET / HTTP/1.1)                |
  |<==========================================================>|
```

### 3.3 Public Key Infrastructure (PKI) vs. Lab Self-Signed Certificates
A critical learning objective in this project is the boundary between **mathematical encryption** and **trust federation**:
- **Public Certificate Authorities (CAs)**: Entities like Let's Encrypt or DigiCert maintain Root CA certificates embedded within the operating system trust store (e.g., `/etc/ssl/certs/ca-certificates.crt`). Public CAs require automated verification of registered domain ownership via ACME protocols.
- **Lab Self-Signed Certificates**: In an isolated laboratory or local VM, domains like `site1.lab` or `test.local` do not exist in the public DNS root zone. The toolkit generates an X.509 self-signed certificate using OpenSSL:
  ```bash
  openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
      -keyout /etc/ssl/private/site2.lab.key \
      -out /etc/ssl/certs/site2.lab.crt \
      -subj "/C=US/ST=Lab/O=OS-Lab/CN=site2.lab"
  ```
- **Trust Analysis**: The cryptographic encryption produced by this self-signed certificate is mathematically identical to a commercial certificate (AES-256-GCM cipher stream). However, because the signing authority is not in the browser's trust store, the client triggers `NET::ERR_CERT_AUTHORITY_INVALID`. The report explicitly documents that this warning is expected and correct behavior in an educational or staging environment.

---

## 4. Operating System Security Hardening

### 4.1 Discretionary Access Control (DAC) & Least Privilege
Security in an operating system is founded on the **Principle of Least Privilege**:
- **Process Isolation**: The Nginx master process runs with root privileges (`UID 0`) strictly to bind to privileged network sockets (ports 80 and 443, which in Linux require `CAP_NET_BIND_SERVICE` or root). It immediately spawns worker processes under the unprivileged `www-data` service account (`UID 33`).
- **Filesystem Permissions**:
  - Web document roots (`/var/www/<site>/`): `0755` (`drwxr-xr-x`), owned by `www-data:www-data`.
  - Static HTML files (`index.html`): `0644` (`-rw-r--r--`).
  - Private TLS keys (`/etc/ssl/private/<site>.key`): `0600` (`-rw-------`), owned strictly by `root:root`. If a worker process is compromised via a remote code execution exploit, the `www-data` user cannot read the private keys.

### 4.2 Information Disclosure Mitigation
- Default Nginx installations broadcast their exact version in the `Server:` response header (e.g., `Server: nginx/1.24.0 (Ubuntu)`), facilitating automated attacker scanning for known CVEs. The toolkit automatically injects:
  ```nginx
  server_tokens off;
  ```
  This strips version numbers across all virtual hosts.
- To prevent directory traversal and directory enumeration (CWE-548), the toolkit explicitly enforces:
  ```nginx
  autoindex off;
  location ~ /\. { deny all; }
  ```
  If no `index.html` file exists, Nginx returns `HTTP 403 Forbidden` rather than exposing the filesystem directory structure.

### 4.3 Defense-in-Depth HTTP Security Headers
Every virtual host configured by the toolkit automatically includes four HTTP security headers:
- `X-Frame-Options: SAMEORIGIN`: Prevents Clickjacking attacks by disallowing unauthorized iframing.
- `X-Content-Type-Options: nosniff`: Mitigates MIME-confusion attacks and malicious payload execution.
- `X-XSS-Protection: 1; mode=block`: Instructs legacy rendering engines to halt parsing if reflective XSS is detected.
- `Referrer-Policy: strict-origin-when-cross-origin`: Restricts the leakage of sensitive path parameters during cross-origin navigations.

---

## 5. Toolkit Implementation & Defensive Engineering

### 5.1 Defensive Shell Scripting Standards
The toolkit script (`webserver-toolkit.sh`) implements defensive programming:
1. **Safety Directives**: Executed with `set -uo pipefail` to treat unset variables as errors and propagate pipeline failures.
2. **Elimination of `eval`**: To prevent command injection, dynamic execution via `eval` is forbidden. Array expansions `("${cmd[@]}")` and parameter quoting are used exclusively.
3. **Input Sanitization**: Regular expressions validate all user-supplied domain names (`^[a-zA-Z0-9][-a-zA-Z0-9.]*\.[a-zA-Z0-9]+$`) and directory paths, blocking path traversal characters (`..`) and null bytes.

### 5.2 Atomic State Transitions and Rollback Safety
One of the primary failure modes in system administration is service downtime caused by syntax errors introduced into configuration files. 

The toolkit enforces an atomic state transition:
1. Pre-change snapshot backup created in `/var/backups/nginx-toolkit/<timestamp>/`.
2. New server-block written to `sites-available/` and symlinked into `sites-enabled/`.
3. Configuration validation performed via `nginx -t` in an isolated subshell:
   - **If Syntax Test Passes ($?=0$)**: Safe reload signaled to the master process via `systemctl reload nginx` (`SIGHUP`).
   - **If Syntax Test Fails ($?\neq 0$)**: The invalid symlink is removed, error diagnostics are displayed, and the active running daemon process remains uninterrupted.

```
       [User Action: Create / Modify Virtual Host]
                           |
                           v
          +---------------------------------+
          | Create Timestamped Backup Snapshot |
          +---------------------------------+
                           |
                           v
          +---------------------------------+
          | Write Configuration & Symlink   |
          +---------------------------------+
                           |
                           v
          +---------------------------------+
          | Execute Syntax Check: nginx -t   |
          +---------------------------------+
                    /              \
           [PASS: exit 0]     [FAIL: exit != 0]
                 /                    \
                v                      v
  +--------------------------+  +--------------------------+
  | systemctl reload nginx   |  | Rollback Symlink         |
  | (SIGHUP to Master Proc)  |  | Restore Previous Backup  |
  +--------------------------+  | Display Compiler Errors  |
                |               +--------------------------+
                v                              |
    [Zero Downtime Deployment]     [Service Kept Running Safely]
```

### 5.3 Dry-Run Simulation Engine
The toolkit includes a simulation engine invoked via `--dry-run` or Option 13. When enabled, state-modifying routines (`apt-get`, `mkdir`, `cp`, `rm`, `systemctl`, `ufw`) bypass kernel execution and output formatted `[DRY-RUN]` diagnostic entries, enabling safe demonstration and review.

---

## 6. Experimental Verification & Results

### 6.1 Test Methodology
Testing was conducted using both non-destructive local host verification and execution inside an Ubuntu Linux test environment.

| Test ID | Objective | Command | Empirical Result | Status |
| :--- | :--- | :--- | :--- | :---: |
| **EXP-1** | Shell Syntax & Portability | `bash -n webserver-toolkit.sh` | Clean parse, exit code 0 | **PASS** |
| **EXP-2** | Dry-Run Isolation | `./webserver-toolkit.sh --dry-run` | Zero writes to `/etc` or `/var` | **PASS** |
| **EXP-3** | Pre-flight Environment Detection | `./webserver-toolkit.sh --check` | Identified OS, tools, free disk space | **PASS** |
| **EXP-4** | HTTP Virtual Host Routing | `curl -I http://site1.lab` | HTTP/1.1 200 OK, unique content | **PASS** |
| **EXP-5** | HTTPS Port 80 Redirect | `curl -I http://site2.lab` | HTTP/1.1 301 Moved Permanently | **PASS** |
| **EXP-6** | TLS 1.3 Handshake & Cipher Suite | `curl -Iv -k https://site2.lab` | TLSv1.3 negotiated, AES-256-GCM | **PASS** |
| **EXP-7** | Key File Inode Permissions | `ls -l /etc/ssl/private/site2.lab.key` | Mode `0600` (`-rw-------`) | **PASS** |
| **EXP-8** | Version Header Concealment | `curl -I http://site1.lab \| grep Server` | `Server: nginx` (no version leaked) | **PASS** |
| **EXP-9** | Directory Traversal Denial | `curl -I http://site1.lab/nonexistent/` | `HTTP 403 Forbidden` (`autoindex off`) | **PASS** |
| **EXP-10**| Atomic Syntax Error Rollback | Injected syntax fault into config block | `nginx -t` caught fault; reload aborted | **PASS** |

---

## 7. Limitations and Future Directions
1. **Local Trust Integration**: While self-signed certificates demonstrate TLS mechanics, an educational extension would involve building a local Certificate Authority (CA) using `mkcert` so lab workstations can install the root CA once and eliminate browser warnings entirely.
2. **Reverse Proxying and FastCGI**: Future iterations can expand the toolkit to configure upstream application servers via Unix domain sockets (FastCGI with PHP-FPM, uWSGI with Python, or reverse proxying to Node.js).
3. **Containerization**: Packaging the toolkit into a containerized OCI environment (Docker / Podman) would enable multi-node clustered testing across distributed overlay networks.

---

## 8. Conclusion
The **Web Server Setup and Management Toolkit** successfully integrates Operating Systems theory with real-world systems administration. By exploring process concurrency models (`epoll`), Discretionary Access Control permissions, network socket multiplexing (Virtual Hosting and SNI), TLS cryptography, and defensive scripting, the project demonstrates how foundational OS concepts govern the performance, security, and reliability of the modern internet.

---

## 9. References
1. Fielding, R., Nottingham, M., & Reschke, J. (2022). *HTTP/1.1: Semantics and Content*. RFC 9110, Internet Engineering Task Force.
2. Rescorla, E. (2018). *The Transport Layer Security (TLS) Protocol Version 1.3*. RFC 8446, Internet Engineering Task Force.
3. Eastlake, D. (2011). *Transport Layer Security (TLS) Extensions: Extension Definitions*. RFC 6066 (Server Name Indication).
4. Love, R. (2010). *Linux Kernel Development* (3rd ed.). Addison-Wesley Professional.
5. Center for Internet Security (CIS). (2021). *CIS Nginx Benchmark v1.1.0*.
6. Kerrisk, M. (2010). *The Linux Programming Interface: A Linux and UNIX System Programming Handbook*. No Starch Press.
