# 🛡️ kali-burp-mcp-bridge

<div align="center">

### *The Ultimate AI-Powered Penetration Testing MCP Server*

[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![MCP Protocol](https://img.shields.io/badge/MCP-v1.2%2B-purple?style=for-the-badge&logo=anthropic&logoColor=white)](https://modelcontextprotocol.io)
[![Burp Suite](https://img.shields.io/badge/Burp%20Suite-Compatible-orange?style=for-the-badge&logo=portswigger&logoColor=white)](https://portswigger.net)
[![Kali Linux](https://img.shields.io/badge/Kali%20Linux-Ready-red?style=for-the-badge&logo=kalilinux&logoColor=white)](https://kali.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)
[![Stars](https://img.shields.io/github/stars/hyperps/kali-burp-mcp-bridge?style=for-the-badge&color=yellow)](https://github.com/hyperps/kali-burp-mcp-bridge/stargazers)

**Connect Claude, ChatGPT, Cursor, and any MCP-compatible AI to your full Kali Linux + Burp Suite security toolkit.**

Run `nmap`, `sqlmap`, `metasploit`, `hydra`, `nuclei` and 60+ more tools — all from a single chat prompt.

[🚀 Quick Start](#-quick-start) · [🔧 All Tools](#-available-tools) · [🤖 AI Setup](#-connecting-your-ai) · [📖 Examples](#-usage-examples) · [🙏 Credits](#-credits)

</div>

---

> ⚠️ **Legal Disclaimer:** This tool is intended for **authorized penetration testing and security research only**. Always obtain explicit written permission before testing any system you do not own. Misuse of this tool is illegal and unethical. The authors accept no liability for unauthorized use.
#### This project is not intended to be exposed publicly without authentication. The kali-burp-mcp-bridge server is designed to run locally or behind a trusted boundary (e.g., internal lab environment, VPN, or secured reverse proxy) and is expected to be protected by an authentication token or equivalent access control mechanism at deployment time.
#### The functions highlighted (Metasploit integration, CLI wrappers, file-based tooling, etc.) are intentionally designed for controlled offensive security environments where the operator is already trusted and authorized. This bridge acts as a thin execution layer between MCP and local security tooling — not as a hardened multi-tenant API service.
---

## 📌 What Is This?

`kali-burp-mcp-bridge` (entry point: **`server.py`**) is a **Model Context Protocol (MCP) server** that gives any AI assistant — Claude, ChatGPT, Cursor, and more — direct, real-time access to your Kali Linux security toolchain and Burp Suite REST API.

It bridges three powerful layers into one conversational interface:

```
You ──► AI Chat ──► server.py (MCP Server) ──► 🔴 Burp Suite REST API
                                           ├──► 🟡 Kali Linux CLI Tools
                                           └──► 🟢 Pure Python Security Modules
```

Instead of switching between terminals and GUI tools, you simply describe what you want:

> *"Scan 10.10.10.5 for open ports, identify services, and check for known CVEs"*

And your AI assistant automatically calls `nmap_scan`, `whatweb_scan`, and `search_cve_by_keyword` for you.

---

## 🏗️ Architecture

```
╔══════════════════════════════════════════════════════════════╗
║           kali-burp-mcp-bridge  v3.0  (server.py)           ║
╠══════════════════════════════════════════════════════════════╣
║  🔴 Layer 1 — Burp Suite REST API  (port 9876)              ║
║     Proxy history · Active/passive scanner · Repeater        ║
║     Intruder · Collaborator OOB · Encoding · Config          ║
╠══════════════════════════════════════════════════════════════╣
║  🟡 Layer 2 — Kali Linux CLI Tools                          ║
║     nmap · masscan · nikto · gobuster · ffuf · dirb          ║
║     sqlmap · hydra · john · hashcat · metasploit             ║
║     whatweb · wpscan · nuclei · enum4linux · smbclient       ║
║     subfinder · amass · fierce · dnsx · sslscan              ║
║     curl · wget · netcat · openssl · whois · dig             ║
╠══════════════════════════════════════════════════════════════╣
║  🟢 Layer 3 — Pure Python Security Modules                  ║
║     JWT decode/forge/brute · CORS · HTTP smuggling           ║
║     SSRF probe · Cache poisoning · OAuth analysis            ║
║     GraphQL introspect · Session entropy · Param mining      ║
║     CVE lookup · GitHub secret scan · Exploit templates      ║
╚══════════════════════════════════════════════════════════════╝

  MCP Transport:  stdio (default)  |  SSE port 8082 (--transport sse)
  Burp REST API:  http://127.0.0.1:9876  (via BurpAI extension)
```

---

## 🚀 Quick Start

### Step 1 — Clone the Repo

```bash
git clone https://github.com/yourusername/kali-burp-mcp-bridge.git
cd kali-burp-mcp-bridge
```

### Step 2 — Install Python Dependencies

The script uses inline PEP 723 dependency metadata, so you can use `uv` for zero-config setup:

```bash
# Option A — using uv (recommended, auto-installs all deps)
pip install uv
uv run server.py

# Option B — using pip manually
pip install "requests>=2,<3" "mcp>=1.2.0,<2" "flask>=3,<4" "websocket-client>=1.6"
python3 server.py
```

### Step 3 — Install Kali Security Tools

```bash
sudo apt-get update && sudo apt-get install -y \
  nmap masscan nikto gobuster dirb ffuf sqlmap \
  hydra john hashcat whatweb wpscan \
  enum4linux smbclient netcat-openbsd \
  curl wget whois dnsutils sslscan \
  amass subfinder fierce \
  metasploit-framework

# Wordlists
sudo apt-get install -y wordlists seclists
sudo gunzip /usr/share/wordlists/rockyou.txt.gz 2>/dev/null || true

# Go-based tools (nuclei, dnsx, ffuf, gobuster latest)
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/ffuf/ffuf/v2@latest
```

> You can also install any missing tool at any time by asking your AI: *"Install nuclei"* — the `install_tool` function handles apt, pip, and go automatically.

### Step 4 — Connect Your AI

See the full connection guide below.

---

## 🤖 Connecting Your AI

### 🟣 Claude (Anthropic) — Claude Desktop App

Claude supports MCP natively via the Desktop app. This is the easiest and most powerful integration.

**Find your config file:**

| OS | Path |
|----|------|
| macOS | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| Windows | `%APPDATA%\Claude\claude_desktop_config.json` |
| Linux | `~/.config/Claude/claude_desktop_config.json` |

**Add this to your config:**

```json
{
  "mcpServers": {
    "kali-burp": {
      "command": "python3",
      "args": ["/full/path/to/kali-burp-mcp-bridge/server.py"],
      "env": {
        "BURP_URL": "http://127.0.0.1:9876",
        "BURP_API_KEY": "",
        "TOOL_TIMEOUT": "120"
      }
    }
  }
}
```

Restart Claude Desktop. You will see the 🔧 tools icon in the chat interface confirming the MCP server is active.

**For a remote Kali machine, use SSE mode:**

```bash
# On your Kali machine
python3 server.py --transport sse --mcp-host 0.0.0.0 --mcp-port 8082
```

```json
{
  "mcpServers": {
    "kali-burp-remote": {
      "url": "http://YOUR_KALI_IP:8082/sse"
    }
  }
}
```

---

### 🟢 Claude.ai (Web Interface)

Claude.ai supports MCP via remote SSE connections.

```bash
# Start SSE server on your machine
python3 server.py --transport sse --mcp-host 0.0.0.0 --mcp-port 8082
```

In Claude.ai settings, navigate to **Integrations → Add MCP Server** and enter:

```
http://YOUR_IP:8082/sse
```

> For claude.ai to reach your server over the internet, expose the port or use a tunnel:
> ```bash
> ngrok http 8082
> # Then use the ngrok HTTPS URL in claude.ai
> ```

---

### 🟡 ChatGPT / OpenAI — Agents SDK

ChatGPT connects via the SSE transport using the OpenAI Agents SDK.

```bash
# Start SSE server first
python3 server.py --transport sse --mcp-port 8082
```

```python
# pip install openai-agents
from agents import Agent, MCPServerSse
import asyncio

async def main():
    async with MCPServerSse(
        name="kali-burp",
        params={"url": "http://127.0.0.1:8082/sse"},
    ) as mcp_server:
        agent = Agent(
            name="PenTest Agent",
            instructions="You are an expert penetration tester. Use the available tools to help test targets.",
            mcp_servers=[mcp_server],
        )
        result = await agent.run("Scan 10.10.10.5 for open ports and identify services")
        print(result.final_output)

asyncio.run(main())
```

---

### 🔵 Cursor IDE

Add to `~/.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "kali-burp": {
      "command": "python3",
      "args": ["/full/path/to/server.py"],
      "env": {
        "BURP_URL": "http://127.0.0.1:9876",
        "TOOL_TIMEOUT": "120"
      }
    }
  }
}
```

Restart Cursor. The tools appear automatically in the AI chat panel.

---

### 🟠 Windsurf (Codeium)

Add to your Windsurf MCP configuration file:

```json
{
  "mcp": {
    "servers": {
      "kali-burp": {
        "command": "python3",
        "args": ["/full/path/to/server.py"],
        "env": {
          "BURP_URL": "http://127.0.0.1:9876"
        }
      }
    }
  }
}
```

---

### ⚪ Any MCP-Compatible Client (Generic SSE)

```bash
# Start in SSE mode
python3 server.py --transport sse --mcp-host 0.0.0.0 --mcp-port 8082

# Connect any MCP client to:
# http://YOUR_HOST:8082/sse
```

This works with LangChain MCP adapters, CrewAI, AutoGen, LlamaIndex, and any framework that supports the MCP SSE transport protocol.

---

## 🔧 Available Tools

### 🌐 Network Scanning

| Tool | Description |
|------|-------------|
| `nmap_scan` | Port and service scan with custom flags (e.g. `-sV -T4 --open`) |
| `nmap_vuln_scan` | Run all Nmap vuln NSE scripts against a target |
| `nmap_os_detect` | OS fingerprinting with `-O -sV -A` |
| `nmap_full_port_scan` | Scan all 65535 ports (slow but thorough) |
| `nmap_udp_scan` | UDP scan for top N ports (requires root) |
| `nmap_script` | Run any specific NSE script (e.g. `smb-vuln-ms17-010`) |
| `masscan_fast` | Ultra-fast packet-level port sweep with configurable rate |

### 🕸️ Web Scanning and Fuzzing

| Tool | Description |
|------|-------------|
| `nikto_scan` | Web server vulnerability scan by host and port |
| `nikto_scan_url` | Nikto scan using a full URL (auto-detects HTTPS) |
| `gobuster_dir` | Directory and file brute-force with extension support |
| `gobuster_dns` | Subdomain brute-force via DNS resolution |
| `gobuster_vhost` | Virtual host enumeration |
| `dirb_scan` | Classic directory scan (fallback when gobuster unavailable) |
| `ffuf_dir` | Fast web directory fuzzing using FUZZ placeholder |
| `ffuf_param` | Parameter fuzzing with custom HTTP method and POST data |
| `wpscan` | WordPress scanner for users, plugins, themes, and timthumbs |
| `nuclei_scan` | Template-based vulnerability scanning (community templates) |
| `nuclei_scan_list` | Nuclei against a file containing multiple target URLs |
| `whatweb_scan` | Web technology fingerprinting with configurable aggression |

### 💉 SQL Injection

| Tool | Description |
|------|-------------|
| `sqlmap_scan` | Full SQL injection test on a URL |
| `sqlmap_dbs` | Enumerate available databases |
| `sqlmap_tables` | Enumerate tables within a specific database |
| `sqlmap_dump` | Dump data from a database or table |
| `sqlmap_os_shell` | Attempt OS command execution via SQLi |
| `sqlmap_request_file` | Test from a saved Burp Suite request file |

### 🔐 Brute Force and Hash Cracking

| Tool | Description |
|------|-------------|
| `hydra_ssh` | SSH credential brute-force |
| `hydra_ftp` | FTP credential brute-force |
| `hydra_smb` | SMB credential brute-force |
| `hydra_http_post` | HTTP POST login form attack with fail string |
| `hydra_service` | Generic service attack (rdp, smtp, mysql, mssql, telnet, etc.) |
| `john_crack` | John the Ripper with wordlist and optional rules |
| `john_show` | Display previously cracked passwords |
| `hashcat_crack` | GPU-accelerated cracking (MD5, NTLM, SHA1, bcrypt, etc.) |

### 💣 Exploitation — Metasploit

| Tool | Description |
|------|-------------|
| `msf_exploit` | Run an exploit with RHOSTS, LHOST, LPORT, PAYLOAD options |
| `msf_generate_payload` | msfvenom payload generation (exe, elf, apk, ps1, dll, raw) |
| `msf_search` | Search the Metasploit module database by keyword |
| `msf_module_info` | Get detailed information on a specific module |
| `msf_run_resource` | Execute a full multi-line Metasploit .rc resource script |

### 🔍 Reconnaissance and OSINT

| Tool | Description |
|------|-------------|
| `subfinder_enum` | Passive subdomain enumeration via OSINT sources |
| `amass_enum` | Active and passive subdomain mapping |
| `enumerate_subdomains` | crt.sh certificate transparency logs plus DNS resolution |
| `fierce_dns` | DNS reconnaissance and zone transfer attempts |
| `dnsx_resolve` | Fast DNS resolution with A, CNAME, MX, NS records |
| `whois_lookup` | WHOIS data for a domain or IP address |
| `dig_query` | DNS query for any record type via any nameserver |
| `enum4linux` | SMB and LDAP enumeration for shares, users, and groups |
| `smbclient_list_shares` | List SMB shares on a target |
| `smbclient_connect` | Connect to an SMB share and execute commands |
| `github_repo_secret_scan` | Scan GitHub repo commits for exposed API keys and secrets |

### 🔑 JWT and Authentication Testing

| Tool | Description |
|------|-------------|
| `jwt_decode` | Decode JWT header and payload, detect algorithm and expiry issues |
| `jwt_forge_none_alg` | Generate `alg:none` bypass tokens (4 casing variants) |
| `jwt_brute_secret` | Brute-force HS256 secret against common passwords or a wordlist |
| `analyze_oauth_flow` | Detect OAuth misconfigurations: implicit flow, missing state, missing PKCE |

### 🕵️ Advanced Web Vulnerability Testing

| Tool | Description |
|------|-------------|
| `test_cors_misconfiguration` | Test CORS policy for origin reflection and credential leakage |
| `detect_request_smuggling` | Raw socket HTTP smuggling detection (CL.TE and TE.CL techniques) |
| `test_host_header_injection` | Host header injection via X-Forwarded-Host and OOB Collaborator |
| `detect_cache_poisoning` | Unkeyed header cache poisoning detection |
| `probe_ssrf` | SSRF via AWS/GCP/Azure metadata endpoints and Burp Collaborator OOB |
| `scan_open_redirects` | Open redirect scanning across common URL parameters |
| `mine_hidden_parameters` | Discover hidden parameters by comparing response length and status |
| `graphql_introspect` | GraphQL schema extraction via introspection query |
| `discover_api_endpoints_from_js` | Extract API paths, secrets, and external URLs from JavaScript files |
| `analyze_session_entropy` | Token entropy analysis and sequential pattern detection |

### 🎯 Payloads and Exploit Templates

| Tool | Description |
|------|-------------|
| `get_payloads` | Return payloads for: sqli, xss, ssti, ssrf, xxe, lfi, cmd_injection, open_redirect |
| `get_all_payload_types` | List all available payload categories |
| `generate_exploit_template` | Generate a ready-to-run Python exploit script for a vulnerability type |
| `auto_exploit_from_scan` | Pull Burp scanner findings and auto-generate exploit scripts per issue |
| `build_intruder_attack` | Load Burp Intruder with generated payloads for a given attack type |

### 🔬 CVE Intelligence

| Tool | Description |
|------|-------------|
| `lookup_cve` | Full CVE details from NVD including CVSS v3 score and references |
| `search_cve_by_keyword` | Keyword-based CVE search against the NVD database |
| `tech_to_cves` | Map a detected technology and version to known CVEs |
| `github_advisory_search` | GitHub Security Advisories by ecosystem, severity, or keyword |

### 🔒 SSL and TLS Testing

| Tool | Description |
|------|-------------|
| `sslscan` | Test SSL/TLS ciphers, protocols, and known vulnerabilities |
| `testssl` | Comprehensive TLS testing with testssl.sh |
| `openssl_check_cert` | Display full certificate chain and certificate details |

### 🌊 Burp Suite REST API

| Category | Tools |
|----------|-------|
| **Proxy** | `get_proxy_http_history`, `get_proxy_http_history_regex`, `get_proxy_websocket_history`, `get_proxy_websocket_history_regex`, `set_proxy_intercept_state` |
| **Scanner** | `burp_active_scan`, `burp_passive_scan`, `burp_get_scan_status`, `burp_cancel_scan`, `get_scanner_issues` |
| **Repeater** | `send_http1_request`, `send_http2_request`, `create_repeater_tab`, `replay_and_diff` |
| **Intruder** | `send_to_intruder`, `build_intruder_attack` |
| **Collaborator** | `generate_collaborator_payload`, `get_collaborator_interactions` |
| **Encoding** | `base64_encode`, `base64_decode`, `url_encode`, `url_decode`, `generate_random_string` |
| **Config** | `output_project_options`, `output_user_options`, `set_project_options`, `set_user_options`, `set_task_execution_engine_state`, `get_active_editor_contents`, `set_active_editor_contents` |

### ⚙️ System and Workflow Tools

| Tool | Description |
|------|-------------|
| `recon_target` | Full recon pipeline: nmap + whatweb + whois + subdomains + CVE hints |
| `full_web_audit` | Complete web audit: nikto + gobuster + CORS + param mining + JS analysis |
| `chain_vulnerabilities_into_narrative` | Build structured attack chain narratives from Burp scanner findings |
| `list_all_tools` | List every available tool organized by category |
| `list_installed_tools` | Show which Kali tools are installed vs missing |
| `install_tool` | Auto-install any missing tool via apt-get, pip, or go install |
| `install_wordlists` | Install rockyou, dirb, and SecLists wordlists |
| `run_command` | Execute any arbitrary bash command directly |
| `curl_request` | HTTP request with full control over method, headers, data, and proxy |
| `wget_download` | Download files from a URL |
| `nc_banner_grab` | Service banner grabbing via netcat |
| `burp_health_check` | Verify Burp REST API connectivity |

---

## 📖 Usage Examples

Once `server.py` is connected to your AI assistant, just speak naturally:

### Reconnaissance

```
"Run a full port scan on 10.10.10.5 and identify all running services"
"Enumerate subdomains for example.com and resolve their IP addresses"
"Do a WHOIS lookup and a service scan on 192.168.1.0/24"
"Find subdomains of target.com using both subfinder and amass"
"Check what web technologies are running on https://target.com"
```

### Web Application Testing

```
"Test https://target.com for SQL injection vulnerabilities"
"Run a full web audit on https://target.com"
"Check for CORS misconfigurations on https://api.target.com"
"Fuzz for hidden directories and files on https://target.com"
"Scan https://target.com/graphql for introspection and exposed types"
"Find hidden parameters on https://target.com/search"
"Extract API endpoints and secrets from https://target.com/app.bundle.js"
```

### JWT and Authentication

```
"Decode this JWT and check for vulnerabilities: eyJhbGciOiJIUzI1NiJ9..."
"Try an alg:none signature bypass on this token"
"Brute-force the HS256 secret on this JWT using rockyou.txt"
"Analyze this OAuth authorization URL for security issues"
```

### Exploitation

```
"Generate a Windows x64 reverse shell payload for 192.168.1.10 port 4444"
"Run the EternalBlue exploit against 10.10.10.4"
"Use sqlmap to dump all databases from https://target.com/vuln?id=1"
"Brute-force SSH on 10.10.10.5 using rockyou.txt"
"Generate a Python cookie stealer exploit for the XSS at https://target.com/search?q="
"Search Metasploit for Apache Struts exploit modules"
```

### Intelligence

```
"What CVEs affect Apache 2.4.49?"
"Look up CVE-2021-44228 Log4Shell and explain the risk"
"Scan the GitHub repo owner/repo for exposed API keys in recent commits"
"Map all known CVEs for nginx 1.14.0"
```

### Burp Suite Automation

```
"Get the last 100 requests from Burp proxy history"
"Launch an active scan against https://target.com"
"Show me all high and critical issues from the Burp scanner"
"Generate a Burp Collaborator payload for out-of-band testing"
"Send this HTTP request to Burp Repeater and show me the response"
"Build an Intruder attack with XSS payloads against this request template"
```

---

## ⚙️ Configuration Reference

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `BURP_URL` | `http://127.0.0.1:9876` | Burp Suite REST API endpoint |
| `BURP_API_KEY` | *(empty)* | API key for Burp authentication if required |
| `TOOL_TIMEOUT` | `120` | Maximum execution time in seconds for CLI tools |
| `TIMEOUT` | `30` | HTTP request timeout in seconds |

### Command Line Flags

```
python3 server.py [OPTIONS]

  --burp-url TEXT        Burp REST API URL       (default: http://127.0.0.1:9876)
  --api-key TEXT         Burp API key            (default: empty)
  --transport TEXT       stdio or sse            (default: stdio)
  --mcp-host TEXT        SSE server bind host    (default: 127.0.0.1)
  --mcp-port INT         SSE server port         (default: 8082)
  --timeout INT          HTTP request timeout    (default: 30)
  --tool-timeout INT     CLI tool timeout        (default: 120)
  --debug                Enable debug logging
```

### Common Launch Commands

```bash
# Default stdio mode — for Claude Desktop, Cursor, local AI tools
python3 server.py

# SSE mode — for claude.ai web, ChatGPT Agents SDK, remote clients
python3 server.py --transport sse

# SSE mode, publicly accessible, custom port
python3 server.py --transport sse --mcp-host 0.0.0.0 --mcp-port 8082

# With Burp API key and debug output
python3 server.py --api-key YOUR_KEY --debug

# Full custom configuration
python3 server.py \
  --burp-url http://127.0.0.1:9876 \
  --api-key YOUR_KEY \
  --transport sse \
  --mcp-host 0.0.0.0 \
  --mcp-port 8082 \
  --tool-timeout 300 \
  --debug
```

---

## 🔌 Burp Suite Setup

To enable the Burp Suite REST API layer:

1. Install **Burp Suite Professional** or **Community Edition** from [portswigger.net/burp](https://portswigger.net/burp)
2. Open Burp Suite and go to the **BApp Store**
3. Install the **BurpAI** extension (search for "BurpAI" or "Burp MCP")
4. The extension starts a REST server on `http://127.0.0.1:9876` automatically
5. Launch `server.py` — it connects to Burp automatically

> Without Burp Suite, all Kali CLI tools and Pure Python security modules work perfectly. Burp integration is optional but unlocks scanner results, proxy history, Collaborator OOB interactions, and Intruder automation.

---


---

## 🔐 Security Considerations

- Only run this tool against systems you **own or have explicit written authorization** to test
- The `run_command` tool provides full shell access — run in a VM or container for isolation
- Bind the SSE server to `127.0.0.1` unless you have proper network-level access controls in place
- Keep `BURP_API_KEY` secret and rotate it regularly
- Output files and tool logs may contain sensitive data — handle and store them securely
- Set conservative `TOOL_TIMEOUT` values to prevent long-running or runaway processes

---

## 🙏 Credits

This project stands on the shoulders of giants in the security community.

### 👤 Daniel S. — PortSwigger

For pioneering and publishing the foundational web application security research that powers this bridge. The CORS testing, HTTP request smuggling detection, web cache poisoning, Host header injection, and OAuth misconfiguration modules are all directly inspired by PortSwigger's world-class research. The [Web Security Academy](https://portswigger.net/web-security) is the best free security training resource on the planet, and Burp Suite Pro is the industry-standard tool that makes the REST API integration layer possible.

### 👤 Daniel Allen

For contributions to the real-world penetration testing workflows, (PortSwigger MCP - Extension)

### 🛠️ Open Source Tools Integrated

| Tool | Author / Project |
|------|-----------------|
| [Nmap](https://nmap.org) | Gordon Lyon (Fyodor) |
| [Metasploit Framework](https://metasploit.com) | Rapid7 |
| [SQLMap](https://sqlmap.org) | Bernardo Damele & Miroslav Stampar |
| [Nuclei](https://github.com/projectdiscovery/nuclei) | ProjectDiscovery |
| [Subfinder](https://github.com/projectdiscovery/subfinder) | ProjectDiscovery |
| [dnsx](https://github.com/projectdiscovery/dnsx) | ProjectDiscovery |
| [Gobuster](https://github.com/OJ/gobuster) | OJ Reeves |
| [ffuf](https://github.com/ffuf/ffuf) | Joona Hoikkala |
| [Amass](https://github.com/owasp-amass/amass) | OWASP |
| [Hydra](https://github.com/vanhauser-thc/thc-hydra) | Van Hauser / THC |
| [Nikto](https://github.com/sullo/nikto) | Chris Sullo |
| [Hashcat](https://hashcat.net) | Jens Steube |
| [John the Ripper](https://www.openwall.com/john/) | Openwall |
| [WhatWeb](https://github.com/urbanadventurer/WhatWeb) | Andrew Horton |
| [WPScan](https://wpscan.com) | WPScan Team |
| [Fierce](https://github.com/mschwager/fierce) | Mark Schwager |
| [SSLScan](https://github.com/rbsec/sslscan) | rbsec |
| [FastMCP](https://github.com/jlowin/fastmcp) | MCP Community |
| [Burp Suite](https://portswigger.net/burp) | PortSwigger |

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for full terms.

---

<div align="center">

**Built with ❤️ for the security research community**

*For authorized testing only. Hack responsibly.*

⭐ **Star this repo** if it helped your work!

</div>
