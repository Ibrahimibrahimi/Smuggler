# ⚡ HTTP Request Smuggler

> A professional HTTP Request Smuggling vulnerability scanner built for **bug bounty hunters** and **penetration testers**.

![Python](https://img.shields.io/badge/Python-3.9%2B-blue?style=flat-square&logo=python)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Security](https://img.shields.io/badge/Use-Authorized%20Testing%20Only-red?style=flat-square)

---

## 📸 Features

| Feature | Details |
|---|---|
| **Detection Techniques** | CL.TE · TE.CL · TE.TE (5 variants) · H2.CL · H2.TE · H2.RL · CRLF |
| **Auth GUI** | Tkinter popup for headers, cookies, tokens, proxy (optional) |
| **Reports** | JSON · HTML · PDF |
| **CLI** | Rich-powered, colored, progress bars, verbosity levels |
| **Batch Scanning** | Multi-threaded, targets from file |
| **WAF Detection** | Cloudflare, Akamai, AWS WAF, Fastly, Imperva, F5, Sucuri… |
| **Backend Fingerprinting** | Apache, Nginx, IIS, Tomcat, Node.js, Gunicorn… |
| **Config Files** | YAML-based scan config + auth config, importable/exportable |

---

## 🚀 Installation

### 1. Clone & Install

```bash
git clone https://github.com/yourname/http-smuggler.git
cd http-smuggler
pip install -r requirements.txt
```

### 2. Optional: PDF report support

```bash
pip install weasyprint
# Linux may also need: apt install libpango-1.0-0 libharfbuzz0b libpangoft2-1.0-0
```

### 3. Optional: Install as CLI tool

```bash
pip install -e .
# Now use: smuggler scan ...
```

---

## 🖥️ CLI Usage

```
smuggler [COMMAND] [OPTIONS]

Commands:
  scan              Scan one or more targets
  auth              Manage authentication configuration (opens GUI)
  list-techniques   List all supported techniques and payloads
  version           Show version info
```

### `scan` — Main scanning command

```bash
# Basic scan (no auth)
python main.py scan -t https://example.com

# Scan with auth GUI popup
python main.py scan -t https://example.com --auth

# Use previously saved auth config (no GUI)
python main.py scan -t https://example.com --auth-config ~/.http-smuggler/auth_config.yaml

# Scan specific techniques only
python main.py scan -t https://example.com --techniques CL.TE,TE.CL

# Batch scan from file
python main.py scan -T targets.txt --threads 10

# Full output: JSON + HTML + PDF
python main.py scan -t https://example.com --format json,html,pdf --output ./my-reports

# Verbose mode (shows target info, errors)
python main.py scan -t https://example.com -v

# Debug mode (maximum verbosity)
python main.py scan -t https://example.com -vv

# Custom timeout & delay
python main.py scan -t https://example.com --timeout 15 --delay 1.0

# Use custom scan config file
python main.py scan -t https://example.com --config my-config.yaml
```

### `auth` — Auth config management

```bash
# Open GUI to create or edit auth config
python main.py auth

# Show currently saved config
python main.py auth --show

# Delete saved config
python main.py auth --clear
```

### `list-techniques` — Show all payloads

```bash
python main.py list-techniques
```

---

## 🔐 Auth Mode

When you pass `--auth`, a **Tkinter GUI popup** appears before scanning:

```
python main.py scan -t https://example.com --auth
```

The GUI lets you configure:

- **HTTP Headers** — key/value pairs (e.g. `X-Api-Key`, `User-Agent`, custom headers)
- **Cookies** — individual entries or paste a raw cookie string to auto-parse
- **Session Token** — Bearer / Basic / Custom with show/hide toggle
- **Proxy** — HTTP or SOCKS5 proxy with optional credentials (e.g. Burp Suite)
- **SSL** — Toggle certificate verification (useful for internal/staging targets)

On submit, config is saved to `~/.http-smuggler/auth_config.yaml` and the scan starts.
You can also **Import** or **Export** configs as YAML or JSON from the GUI.

### Auth Config File Format

```yaml
# ~/.http-smuggler/auth_config.yaml
headers:
  User-Agent: "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
  X-Custom-Header: "value"

cookies:
  sessionid: "abc123xyz"
  csrftoken: "def456"

token: "eyJhbGciOiJIUzI1NiIsInR..."
token_type: "Bearer"   # Bearer | Basic | Custom | None

proxy_enabled: false
proxy_url: "http://127.0.0.1:8080"
proxy_username: ""
proxy_password: ""

ssl_verify: false
saved_at: "2024-01-15T10:30:00"
```

---

## ⚙️ Scan Config File

Place a `config.yaml` at `~/.http-smuggler/config.yaml` or pass via `--config`:

```yaml
techniques:
  - CL.TE
  - TE.CL
  - TE.TE
  - H2.CL
  - H2.TE
  - CRLF

timeout: 10.0
timing_threshold: 5.0
delay: 0.3
retries: 2
threads: 5

output_dir: "./results"
output_formats:
  - json
  - html

verbose: 0
follow_redirects: false
detect_waf: true
fingerprint_backend: true
confirm_vulns: true
```

---

## 🎯 Supported Techniques

| Technique | Description | Severity |
|---|---|---|
| **CL.TE** | Front-end uses Content-Length, back-end uses Transfer-Encoding | 🔴 Critical |
| **TE.CL** | Front-end uses Transfer-Encoding, back-end uses Content-Length | 🔴 Critical |
| **TE.TE** (Space) | Obfuscated TE via space before colon | 🟠 High |
| **TE.TE** (Duplicate) | Duplicate Transfer-Encoding headers | 🟠 High |
| **TE.TE** (Junk chunk) | Chunk extension with junk value | 🟠 High |
| **TE.TE** (Tab prefix) | Tab-prefixed Transfer-Encoding | 🟠 High |
| **TE.TE** (Null byte) | Null byte in TE value | 🟠 High |
| **H2.CL** | HTTP/2 → HTTP/1.1 downgrade with Content-Length desync | 🔴 Critical |
| **H2.TE** | Forbidden Transfer-Encoding in HTTP/2 forwarded on downgrade | 🔴 Critical |
| **H2.RL** | CRLF injection in HTTP/2 pseudo-headers | 🔴 Critical |
| **CRLF** | CRLF injection in header values introduces TE header | 🟠 High |
| **Cache Poison** | Smuggle + cache poison chained attack | 🔴 Critical |

### Detection Methods Per Technique

- **Timing-based**: Send incomplete/ambiguous body, measure if backend hangs
- **Differential response**: Compare response status/size against baseline
- **Error analysis**: Unexpected 400/405/501 on follow-up request

---

## 📊 Output Formats

### JSON (`--format json`)
Machine-readable, perfect for automation, CI/CD, or dashboards.

```json
{
  "tool": "HTTP Request Smuggler",
  "generated_at": "2024-01-15T10:30:00",
  "summary": {
    "total_targets": 3,
    "vulnerable": 1,
    "total_findings": 2,
    "critical": 1,
    "high": 1
  },
  "results": [...]
}
```

### HTML (`--format html`)
Dark-themed, professional report with:
- Summary stat cards
- Per-target sections with WAF/backend info
- Color-coded severity findings
- Remediation advice per finding
- Reference links

### PDF (`--format pdf`)
Same as HTML, exported to PDF via WeasyPrint. Requires:
```bash
pip install weasyprint
```

---

## 🗂️ Project Structure

```
http-smuggler/
├── main.py                     # CLI entry point (click + rich)
├── setup.py                    # pip install config
├── config.yaml                 # Default scan config template
├── requirements.txt
│
├── scanner/
│   ├── __init__.py
│   ├── core.py                 # SmuggleScanner engine (orchestrator)
│   └── detectors.py            # Per-technique detection logic + Finding dataclass
│
├── payloads/
│   ├── __init__.py
│   └── database.py             # All smuggling payloads (14 payloads, 7 techniques)
│
├── gui/
│   ├── __init__.py
│   └── auth_window.py          # Tkinter auth GUI (headers/cookies/token/proxy/SSL)
│
├── config/
│   ├── __init__.py
│   └── manager.py              # AuthConfig, ScanConfig, save/load YAML
│
├── reports/
│   ├── __init__.py
│   └── generators.py           # JSON / HTML / PDF report generators
│
└── utils/
    ├── __init__.py
    └── http.py                 # Raw TCP HTTP sender, WAF detector, fingerprinter
```

---

## 🔬 How Detection Works

### Timing-based (Primary)

The most reliable method. Send a request designed to leave the backend in a waiting state:

**CL.TE timing**: Frontend sees `Content-Length: 4` and forwards body. Backend sees `Transfer-Encoding: chunked` and waits for the `0\r\n\r\n` terminator that never comes → **timeout**.

**TE.CL timing**: Frontend reads chunk `0` (done). Backend sees `Content-Length: 6` and waits for 6 body bytes that never come → **timeout**.

If actual response time > baseline + `timing_threshold` (default 5s), it's flagged.

### Differential Response (Secondary)

Send a payload that smuggles a prefix (`G`, `GPOST`, etc.) to the backend. The next legitimate request to the same connection gets an unexpected `405 Method Not Allowed` or similar error because the backend sees `GPOST /` instead of `POST /`.

### Raw TCP Sockets

All requests are sent over **raw TCP sockets** (not urllib3/requests), bypassing header normalization. This is essential — high-level HTTP libraries automatically fix malformed headers, preventing smuggling payloads from reaching the server in their intended form.

---

## ⚠️ Legal & Ethical Notice

> **For authorized security testing only.**
> 
> HTTP Request Smuggling attacks can cause service disruption, data leakage, and affect other users of the target system. Only use this tool against systems you own or have **explicit written permission** to test.
>
> The authors assume no liability for misuse.

---

## 📚 References

- [PortSwigger Web Academy — HTTP Request Smuggling](https://portswigger.net/web-security/request-smuggling)
- [HTTP Desync Attacks: Request Smuggling Reborn (James Kettle)](https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn)
- [HTTP/2: The Sequel is Always Worse](https://portswigger.net/research/http2)
- [OWASP HTTP Request Smuggling](https://owasp.org/www-community/attacks/HTTP_Request_Smuggling)
- [RFC 7230 — HTTP/1.1 Message Syntax](https://tools.ietf.org/html/rfc7230)
- [RFC 9113 — HTTP/2](https://tools.ietf.org/html/rfc9113)

---

## 🤝 Contributing

1. Fork the repo
2. Add new payloads to `payloads/database.py`
3. Add new detectors to `scanner/detectors.py`
4. Open a PR with a description of the technique and references

---

## 📄 License

MIT — see [LICENSE](LICENSE)
