# HTTP Request Smuggler

A powerful HTTP Request Smuggling vulnerability scanner for bug bounty hunting and authorized security testing.

## Features

- **7 Detection Techniques**: CL.TE, TE.CL, TE.TE, H2.CL, H2.TE, H2.RL, CRLF
- **14 Curated Payloads**: Including timing-based and differential detection
- **WAF/CDN Detection**: Identifies Cloudflare, AWS WAF, Akamai, and more
- **Backend Fingerprinting**: Apache, Nginx, IIS, Tomcat, Node.js, etc.
- **Authentication Support**: Headers, cookies, tokens via web UI
- **Report Generation**: JSON and HTML output
- **Batch Scanning**: Scan multiple targets with thread pool
- **Raw TCP Requests**: Bypasses HTTP library normalization for accurate testing

## Installation

```bash
git clone https://github.com/Ibrahimibrahimi/Smuggler.git
cd Smuggler
pip install -e .

# For PDF report support:
pip install -e ".[pdf]"
```

## Usage

### Basic Scan

```bash
# Scan a single target
smuggler scan -t https://example.com

# Scan with verbose output
smuggler scan -t https://example.com -v

# Scan specific techniques only
smuggler scan -t https://example.com --techniques CL.TE,TE.CL
```

### Batch Scanning

```bash
# Scan multiple targets from file (one URL per line)
smuggler scan -T targets.txt

# With custom threads and delay
smuggler scan -T targets.txt --threads 10 --delay 0.5
```

### Authenticated Scanning

```bash
# Opens web UI to configure headers, cookies, tokens
smuggler scan -t https://example.com --auth

# Use saved auth config
smuggler scan -t https://example.com --auth-config ~/.http-smuggler/auth_config.yaml
```

### Auth Management

```bash
# Open web UI to create/edit auth config
smuggler auth

# Display saved config
smuggler auth --show

# Delete saved config
smuggler auth --clear
```

### Other Commands

```bash
# List all techniques and payloads
smuggler list-techniques

# Show version
smuggler version
```

## CLI Options

| Option | Description |
|--------|-------------|
| `-t, --target` | Single target URL |
| `-T, --targets` | File with one URL per line |
| `-a, --auth` | Enable auth mode (opens web UI) |
| `--auth-config` | Path to saved auth config |
| `--techniques` | Comma-separated techniques (CL.TE,TE.CL,TE.TE,H2.CL,H2.TE,H2.RL,CRLF) |
| `-to, --timeout` | Request timeout in seconds (default: 10) |
| `-th, --threads` | Concurrent threads (default: 5) |
| `-d, --delay` | Delay between requests (default: 0.3) |
| `-o, --output` | Output directory (default: ./results) |
| `-f, --format` | Report formats: json,html,pdf (default: json,html) |
| `-v, --verbose` | Verbosity: -v (verbose) -vv (debug) |
| `--no-banner` | Suppress banner |

## Detection Techniques

| Technique | Description |
|-----------|-------------|
| CL.TE | Front-end uses Content-Length, back-end uses Transfer-Encoding |
| TE.CL | Front-end uses Transfer-Encoding, back-end uses Content-Length |
| TE.TE | Obfuscated Transfer-Encoding headers |
| H2.CL | HTTP/2 downgrade with Content-Length injection |
| H2.TE | HTTP/2 downgrade with Transfer-Encoding injection |
| H2.RL | HTTP/2 request line injection via pseudo-headers |
| CRLF | CRLF injection in header values |

## Configuration

Default config is stored at `~/.http-smuggler/config.yaml`. You can also pass a custom config:

```bash
smuggler scan -t https://example.com --config /path/to/config.yaml
```

See `config.yaml` in the repository for all available options.

## Output

Reports are saved in the output directory (default: `./results/`):

- `smuggler_report_YYYYMMDD_HHMMSS.json` - Machine-readable JSON report
- `smuggler_report_YYYYMMDD_HHMMSS.html` - Visual HTML report with dark theme

## Project Structure

```
smuggler/
├── cli.py              # CLI interface
├── scanner/
│   ├── core.py         # Main scanner engine
│   ├── detectors.py    # Detection methods
│   └── http_utils.py   # Raw HTTP utilities
├── payloads/
│   └── database.py     # Payload database
├── config/
│   └── manager.py      # Config handling
├── gui/
│   ├── auth_app.py     # Flask web UI
│   ├── templates/      # HTML templates
│   └── static/         # CSS assets
└── reports/
    └── generators.py   # JSON/HTML/PDF reports
```

## Disclaimer

This tool is for authorized security testing and bug bounty hunting only. Always obtain proper authorization before scanning targets. The author is not responsible for misuse of this software.

## License

MIT
