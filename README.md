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

## Step-by-Step Tutorial

### Step 1: Install the Tool

```bash
# Clone the repository
git clone https://github.com/Ibrahimibrahimi/Smuggler.git
cd Smuggler

# Install in editable mode
pip install -e .

# Verify installation
smuggler version
```

### Step 2: Your First Scan

Start with a simple scan against a single target:

```bash
# Basic scan with default settings
smuggler scan -t https://example.com
```

This will:
1. Probe the target to check reachability
2. Detect WAF/CDN and backend server
3. Test all applicable smuggling techniques
4. Generate JSON and HTML reports in `./results/`

### Step 3: Understanding the Output

**Console Output:**
- Target info panel shows WAF, backend, HTTP/2 support, baseline response time
- Findings table shows each detected vulnerability with severity and confidence
- Summary shows total targets, vulnerable count, and report locations

**Reports:**
- Open the HTML report in your browser for a visual breakdown
- Use the JSON report for automation or further analysis

### Step 4: Scan Multiple Targets

Create a `targets.txt` file with one URL per line:

```
https://target1.com
https://target2.com
https://api.target3.com
https://staging.target4.com
```

Then scan all targets:

```bash
smuggler scan -T targets.txt
```

### Step 5: Authenticated Scanning

For targets requiring login:

```bash
# Launch auth web UI
smuggler scan -t https://target.com --auth
```

This opens a browser tab at `http://127.0.0.1:5555` where you can:

1. **Add Headers**: Click "+ Add" to add custom headers (e.g., X-API-Key)
2. **Add Cookies**: Paste raw cookie string or add key-value pairs
3. **Set Token**: Choose Bearer/Basic/Custom and enter your token
4. **Configure Proxy**: Enable and set proxy URL (e.g., Burp Suite at `http://127.0.0.1:8080`)
5. **SSL Settings**: Toggle SSL verification for self-signed certs
6. **Save**: Click "Save & Start Scan" or "Save Config Only"

Your config is saved to `~/.http-smuggler/auth_config.yaml` for reuse.

### Step 6: Use Saved Auth Config

```bash
# Reuse saved auth config without opening web UI
smuggler scan -t https://target.com --auth-config ~/.http-smuggler/auth_config.yaml

# Or manage auth config directly
smuggler auth --show    # View saved config
smuggler auth --clear   # Delete saved config
```

### Step 7: Target Specific Techniques

Focus on specific smuggling techniques:

```bash
# Test only CL.TE and TE.CL
smuggler scan -t https://target.com --techniques CL.TE,TE.CL

# Test only HTTP/2 techniques
smuggler scan -t https://target.com --techniques H2.CL,H2.TE,H2.RL

# Test only CRLF injection
smuggler scan -t https://target.com --techniques CRLF
```

### Step 8: Adjust Scan Settings

```bash
# Increase timeout for slow targets
smuggler scan -t https://target.com --timeout 30

# Use more threads for batch scanning
smuggler scan -T targets.txt --threads 20

# Add delay between requests to avoid rate limiting
smuggler scan -T targets.txt --delay 1.0

# Save reports to custom directory
smuggler scan -t https://target.com -o /path/to/reports
```

### Step 9: Debug Mode

When things aren't working as expected:

```bash
# Verbose output (-v)
smuggler scan -t https://target.com -v

# Debug output (-vv) shows all errors and H2 detection details
smuggler scan -t https://target.com -vv
```

### Step 10: Read the Reports

**JSON Report** contains:
- Target info (WAF, backend, HTTP/2 support)
- Each finding with technique, severity, confidence, evidence
- Remediation steps and reference links

**HTML Report** provides:
- Visual dashboard with summary cards
- Per-target breakdown with findings
- Color-coded severity badges
- Copy-ready evidence and remediation

### Example Workflow

Complete bug bounty workflow:

```bash
# 1. Create target list
echo "https://program-target.com" > targets.txt
echo "https://api.program-target.com" >> targets.txt

# 2. Configure auth (if needed)
smuggler auth

# 3. Run full scan with all techniques
smuggler scan -T targets.txt -a -v -o ./bounty-results

# 4. Review HTML report in browser
open ./bounty-results/smuggler_report_*.html

# 5. Check JSON for automation
cat ./bounty-results/smuggler_report_*.json | python -m json.tool
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

## Contributing

Contributions are welcome! Here's how to contribute:

1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/amazing-feature`)
3. **Commit** your changes (`git commit -m 'Add amazing feature'`)
4. **Push** to the branch (`git push origin feature/amazing-feature`)
5. **Open** a Pull Request

### Development Setup

```bash
# Clone your fork
git clone https://github.com/your-username/Smuggler.git
cd Smuggler

# Install in development mode
pip install -e ".[dev]"

# Run tests
pytest tests/ -v
```

### Adding New Techniques

To add a new smuggling technique:

1. Add payload to `smuggler/payloads/database.py`
2. Create detector in `smuggler/scanner/detectors.py`
3. Register detector in `smuggler/scanner/core.py`
4. Add technique name to `TECHNIQUES_ALL` in `smuggler/cli.py`

### Reporting Issues

- Use GitHub Issues for bug reports
- Include target type, error messages, and verbose output
- Never post real credentials or sensitive target info

## Roadmap

- [ ] WebSocket smuggling detection
- [ ] Async scanning with asyncio
- [ ] Nuclei template integration
- [ ] PDF report improvements
- [ ] Custom payload support
- [ ] Scan history and comparison

## Technical Details

### How Detection Works

**Timing-Based Detection:**
- Sends malformed requests that cause backend to wait
- Measures response time vs baseline
- Significant delay indicates backend is processing differently than frontend

**Differential Response:**
- Sends smuggling payloads and analyzes error responses
- Unexpected status codes (400, 403, 501) with timing anomalies indicate vulnerability

**HTTP/2 Downgrade:**
- Tests if HTTP/2 requests with forbidden headers are processed
- Detects frontend-to-backend protocol downgrade vulnerabilities

### Raw TCP Requests

Smuggler uses raw TCP sockets instead of high-level HTTP libraries. This is essential because:

- HTTP libraries normalize headers (removing duplicates, fixing case)
- Smuggling requires sending malformed headers that libraries would reject
- Raw sockets give full control over the HTTP request format

## Disclaimer

This tool is for authorized security testing and bug bounty hunting only. Always obtain proper authorization before scanning targets. The author is not responsible for misuse of this software.

## License

MIT
