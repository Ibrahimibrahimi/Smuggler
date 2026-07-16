# HTTP Request Smuggler — Todo

## Core Features
- [x] CLI with Click + Rich (smuggler/cli.py)
- [x] 7 detection techniques (CL.TE, TE.CL, TE.TE, H2.CL, H2.TE, H2.RL, CRLF)
- [x] 14 payloads in database
- [x] Raw TCP socket smuggling (http_utils.py)
- [x] WAF detection
- [x] Backend fingerprinting
- [x] Timing analysis
- [x] Auth web UI (Flask on port 5555)
- [x] JSON, HTML, PDF report generation
- [x] Config manager with YAML
- [x] Batch scanning with thread pool
- [x] Claude-style light HTML theme
- [x] pyproject.toml packaging
- [x] README with docs

## Enhancements
- [ ] Auto-exploit mode (cache poisoning, credential theft, XSS relay)
- [ ] WAF bypass payloads (encoded variants, double-chunked, obfuscated TE)
- [ ] Session replay / raw request logging
- [ ] Rate limiting detection (auto-throttle on 429s)
- [ ] Slack/Discord webhooks for real-time alerts
- [ ] Custom payload support (user-defined from file)
- [ ] Response diffing (compare smuggled vs clean response)
- [ ] Dockerfile for one-command deployment
- [ ] Colorized terminal output (Rich already installed)
- [ ] Progress bar per-technique during scan
- [ ] `smuggler report` subcommand (convert JSON to HTML)
- [ ] Async scanning (asyncio) for 10x faster batch scans
- [ ] Plugin system for community-contributed detectors
- [ ] WebSocket smuggling detection
- [ ] CI/CD integration (GitHub Actions)
- [ ] Nmap/Nuclei integration
