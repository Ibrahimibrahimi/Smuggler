"""
Report Generators
Produces JSON, HTML, and PDF output from scan results
"""

import json
from datetime import datetime
from pathlib import Path
from typing import List, Tuple
from dataclasses import asdict

from smuggler.scanner.core import ScanResult
from smuggler.scanner.detectors import Finding, Confidence
from smuggler import __version__


# --- Helpers ---

SEVERITY_EMOJI = {
    "critical": "\U0001f534",
    "high":     "\U0001f7e0",
    "medium":   "\U0001f7e1",
    "low":      "\U0001f535",
}

CONFIDENCE_LABEL = {
    Confidence.CONFIRMED: "Confirmed",
    Confidence.LIKELY:    "Likely",
    Confidence.POSSIBLE:  "Possible",
    Confidence.FALSE_POS: "False Positive",
}

SEVERITY_COLOR = {
    "critical": "#ef4444",
    "high":     "#f97316",
    "medium":   "#eab308",
    "low":      "#3b82f6",
}


def _ensure_output_dir(output_dir: str) -> Path:
    path = Path(output_dir)
    path.mkdir(parents=True, exist_ok=True)
    return path


def _safe_filename(url: str) -> str:
    return url.replace("https://", "").replace("http://", "").replace("/", "_").replace(":", "-")[:60]


# --- JSON Report ---

def generate_json(results: List[ScanResult], output_dir: str) -> str:
    out_dir = _ensure_output_dir(output_dir)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = out_dir / f"smuggler_report_{timestamp}.json"

    def _serialise(obj):
        if isinstance(obj, Confidence):
            return obj.value
        if hasattr(obj, "__dataclass_fields__"):
            return asdict(obj)
        return str(obj)

    report = {
        "tool": "HTTP Request Smuggler",
        "version": __version__,
        "generated_at": datetime.now().isoformat(),
        "summary": {
            "total_targets": len(results),
            "vulnerable": sum(1 for r in results if r.is_vulnerable),
            "total_findings": sum(len(r.findings) for r in results),
            "critical": sum(r.critical_count for r in results),
            "high": sum(r.high_count for r in results),
        },
        "results": [
            {
                "target": r.target,
                "started_at": r.started_at,
                "finished_at": r.finished_at,
                "duration": r.duration,
                "vulnerable": r.is_vulnerable,
                "target_info": {
                    "waf": r.target_info.waf if r.target_info else None,
                    "backend": r.target_info.backend if r.target_info else None,
                    "supports_h2": r.target_info.supports_h2 if r.target_info else False,
                    "baseline_time": r.target_info.baseline_time if r.target_info else 0,
                },
                "findings": [
                    {
                        "technique": f.technique,
                        "payload_name": f.payload_name,
                        "severity": f.severity,
                        "confidence": f.confidence.value,
                        "description": f.description,
                        "evidence": f.evidence,
                        "elapsed": f.elapsed,
                        "remediation": f.remediation,
                        "references": f.references,
                    }
                    for f in r.findings
                ],
                "techniques_tested": r.techniques_tested,
                "total_requests": r.total_requests,
                "errors": r.errors,
            }
            for r in results
        ],
    }

    with open(filename, "w") as f:
        json.dump(report, f, indent=2, default=_serialise)

    return str(filename)


# --- HTML Report ---

_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>HTTP Smuggler Report — {timestamp}</title>
<style>
  :root {{
    --bg: #FAF8F5;
    --surface: #FFFFFF;
    --surface2: #F5F0EB;
    --border: #E8E0D8;
    --accent: #C47A3A;
    --accent2: #8B6F5C;
    --text: #3D3229;
    --muted: #9A8C80;
    --critical: #C0392B;
    --high: #D4731A;
    --medium: #B8960F;
    --low: #4A7FB5;
    --success: #5A9E6F;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: var(--bg); color: var(--text); font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Inter', sans-serif; line-height: 1.6; -webkit-font-smoothing: antialiased; }}
  .container {{ max-width: 1100px; margin: 0 auto; padding: 48px 32px; }}

  .report-header {{ border-bottom: 1px solid var(--border); padding-bottom: 36px; margin-bottom: 44px; }}
  .report-header h1 {{ font-size: 2rem; font-weight: 700; color: var(--text); letter-spacing: -0.02em; }}
  .report-header .meta {{ color: var(--muted); font-size: 0.875rem; margin-top: 8px; }}

  .summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 16px; margin-bottom: 48px; }}
  .stat-card {{ background: var(--surface); border: 1px solid var(--border); border-radius: 16px; padding: 24px; text-align: center; box-shadow: 0 1px 3px rgba(0,0,0,0.04); }}
  .stat-card .num {{ font-size: 2.5rem; font-weight: 800; line-height: 1; }}
  .stat-card .label {{ color: var(--muted); font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.08em; margin-top: 6px; font-weight: 500; }}
  .stat-card.vuln .num {{ color: var(--critical); }}
  .stat-card.critical .num {{ color: var(--critical); }}
  .stat-card.high .num {{ color: var(--high); }}
  .stat-card.ok .num {{ color: var(--success); }}

  .target-block {{ background: var(--surface); border: 1px solid var(--border); border-radius: 16px; margin-bottom: 28px; overflow: hidden; box-shadow: 0 1px 4px rgba(0,0,0,0.04); }}
  .target-header {{ padding: 20px 24px; border-bottom: 1px solid var(--border); display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 12px; }}
  .target-url {{ font-family: 'SF Mono', 'Fira Code', 'Consolas', monospace; font-size: 0.95rem; font-weight: 600; color: var(--accent); word-break: break-all; }}
  .badge {{ display: inline-block; border-radius: 20px; padding: 4px 12px; font-size: 0.7rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em; }}
  .badge-vuln {{ background: #FDE8E8; color: var(--critical); border: 1px solid #F5C6C6; }}
  .badge-safe {{ background: #E8F5ED; color: var(--success); border: 1px solid #C6E5CF; }}

  .target-meta {{ display: flex; gap: 28px; padding: 16px 24px; background: var(--surface2); flex-wrap: wrap; }}
  .meta-item {{ font-size: 0.8rem; }}
  .meta-item span {{ color: var(--muted); }}
  .meta-item strong {{ color: var(--text); font-weight: 600; }}

  .findings-list {{ padding: 20px 24px; }}
  .finding {{ border: 1px solid var(--border); border-radius: 12px; margin-bottom: 16px; overflow: hidden; background: var(--surface); }}
  .finding-header {{ padding: 14px 18px; display: flex; align-items: center; gap: 12px; flex-wrap: wrap; }}
  .severity-dot {{ width: 10px; height: 10px; border-radius: 50%; flex-shrink: 0; }}
  .finding-title {{ font-weight: 600; font-size: 0.92rem; flex: 1; color: var(--text); }}
  .technique-badge {{ background: #F0E8F8; color: #7C5BA3; border: 1px solid #DDD0EE; }}
  .conf-badge {{ background: var(--surface2); color: var(--muted); border: 1px solid var(--border); }}
  .finding-body {{ padding: 0 18px 16px; border-top: 1px solid var(--border); }}
  .finding-body p {{ margin-top: 12px; font-size: 0.85rem; color: #6B5E53; line-height: 1.6; }}
  .finding-body .evidence {{ font-family: 'SF Mono', 'Fira Code', 'Consolas', monospace; background: var(--surface2); border: 1px solid var(--border); border-radius: 8px; padding: 10px 14px; font-size: 0.78rem; color: var(--accent); margin-top: 10px; word-break: break-all; line-height: 1.5; }}
  .remediation {{ background: #EEF6F0; border: 1px solid #D0E8D6; border-radius: 8px; padding: 12px 14px; margin-top: 12px; font-size: 0.83rem; color: #3D6E4A; line-height: 1.5; }}
  .refs {{ margin-top: 10px; }}
  .refs a {{ color: var(--accent); font-size: 0.78rem; text-decoration: none; margin-right: 12px; }}
  .refs a:hover {{ text-decoration: underline; }}

  .no-findings {{ padding: 28px 24px; text-align: center; color: var(--muted); }}
  .no-findings .icon {{ font-size: 2rem; margin-bottom: 8px; }}

  .footer {{ text-align: center; color: var(--muted); font-size: 0.78rem; margin-top: 48px; padding-top: 24px; border-top: 1px solid var(--border); }}
</style>
</head>
<body>
<div class="container">

<div class="report-header">
  <h1>HTTP Request Smuggler</h1>
  <p class="meta">Scan Report &middot; Generated {timestamp} &middot; {total_targets} target(s) scanned</p>
</div>

<div class="summary-grid">
  <div class="stat-card"><div class="num">{total_targets}</div><div class="label">Targets</div></div>
  <div class="stat-card vuln"><div class="num">{vulnerable}</div><div class="label">Vulnerable</div></div>
  <div class="stat-card critical"><div class="num">{critical}</div><div class="label">Critical</div></div>
  <div class="stat-card high"><div class="num">{high}</div><div class="label">High</div></div>
  <div class="stat-card ok"><div class="num">{safe}</div><div class="label">Clean</div></div>
</div>

{targets_html}

<div class="footer">Generated by HTTP Request Smuggler &middot; For authorized security testing only</div>
</div>
</body>
</html>"""


def _finding_html(f: Finding) -> str:
    color = SEVERITY_COLOR.get(f.severity, "#64748b")
    refs_html = ""
    if f.references:
        links = " ".join(f'<a href="{r}" target="_blank">{r}</a>' for r in f.references)
        refs_html = f'<div class="refs">{links}</div>'

    bg_map = {{"critical": "#FDE8E8", "high": "#FEF0E3", "medium": "#FDF5DC", "low": "#E3EEF7"}}
    bg = bg_map.get(f.severity, "#F5F0EB")

    return f"""
<div class="finding">
  <div class="finding-header">
    <div class="severity-dot" style="background:{color}"></div>
    <div class="finding-title">{f.payload_name}</div>
    <span class="badge technique-badge">{f.technique}</span>
    <span class="badge conf-badge">{CONFIDENCE_LABEL.get(f.confidence, f.confidence)}</span>
    <span class="badge" style="background:{bg};color:{color};border:1px solid {bg}">{f.severity.upper()}</span>
  </div>
  <div class="finding-body">
    <p>{f.description}</p>
    <div class="evidence">Evidence: {f.evidence}</div>
    {'<div class="remediation"><strong>Remediation:</strong> ' + f.remediation + '</div>' if f.remediation else ''}
    {refs_html}
  </div>
</div>"""


def _target_html(r: ScanResult) -> str:
    vuln_badge = '<span class="badge badge-vuln">VULNERABLE</span>' if r.is_vulnerable else '<span class="badge badge-safe">CLEAN</span>'
    ti = r.target_info

    meta = f"""
<div class="target-meta">
  <div class="meta-item"><span>WAF/CDN: </span><strong>{ti.waf or "None detected"}</strong></div>
  <div class="meta-item"><span>Backend: </span><strong>{ti.backend or "Unknown"}</strong></div>
  <div class="meta-item"><span>HTTP/2: </span><strong>{"Yes" if ti.supports_h2 else "No"}</strong></div>
  <div class="meta-item"><span>Baseline RTT: </span><strong>{ti.baseline_time:.3f}s</strong></div>
  <div class="meta-item"><span>Requests sent: </span><strong>{r.total_requests}</strong></div>
  <div class="meta-item"><span>Techniques: </span><strong>{", ".join(r.techniques_tested)}</strong></div>
</div>""" if ti else ""

    if r.findings:
        findings_html = "".join(_finding_html(f) for f in r.findings)
        body = f'<div class="findings-list">{findings_html}</div>'
    else:
        body = '<div class="no-findings"><div class="icon"></div>No vulnerabilities detected for this target</div>'

    return f"""
<div class="target-block">
  <div class="target-header">
    <div class="target-url">{r.target}</div>
    {vuln_badge}
  </div>
  {meta}
  {body}
</div>"""


def generate_html(results: List[ScanResult], output_dir: str) -> Tuple[str, str]:
    """Generate HTML report. Returns (file_path, html_content)."""
    out_dir = _ensure_output_dir(output_dir)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = out_dir / f"smuggler_report_{timestamp}.html"

    total_targets  = len(results)
    vulnerable     = sum(1 for r in results if r.is_vulnerable)
    critical_count = sum(r.critical_count for r in results)
    high_count     = sum(r.high_count for r in results)
    safe_count     = total_targets - vulnerable
    targets_html   = "\n".join(_target_html(r) for r in results)
    ts             = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    html = _HTML_TEMPLATE.format(
        timestamp=ts,
        total_targets=total_targets,
        vulnerable=vulnerable,
        critical=critical_count,
        high=high_count,
        safe=safe_count,
        targets_html=targets_html,
    )

    with open(filename, "w", encoding="utf-8") as f:
        f.write(html)

    return str(filename), html


# --- PDF Report ---

def generate_pdf(results: List[ScanResult], output_dir: str) -> str:
    """Generate PDF by converting the HTML report via weasyprint"""
    out_dir = _ensure_output_dir(output_dir)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    pdf_path = out_dir / f"smuggler_report_{timestamp}.pdf"

    # Generate HTML and get content directly (no fragile glob search)
    html_path, html_content = generate_html(results, output_dir)

    try:
        from weasyprint import HTML
        HTML(string=html_content).write_pdf(str(pdf_path))
    except ImportError:
        raise RuntimeError(
            "weasyprint is not installed. Run: pip install weasyprint\n"
            "Or install system deps: https://doc.courtbouillon.org/weasyprint/stable/first_steps.html"
        )

    return str(pdf_path)


# --- Dispatcher ---

def generate_reports(results: List[ScanResult], output_dir: str, formats: List[str]) -> dict:
    """Generate all requested report formats. Returns dict of format -> file path."""
    generated = {}
    for fmt in formats:
        fmt = fmt.lower()
        try:
            if fmt == "json":
                generated["json"] = generate_json(results, output_dir)
            elif fmt == "html":
                path, _ = generate_html(results, output_dir)
                generated["html"] = path
            elif fmt == "pdf":
                generated["pdf"] = generate_pdf(results, output_dir)
        except Exception as e:
            generated[fmt] = f"ERROR: {e}"
    return generated
