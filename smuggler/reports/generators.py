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
    --bg: #0a0d14;
    --surface: #111520;
    --surface2: #1a1f30;
    --border: #252a3d;
    --accent: #00d4ff;
    --accent2: #7c3aed;
    --text: #e2e8f0;
    --muted: #64748b;
    --critical: #ef4444;
    --high: #f97316;
    --medium: #eab308;
    --low: #3b82f6;
    --success: #22c55e;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: var(--bg); color: var(--text); font-family: 'Segoe UI', system-ui, sans-serif; line-height: 1.6; }}
  .container {{ max-width: 1100px; margin: 0 auto; padding: 40px 24px; }}

  .report-header {{ border-bottom: 1px solid var(--border); padding-bottom: 32px; margin-bottom: 40px; }}
  .report-header h1 {{ font-size: 2rem; font-weight: 800; background: linear-gradient(135deg, var(--accent), var(--accent2)); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }}
  .report-header .meta {{ color: var(--muted); font-size: 0.875rem; margin-top: 6px; }}

  .summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 16px; margin-bottom: 48px; }}
  .stat-card {{ background: var(--surface); border: 1px solid var(--border); border-radius: 12px; padding: 20px; text-align: center; }}
  .stat-card .num {{ font-size: 2.5rem; font-weight: 900; line-height: 1; }}
  .stat-card .label {{ color: var(--muted); font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.08em; margin-top: 4px; }}
  .stat-card.vuln .num {{ color: var(--critical); }}
  .stat-card.critical .num {{ color: var(--critical); }}
  .stat-card.high .num {{ color: var(--high); }}
  .stat-card.ok .num {{ color: var(--success); }}

  .target-block {{ background: var(--surface); border: 1px solid var(--border); border-radius: 14px; margin-bottom: 28px; overflow: hidden; }}
  .target-header {{ padding: 20px 24px; border-bottom: 1px solid var(--border); display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 12px; }}
  .target-url {{ font-family: 'Consolas', monospace; font-size: 1rem; font-weight: 700; color: var(--accent); word-break: break-all; }}
  .badge {{ display: inline-block; border-radius: 6px; padding: 3px 10px; font-size: 0.75rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.06em; }}
  .badge-vuln {{ background: rgba(239,68,68,0.15); color: var(--critical); border: 1px solid var(--critical); }}
  .badge-safe {{ background: rgba(34,197,94,0.1); color: var(--success); border: 1px solid var(--success); }}

  .target-meta {{ display: flex; gap: 24px; padding: 14px 24px; background: var(--surface2); flex-wrap: wrap; }}
  .meta-item {{ font-size: 0.82rem; }}
  .meta-item span {{ color: var(--muted); }}
  .meta-item strong {{ color: var(--text); }}

  .findings-list {{ padding: 20px 24px; }}
  .finding {{ border: 1px solid var(--border); border-radius: 10px; margin-bottom: 16px; overflow: hidden; }}
  .finding-header {{ padding: 14px 18px; display: flex; align-items: center; gap: 12px; flex-wrap: wrap; }}
  .severity-dot {{ width: 10px; height: 10px; border-radius: 50%; flex-shrink: 0; }}
  .finding-title {{ font-weight: 700; font-size: 0.95rem; flex: 1; }}
  .technique-badge {{ background: rgba(124,58,237,0.15); color: #a78bfa; border: 1px solid rgba(124,58,237,0.3); }}
  .conf-badge {{ background: var(--surface2); color: var(--muted); border: 1px solid var(--border); }}
  .finding-body {{ padding: 0 18px 16px; border-top: 1px solid var(--border); }}
  .finding-body p {{ margin-top: 12px; font-size: 0.875rem; color: #94a3b8; }}
  .finding-body .evidence {{ font-family: 'Consolas', monospace; background: var(--bg); border: 1px solid var(--border); border-radius: 6px; padding: 10px 14px; font-size: 0.8rem; color: var(--accent); margin-top: 8px; word-break: break-all; }}
  .remediation {{ background: rgba(34,197,94,0.05); border: 1px solid rgba(34,197,94,0.15); border-radius: 8px; padding: 12px 14px; margin-top: 12px; font-size: 0.85rem; color: #86efac; }}
  .refs {{ margin-top: 10px; }}
  .refs a {{ color: var(--accent); font-size: 0.8rem; text-decoration: none; margin-right: 12px; }}
  .refs a:hover {{ text-decoration: underline; }}

  .no-findings {{ padding: 28px 24px; text-align: center; color: var(--muted); }}
  .no-findings .icon {{ font-size: 2rem; margin-bottom: 8px; }}

  .footer {{ text-align: center; color: var(--muted); font-size: 0.8rem; margin-top: 48px; padding-top: 24px; border-top: 1px solid var(--border); }}
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

    return f"""
<div class="finding">
  <div class="finding-header">
    <div class="severity-dot" style="background:{color}"></div>
    <div class="finding-title">{f.payload_name}</div>
    <span class="badge technique-badge">{f.technique}</span>
    <span class="badge conf-badge">{CONFIDENCE_LABEL.get(f.confidence, f.confidence)}</span>
    <span class="badge" style="background:rgba(0,0,0,0.3);color:{color};border:1px solid {color}">{f.severity.upper()}</span>
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
