"""
Smuggling Detectors
Each detector implements a specific technique check and returns a Finding
"""

import time
from dataclasses import dataclass, field
from typing import Optional, List, Dict
from enum import Enum

from smuggler.scanner.http_utils import send_raw_http, RawResponse, is_timing_anomaly
from smuggler.payloads.database import SmugglePayload


class Confidence(str, Enum):
    CONFIRMED = "confirmed"
    LIKELY     = "likely"
    POSSIBLE   = "possible"
    FALSE_POS  = "false_positive"


@dataclass
class Finding:
    technique: str
    payload_name: str
    severity: str
    confidence: Confidence
    url: str
    description: str
    evidence: str
    request_sent: str
    response_received: str
    elapsed: float
    remediation: str = ""
    references: List[str] = field(default_factory=list)
    extra: Dict = field(default_factory=dict)


REMEDIATION_MAP = {
    "CL.TE": (
        "Ensure all proxy layers use the same body-length header. "
        "Prefer Transfer-Encoding and disable or normalize Content-Length on intermediaries. "
        "Use HTTP/2 end-to-end where possible."
    ),
    "TE.CL": (
        "Configure front-end to consistently forward Transfer-Encoding to the backend. "
        "Reject requests with conflicting Content-Length and Transfer-Encoding headers."
    ),
    "TE.TE": (
        "Reject requests with multiple or malformed Transfer-Encoding headers. "
        "Normalize all TE headers at the WAF/CDN layer before forwarding."
    ),
    "H2.CL": (
        "Disable HTTP/1.1 downgrade where possible or use strict HTTP/2 end-to-end. "
        "Strip Content-Length from HTTP/2 requests before downgrading."
    ),
    "H2.TE": (
        "Per RFC 9113, Transfer-Encoding is forbidden in HTTP/2 — reject such requests at ingress. "
        "Do not forward TE headers when downgrading to HTTP/1.1."
    ),
    "H2.RL": (
        "Validate HTTP/2 pseudo-header values. Reject any :path, :method, or :authority "
        "containing CRLF or other control characters."
    ),
    "CRLF": (
        "Strip or reject CRLF sequences in all header values. "
        "Apply strict header validation at every proxy layer."
    ),
}


def _build_evidence(response: RawResponse, extra_note: str = "") -> str:
    lines = []
    if response.error:
        lines.append(f"Error: {response.error}")
    else:
        lines.append(f"Status: {response.status_code}")
        lines.append(f"Elapsed: {response.elapsed:.3f}s")
    if extra_note:
        lines.append(extra_note)
    return " | ".join(lines)


def _format_request(method: str, url: str, headers: dict, body: str) -> str:
    lines = [f"{method} {url} HTTP/1.1"]
    for k, v in headers.items():
        lines.append(f"{k}: {v}")
    lines.append("")
    lines.append(repr(body))
    return "\n".join(lines)


def detect_cl_te(
    url: str,
    payload: SmugglePayload,
    extra_headers: Dict[str, str],
    cookies: Dict[str, str],
    timeout: float,
    baseline_time: float,
    timing_threshold: float,
    verify_ssl: bool = True,
) -> Optional[Finding]:
    """
    CL.TE detection: send request with both Content-Length and Transfer-Encoding.
    Frontend uses CL, backend uses TE. If smuggled byte causes next request to
    error or if timing reveals backend waiting for chunk terminator.
    """
    headers = {**extra_headers, **payload.headers}
    if cookies:
        headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in cookies.items())

    # Timing-based: send incomplete chunked body
    timing_headers = {**headers, "Content-Length": "4", "Transfer-Encoding": "chunked"}
    timing_body = "1\r\nA"  # No terminator — backend waits

    resp = send_raw_http(url, "POST", timing_headers, timing_body, timeout=timeout, verify_ssl=verify_ssl)

    if resp.error == "TIMEOUT" or is_timing_anomaly(baseline_time, resp.elapsed, timing_threshold):
        return Finding(
            technique="CL.TE",
            payload_name=payload.name + " (timing)",
            severity="high",
            confidence=Confidence.LIKELY,
            url=url,
            description="CL.TE timing anomaly: backend timed out waiting for chunked terminator. "
                        "Indicates front-end used Content-Length, back-end used Transfer-Encoding.",
            evidence=_build_evidence(resp, f"baseline={baseline_time:.2f}s actual={resp.elapsed:.2f}s"),
            request_sent=_format_request("POST", url, timing_headers, timing_body),
            response_received=resp.raw[:500],
            elapsed=resp.elapsed,
            remediation=REMEDIATION_MAP["CL.TE"],
            references=payload.references,
        )

    # Differential response: send smuggled prefix, check next request status
    headers2 = {**headers}
    resp2 = send_raw_http(url, "POST", headers2, payload.body, timeout=timeout, verify_ssl=verify_ssl)

    if resp2.status_code in (400, 403, 405, 501) and resp2.elapsed > baseline_time * 1.5:
        return Finding(
            technique="CL.TE",
            payload_name=payload.name,
            severity=payload.severity,
            confidence=Confidence.POSSIBLE,
            url=url,
            description=f"CL.TE differential: unexpected {resp2.status_code} with elevated response time. "
                        "Possible smuggled prefix consumed by backend.",
            evidence=_build_evidence(resp2, f"status={resp2.status_code}"),
            request_sent=_format_request("POST", url, headers2, payload.body),
            response_received=resp2.raw[:500],
            elapsed=resp2.elapsed,
            remediation=REMEDIATION_MAP["CL.TE"],
            references=payload.references,
        )

    return None


def detect_te_cl(
    url: str,
    payload: SmugglePayload,
    extra_headers: Dict[str, str],
    cookies: Dict[str, str],
    timeout: float,
    baseline_time: float,
    timing_threshold: float,
    verify_ssl: bool = True,
) -> Optional[Finding]:
    """
    TE.CL detection: front-end uses Transfer-Encoding, back-end uses Content-Length.
    Timing: oversized Content-Length causes backend to wait for more body data.
    """
    headers = {**extra_headers, **payload.headers}
    if cookies:
        headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in cookies.items())

    # Timing-based: backend waiting for Content-Length bytes that won't come
    timing_headers = {
        **headers,
        "Content-Length": "6",
        "Transfer-Encoding": "chunked",
    }
    timing_body = "0\r\n\r\nX"  # Frontend reads chunk 0 (done), backend wants 6 bytes

    resp = send_raw_http(url, "POST", timing_headers, timing_body, timeout=timeout, verify_ssl=verify_ssl)

    if resp.error == "TIMEOUT" or is_timing_anomaly(baseline_time, resp.elapsed, timing_threshold):
        return Finding(
            technique="TE.CL",
            payload_name=payload.name + " (timing)",
            severity="high",
            confidence=Confidence.LIKELY,
            url=url,
            description="TE.CL timing anomaly: backend waited for additional body bytes not sent. "
                        "Indicates front-end used Transfer-Encoding, back-end used Content-Length.",
            evidence=_build_evidence(resp, f"baseline={baseline_time:.2f}s actual={resp.elapsed:.2f}s"),
            request_sent=_format_request("POST", url, timing_headers, timing_body),
            response_received=resp.raw[:500],
            elapsed=resp.elapsed,
            remediation=REMEDIATION_MAP["TE.CL"],
            references=payload.references,
        )

    return None


def detect_te_te(
    url: str,
    payload: SmugglePayload,
    extra_headers: Dict[str, str],
    cookies: Dict[str, str],
    timeout: float,
    baseline_time: float,
    timing_threshold: float,
    verify_ssl: bool = True,
) -> Optional[Finding]:
    """
    TE.TE: both front and back use Transfer-Encoding, but obfuscation causes one
    to ignore the header — falls back to Content-Length -> desync
    """
    headers = {**extra_headers, **payload.headers}
    if cookies:
        headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in cookies.items())

    # Use raw_headers if payload has them (for duplicate header payloads)
    resp = send_raw_http(
        url, "POST", headers, payload.body, timeout=timeout, verify_ssl=verify_ssl,
        raw_headers=payload.raw_headers if payload.raw_headers else None,
    )

    if resp.error == "TIMEOUT" or is_timing_anomaly(baseline_time, resp.elapsed, timing_threshold):
        return Finding(
            technique="TE.TE",
            payload_name=payload.name,
            severity=payload.severity,
            confidence=Confidence.POSSIBLE,
            url=url,
            description=f"TE.TE obfuscation ({payload.name}): timing anomaly with obfuscated "
                        "Transfer-Encoding header. One proxy layer likely ignored the header.",
            evidence=_build_evidence(resp, f"technique={payload.name}"),
            request_sent=_format_request("POST", url, headers, payload.body),
            response_received=resp.raw[:500],
            elapsed=resp.elapsed,
            remediation=REMEDIATION_MAP["TE.TE"],
            references=payload.references,
        )

    # Check for unexpected error response (differential)
    if resp.status_code in (400, 413, 501):
        return Finding(
            technique="TE.TE",
            payload_name=payload.name,
            severity="medium",
            confidence=Confidence.POSSIBLE,
            url=url,
            description=f"TE.TE obfuscation ({payload.name}): server returned {resp.status_code} "
                        "for obfuscated Transfer-Encoding — possible inconsistent parsing.",
            evidence=_build_evidence(resp),
            request_sent=_format_request("POST", url, headers, payload.body),
            response_received=resp.raw[:500],
            elapsed=resp.elapsed,
            remediation=REMEDIATION_MAP["TE.TE"],
            references=payload.references,
        )

    return None


def detect_h2_smuggling(
    url: str,
    payload: SmugglePayload,
    extra_headers: Dict[str, str],
    cookies: Dict[str, str],
    timeout: float,
    baseline_time: float,
    verify_ssl: bool = True,
    verbose: int = 0,
) -> Optional[Finding]:
    """
    HTTP/2 downgrade smuggling: attempt H2 request with forbidden headers.
    Uses httpx with HTTP/2 support.

    Note: Full H2 smuggling (especially H2.RL pseudo-header injection) requires
    raw HTTP/2 frame construction via the h2 library. This detection is limited
    to what httpx can express.
    """
    try:
        import httpx

        headers = {**extra_headers, **payload.headers}
        if cookies:
            headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in cookies.items())

        start = time.time()
        with httpx.Client(http2=True, verify=verify_ssl, timeout=timeout) as client:
            resp = client.post(url, headers=headers, content=payload.body.encode())
        elapsed = time.time() - start

        if resp.status_code in (400, 403, 502, 503) or is_timing_anomaly(baseline_time, elapsed, 4.0):
            return Finding(
                technique=payload.technique,
                payload_name=payload.name,
                severity=payload.severity,
                confidence=Confidence.POSSIBLE,
                url=url,
                description=f"HTTP/2 smuggling probe ({payload.name}): anomalous response {resp.status_code}. "
                            "Server may be vulnerable to H2 downgrade desync.",
                evidence=f"Status: {resp.status_code} | Elapsed: {elapsed:.3f}s",
                request_sent=_format_request("POST", url, headers, payload.body),
                response_received=resp.text[:500],
                elapsed=elapsed,
                remediation=REMEDIATION_MAP.get(payload.technique, ""),
                references=payload.references,
            )
    except ImportError:
        if verbose >= 2:
            pass  # httpx[http2] not installed — silently skip
    except Exception as e:
        if verbose >= 2:
            # Log the error in debug mode instead of silently swallowing
            import sys
            print(f"[DEBUG] H2 detection error for {payload.name}: {e}", file=sys.stderr)

    return None


def detect_crlf(
    url: str,
    payload: SmugglePayload,
    extra_headers: Dict[str, str],
    cookies: Dict[str, str],
    timeout: float,
    baseline_time: float,
    verify_ssl: bool = True,
) -> Optional[Finding]:
    """CRLF injection detection in header values"""
    headers = {**extra_headers, **payload.headers}
    if cookies:
        headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in cookies.items())

    resp = send_raw_http(url, "POST", headers, payload.body, timeout=timeout, verify_ssl=verify_ssl)

    # If the injected TE header was processed, we might see chunked response behavior
    if "transfer-encoding" in resp.headers and is_timing_anomaly(baseline_time, resp.elapsed, 3.0):
        return Finding(
            technique="CRLF",
            payload_name=payload.name,
            severity=payload.severity,
            confidence=Confidence.POSSIBLE,
            url=url,
            description="CRLF injection in header values may have introduced a Transfer-Encoding header. "
                        "This can enable request smuggling through header injection.",
            evidence=_build_evidence(resp),
            request_sent=_format_request("POST", url, headers, payload.body),
            response_received=resp.raw[:500],
            elapsed=resp.elapsed,
            remediation=REMEDIATION_MAP["CRLF"],
            references=payload.references,
        )

    return None
