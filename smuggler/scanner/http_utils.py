"""
HTTP Utilities
Low-level helpers for sending raw HTTP requests and analyzing responses
"""

import socket
import ssl
import time
import re
from typing import Optional, Tuple, Dict, List, Union
from urllib.parse import urlparse
from dataclasses import dataclass


@dataclass
class RawResponse:
    status_code: int
    headers: Dict[str, str]
    body: str
    elapsed: float
    raw: str
    error: Optional[str] = None


WAF_SIGNATURES = {
    "Cloudflare": ["cf-ray", "cloudflare", "__cfduid", "cf-cache-status"],
    "AWS WAF": ["x-amzn-requestid", "x-amz-cf-id", "x-amz-id"],
    "Akamai": ["akamai-grn", "ak-origin"],
    "Fastly": ["fastly-debug-digest", "x-fastly-request-id", "x-served-by"],
    "Imperva": ["x-iinfo", "incap_ses", "_incap_"],
    "F5 BIG-IP": ["bigipserver", "f5_st", "ts0"],
    "ModSecurity": ["mod_security", "modsecurity"],
    "Sucuri": ["x-sucuri-id", "sucuri-clientid"],
    "StackPath": ["x-sp-url", "x-sp-edge"],
    "Nginx": ["nginx"],
    "Apache": ["apache"],
    "IIS": ["iis", "asp.net"],
    "LiteSpeed": ["litespeed"],
}

BACKEND_SIGNATURES = {
    "Apache": [r"Apache/[\d\.]+", r"apache"],
    "Nginx": [r"nginx/[\d\.]+", r"openresty"],
    "IIS": [r"Microsoft-IIS/[\d\.]+", r"ASP\.NET"],
    "Tomcat": [r"Apache-Coyote", r"Tomcat"],
    "Node.js": [r"Express", r"Node\.js"],
    "Gunicorn": [r"gunicorn/[\d\.]+"],
    "Caddy": [r"Caddy"],
    "LiteSpeed": [r"LiteSpeed"],
    "HAProxy": [r"haproxy"],
}


def parse_url(url: str) -> Tuple[str, int, str, bool]:
    """Returns (host, port, path, is_https)"""
    parsed = urlparse(url)
    is_https = parsed.scheme == "https"
    host = parsed.hostname or ""
    port = parsed.port or (443 if is_https else 80)
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    return host, port, path, is_https


def send_raw_http(
    url: str,
    method: str,
    headers: Union[Dict[str, str], List[Tuple[str, str]]],
    body: str,
    timeout: float = 10.0,
    verify_ssl: bool = True,
    raw_headers: Optional[List[Tuple[str, str]]] = None,
) -> RawResponse:
    """
    Send a raw TCP HTTP request (bypasses urllib3 normalization).
    This is essential for smuggling tests — high-level HTTP libraries
    sanitize/normalize headers which would prevent sending malformed requests.

    Args:
        raw_headers: If provided, used instead of headers dict. Allows duplicate header names.
    """
    host, port, path, is_https = parse_url(url)
    start = time.time()

    # Build raw HTTP/1.1 request
    raw_body = body.replace("\\r\\n", "\r\n") if "\\r\\n" in body else body

    request_lines = [f"{method} {path} HTTP/1.1"]
    request_lines.append(f"Host: {host}")

    # Use raw_headers if provided (supports duplicate headers), else use dict
    if raw_headers:
        for k, v in raw_headers:
            request_lines.append(f"{k}: {v}")
    elif isinstance(headers, dict):
        for k, v in headers.items():
            request_lines.append(f"{k}: {v}")
    else:
        for k, v in headers:
            request_lines.append(f"{k}: {v}")

    request_lines.append(f"Connection: close")
    request_lines.append("")
    request_lines.append(raw_body)

    raw_request = "\r\n".join(request_lines)

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)

        if is_https:
            ctx = ssl.create_default_context()
            if not verify_ssl:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=host)

        sock.connect((host, port))
        sock.sendall(raw_request.encode("utf-8", errors="replace"))

        response_data = b""
        while True:
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response_data += chunk
            except socket.timeout:
                break

        sock.close()
        elapsed = time.time() - start

        raw_str = response_data.decode("utf-8", errors="replace")
        return _parse_raw_response(raw_str, elapsed)

    except socket.timeout:
        elapsed = time.time() - start
        return RawResponse(
            status_code=0,
            headers={},
            body="",
            elapsed=elapsed,
            raw="",
            error="TIMEOUT",
        )
    except Exception as e:
        elapsed = time.time() - start
        return RawResponse(
            status_code=0,
            headers={},
            body="",
            elapsed=elapsed,
            raw="",
            error=str(e),
        )


def _parse_raw_response(raw: str, elapsed: float) -> RawResponse:
    """Parse raw HTTP response string"""
    if not raw:
        return RawResponse(0, {}, "", elapsed, raw, "Empty response")

    try:
        header_section, _, body = raw.partition("\r\n\r\n")
        lines = header_section.split("\r\n")
        status_line = lines[0] if lines else ""

        status_code = 0
        parts = status_line.split(" ", 2)
        if len(parts) >= 2:
            try:
                status_code = int(parts[1])
            except ValueError:
                pass

        headers = {}
        for line in lines[1:]:
            if ":" in line:
                k, _, v = line.partition(":")
                headers[k.strip().lower()] = v.strip()

        return RawResponse(
            status_code=status_code,
            headers=headers,
            body=body,
            elapsed=elapsed,
            raw=raw,
        )
    except Exception as e:
        return RawResponse(0, {}, "", elapsed, raw, f"Parse error: {e}")


def detect_waf(headers: Dict[str, str], server_header: str = "") -> Optional[str]:
    """Detect WAF/CDN from response headers"""
    combined = " ".join(headers.keys()).lower() + " " + " ".join(headers.values()).lower()
    combined += " " + server_header.lower()

    for waf_name, signatures in WAF_SIGNATURES.items():
        for sig in signatures:
            if sig.lower() in combined:
                return waf_name
    return None


def fingerprint_backend(headers: Dict[str, str]) -> Optional[str]:
    """Fingerprint backend server from response headers"""
    server = headers.get("server", "") + headers.get("x-powered-by", "")

    for backend_name, patterns in BACKEND_SIGNATURES.items():
        for pattern in patterns:
            if re.search(pattern, server, re.IGNORECASE):
                return backend_name
    return None


def is_timing_anomaly(baseline: float, actual: float, threshold: float = 5.0) -> bool:
    """True if actual response time is suspiciously slower than baseline"""
    return actual > (baseline + threshold)
