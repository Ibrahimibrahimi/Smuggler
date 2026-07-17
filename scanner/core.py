"""
Scanner Core Engine
Orchestrates all detection techniques across targets
"""

import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Callable
from datetime import datetime

from config.manager import ScanConfig
from payloads.database import ALL_PAYLOADS, SmugglePayload, TECHNIQUES
from utils.http import (
    send_raw_http,
    detect_waf,
    fingerprint_backend,
    get_baseline_response_time,
)
from scanner.detectors import (
    Finding,
    detect_cl_te,
    detect_te_cl,
    detect_te_te,
    detect_h2_smuggling,
    detect_crlf,
)


@dataclass
class TargetInfo:
    url: str
    waf: Optional[str] = None
    backend: Optional[str] = None
    supports_h2: bool = False
    baseline_time: float = 0.0
    server_header: str = ""
    reachable: bool = True
    error: Optional[str] = None


@dataclass
class ScanResult:
    target: str
    started_at: str
    finished_at: str = ""
    duration: float = 0.0
    target_info: Optional[TargetInfo] = None
    findings: List[Finding] = field(default_factory=list)
    techniques_tested: List[str] = field(default_factory=list)
    total_requests: int = 0
    errors: List[str] = field(default_factory=list)

    @property
    def is_vulnerable(self) -> bool:
        return len(self.findings) > 0

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "critical")

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "high")


ProgressCallback = Callable[[str, int, int], None]


def _probe_target(url: str, extra_headers: Dict, timeout: float) -> TargetInfo:
    """Probe target: reachability, WAF, backend, baseline timing"""
    info = TargetInfo(url=url)
    try:
        resp = send_raw_http(url, "GET", extra_headers, "", timeout=timeout)
        if resp.error and resp.status_code == 0:
            info.reachable = False
            info.error = resp.error
            return info

        info.server_header = resp.headers.get("server", "")
        info.waf = detect_waf(resp.headers, info.server_header)
        info.backend = fingerprint_backend(resp.headers)
        info.baseline_time = resp.elapsed

        # Check HTTP/2 support via Alt-Svc header
        alt_svc = resp.headers.get("alt-svc", "")
        info.supports_h2 = "h2" in alt_svc.lower()

    except Exception as e:
        info.reachable = False
        info.error = str(e)

    return info


def _scan_single_target(
    url: str,
    cfg: ScanConfig,
    progress_cb: Optional[ProgressCallback] = None,
) -> ScanResult:
    """Run all requested techniques against a single target"""
    started_at = datetime.now().isoformat()
    result = ScanResult(target=url, started_at=started_at)

    # Build auth headers / cookies
    extra_headers: Dict[str, str] = {}
    cookies: Dict[str, str] = {}
    if cfg.use_auth and cfg.auth:
        extra_headers = cfg.auth.get_auth_headers()
        cookies = cfg.auth.get_cookies_dict()

    # Step 1: Probe target
    if progress_cb:
        progress_cb("Probing target...", 0, 1)
    target_info = _probe_target(url, extra_headers, cfg.timeout)
    result.target_info = target_info
    result.total_requests += 1

    if not target_info.reachable:
        result.errors.append(f"Target unreachable: {target_info.error}")
        result.finished_at = datetime.now().isoformat()
        return result

    baseline = target_info.baseline_time

    # Step 2: Select payloads based on requested techniques
    payloads_to_test: List[SmugglePayload] = []
    for technique in cfg.techniques:
        payloads_to_test.extend(TECHNIQUES.get(technique, []))

    # Step 3: Skip H2 techniques if target doesn't advertise H2
    if not target_info.supports_h2:
        payloads_to_test = [
            p for p in payloads_to_test
            if p.technique not in ("H2.CL", "H2.TE", "H2.RL")
        ]

    total_payloads = len(payloads_to_test)
    result.techniques_tested = list({p.technique for p in payloads_to_test})

    # Step 4: Run detectors
    for idx, payload in enumerate(payloads_to_test):
        if progress_cb:
            progress_cb(f"Testing {payload.technique}: {payload.name}", idx, total_payloads)

        finding: Optional[Finding] = None

        try:
            if payload.technique == "CL.TE":
                finding = detect_cl_te(
                    url, payload, extra_headers, cookies,
                    cfg.timeout, baseline, cfg.timing_threshold,
                )
            elif payload.technique == "TE.CL":
                finding = detect_te_cl(
                    url, payload, extra_headers, cookies,
                    cfg.timeout, baseline, cfg.timing_threshold,
                )
            elif payload.technique in ("TE.TE",):
                finding = detect_te_te(
                    url, payload, extra_headers, cookies,
                    cfg.timeout, baseline, cfg.timing_threshold,
                )
            elif payload.technique in ("H2.CL", "H2.TE", "H2.RL"):
                finding = detect_h2_smuggling(
                    url, payload, extra_headers, cookies,
                    cfg.timeout, baseline,
                )
            elif payload.technique == "CRLF":
                finding = detect_crlf(
                    url, payload, extra_headers, cookies,
                    cfg.timeout, baseline,
                )

            result.total_requests += 1

            if finding:
                result.findings.append(finding)

        except Exception as e:
            result.errors.append(f"{payload.name}: {e}")

        # Rate limiting
        if cfg.delay > 0:
            time.sleep(cfg.delay)

    result.finished_at = datetime.now().isoformat()
    result.duration = sum(f.elapsed for f in result.findings)

    if progress_cb:
        progress_cb("Done", total_payloads, total_payloads)

    return result


class SmuggleScanner:
    """Main scanner class — handles single and batch scanning"""

    def __init__(self, cfg: ScanConfig):
        self.cfg = cfg
        self._stop_event = threading.Event()

    def stop(self):
        self._stop_event.set()

    def scan(
        self,
        url: str,
        progress_cb: Optional[ProgressCallback] = None,
    ) -> ScanResult:
        """Scan a single target"""
        return _scan_single_target(url, self.cfg, progress_cb)

    def scan_multiple(
        self,
        urls: List[str],
        on_result: Optional[Callable[[ScanResult], None]] = None,
        progress_cb: Optional[ProgressCallback] = None,
    ) -> List[ScanResult]:
        """Scan multiple targets with thread pool"""
        results: List[ScanResult] = []
        lock = threading.Lock()

        def run_one(url: str) -> ScanResult:
            if self._stop_event.is_set():
                return ScanResult(
                    target=url,
                    started_at=datetime.now().isoformat(),
                    errors=["Scan cancelled"],
                )
            r = _scan_single_target(url, self.cfg, progress_cb)
            with lock:
                results.append(r)
                if on_result:
                    on_result(r)
            return r

        with ThreadPoolExecutor(max_workers=self.cfg.threads) as executor:
            futures = {executor.submit(run_one, url): url for url in urls}
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    url = futures[future]
                    with lock:
                        results.append(
                            ScanResult(
                                target=url,
                                started_at=datetime.now().isoformat(),
                                errors=[str(e)],
                            )
                        )

        return results

    def load_targets_from_file(self, path: str) -> List[str]:
        """Load URL targets from a newline-separated file"""
        with open(path) as f:
            lines = f.read().splitlines()
        targets = []
        for line in lines:
            line = line.strip()
            if line and not line.startswith("#"):
                if not line.startswith(("http://", "https://")):
                    line = "https://" + line
                targets.append(line)
        return targets
