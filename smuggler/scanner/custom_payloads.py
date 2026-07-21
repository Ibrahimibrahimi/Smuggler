"""
Custom Payload Loader
Load user-defined payloads from YAML files and merge them into the registry
"""

from pathlib import Path
from typing import List

import yaml

from smuggler.payloads.database import SmugglePayload, ALL_PAYLOADS, TECHNIQUES


REQUIRED_FIELDS = {"name", "technique", "description", "severity", "headers", "body", "expected_behavior"}
VALID_SEVERITIES = {"critical", "high", "medium", "low"}


def _validate_payload(data: dict) -> SmugglePayload:
    """Validate a raw payload dict and return a SmugglePayload instance."""
    missing = REQUIRED_FIELDS - set(data.keys())
    if missing:
        raise ValueError(f"Payload '{data.get('name', '<unnamed>')}' missing required fields: {', '.join(sorted(missing))}")

    severity = data["severity"].lower()
    if severity not in VALID_SEVERITIES:
        raise ValueError(f"Payload '{data['name']}' has invalid severity '{data['severity']}' (expected one of: {', '.join(sorted(VALID_SEVERITIES))})")

    return SmugglePayload(
        name=data["name"],
        technique=data["technique"].upper(),
        description=data["description"],
        severity=severity,
        headers=data["headers"],
        body=data.get("body", ""),
        expected_behavior=data["expected_behavior"],
        references=data.get("references", []),
        tags=data.get("tags", []),
        raw_headers=data.get("raw_headers", []),
    )


def load_custom_payloads(file_path: str) -> List[SmugglePayload]:
    """Load user-defined payloads from a YAML file.

    The file should contain a list of payload objects, each with at least:
      name, technique, description, severity, headers, body, expected_behavior
    """
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"Payload file not found: {file_path}")

    with open(path, "r", encoding="utf-8") as f:
        raw = yaml.safe_load(f)

    if not isinstance(raw, list):
        raise ValueError(f"Expected a YAML list of payloads, got {type(raw).__name__}")

    payloads: List[SmugglePayload] = []
    for idx, entry in enumerate(raw):
        if not isinstance(entry, dict):
            raise ValueError(f"Entry #{idx + 1} is not a mapping")
        payloads.append(_validate_payload(entry))

    return payloads


def merge_payloads(built_in: List[SmugglePayload], custom: List[SmugglePayload]) -> List[SmugglePayload]:
    """Merge custom payloads into the built-in list.

    Deduplicates by name (custom payloads override built-in with the same name).
    Returns the combined list.
    """
    merged = {p.name: p for p in built_in}
    for p in custom:
        merged[p.name] = p
    return list(merged.values())


def register_custom_payloads(custom: List[SmugglePayload]) -> None:
    """Register custom payloads into the global ALL_PAYLOADS and TECHNIQUES registries."""
    global ALL_PAYLOADS, TECHNIQUES

    merged = merge_payloads(ALL_PAYLOADS, custom)
    ALL_PAYLOADS.clear()
    ALL_PAYLOADS.extend(merged)

    TECHNIQUES.clear()
    for p in ALL_PAYLOADS:
        TECHNIQUES.setdefault(p.technique, []).append(p)
