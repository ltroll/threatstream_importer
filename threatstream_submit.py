#!/usr/bin/env python3
"""Submit indicators to Anomali ThreatStream without UI approval.

This module can be used as a CLI or imported from another Python script.
Configuration is loaded from a .env file by default.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


DEFAULT_BASE_URL = "https://api.threatstream.com"
DEFAULT_TIMEOUT = 30
DEFAULT_TAG_TLP = "red"
INDICATOR_FIELDS = {
    "domain": "domain",
    "email": "email",
    "ip": "srcip",
    "url": "url",
}


class ThreatStreamError(RuntimeError):
    """Raised when ThreatStream rejects the request or cannot be reached."""


def load_dotenv(path: str | Path | None = None) -> dict[str, str]:
    """Load simple KEY=VALUE pairs from a .env file into os.environ.

    Existing environment variables are not overwritten. Lines beginning with
    "#" and blank lines are ignored.
    """

    env_path = Path(path) if path else Path(__file__).with_name(".env")
    values: dict[str, str] = {}

    if not env_path.exists():
        return values

    for line_number, raw_line in enumerate(env_path.read_text().splitlines(), 1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export ") :].strip()
        if "=" not in line:
            raise ValueError(f"Invalid .env line {line_number}: expected KEY=VALUE")

        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip("'\"")

        if not key:
            raise ValueError(f"Invalid .env line {line_number}: empty key")

        values[key] = value
        os.environ.setdefault(key, value)

    return values


def parse_tags(tags: str | list[str] | None, tlp: str | None = None) -> list[dict[str, str]]:
    """Convert comma-separated tags or a list of tag names into ThreatStream tag objects."""

    if tags is None:
        return []
    if isinstance(tags, str):
        names = [tag.strip() for tag in tags.split(",")]
    else:
        names = [tag.strip() for tag in tags]

    parsed_tags = [{"name": name} for name in names if name]
    if tlp:
        for tag in parsed_tags:
            tag["tlp"] = tlp
    return parsed_tags


def build_payload(
    indicator: str,
    indicator_type: str,
    itype: str,
    tags: str | list[str] | None = None,
    *,
    classification: str | None = None,
    confidence: int | None = None,
    severity: str | None = None,
    allow_unresolved: bool | None = None,
    source_confidence_weight: int | None = None,
    tag_tlp: str | None = DEFAULT_TAG_TLP,
) -> dict[str, Any]:
    """Build the JSON payload expected by ThreatStream's direct import API."""

    normalized_type = indicator_type.lower().strip()
    if normalized_type not in INDICATOR_FIELDS:
        allowed = ", ".join(sorted(INDICATOR_FIELDS))
        raise ValueError(f"Unsupported indicator type '{indicator_type}'. Use one of: {allowed}")

    meta: dict[str, Any] = {}
    if classification:
        meta["classification"] = classification
    if confidence is not None:
        meta["confidence"] = confidence
    if allow_unresolved is not None:
        meta["allow_unresolved"] = allow_unresolved
    if source_confidence_weight is not None:
        meta["source_confidence_weight"] = source_confidence_weight

    indicator_object: dict[str, Any] = {
        INDICATOR_FIELDS[normalized_type]: indicator,
        "itype": itype,
    }
    parsed_tags = parse_tags(tags, tag_tlp)
    if parsed_tags:
        indicator_object["tags"] = parsed_tags
    if severity:
        indicator_object["severity"] = severity

    payload: dict[str, Any] = {"objects": [indicator_object]}
    if meta:
        payload["meta"] = meta
    return payload


def submit_indicator(
    indicator: str,
    indicator_type: str,
    itype: str,
    tags: str | list[str] | None = None,
    *,
    username: str | None = None,
    api_key: str | None = None,
    base_url: str | None = None,
    classification: str | None = None,
    confidence: int | None = None,
    severity: str | None = None,
    allow_unresolved: bool | None = None,
    source_confidence_weight: int | None = None,
    tag_tlp: str | None = DEFAULT_TAG_TLP,
    timeout: int = DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    """Submit a single indicator and return status/body details.

    username and api_key default to THREATSTREAM_USERNAME and
    THREATSTREAM_API_KEY from the environment or .env file.
    """

    load_dotenv()

    resolved_username = username or os.environ.get("THREATSTREAM_USERNAME")
    resolved_api_key = api_key or os.environ.get("THREATSTREAM_API_KEY")
    resolved_base_url = (base_url or os.environ.get("THREATSTREAM_BASE_URL") or DEFAULT_BASE_URL).rstrip("/")

    if not resolved_username:
        raise ThreatStreamError("Missing THREATSTREAM_USERNAME in environment or .env")
    if not resolved_api_key:
        raise ThreatStreamError("Missing THREATSTREAM_API_KEY in environment or .env")

    payload = build_payload(
        indicator,
        indicator_type,
        itype,
        tags,
        classification=classification,
        confidence=confidence,
        severity=severity,
        allow_unresolved=allow_unresolved,
        source_confidence_weight=source_confidence_weight,
        tag_tlp=tag_tlp,
    )

    request_body = json.dumps(payload).encode("utf-8")
    request = Request(
        f"{resolved_base_url}/api/v2/intelligence/",
        data=request_body,
        method="PATCH",
        headers={
            "Authorization": f"apikey {resolved_username}:{resolved_api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "threatstream-submit/1.0",
        },
    )

    try:
        with urlopen(request, timeout=timeout) as response:
            body = response.read().decode("utf-8")
            return {
                "status_code": response.status,
                "success": 200 <= response.status < 300,
                "body": _parse_response_body(body),
            }
    except HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        raise ThreatStreamError(
            f"ThreatStream returned HTTP {exc.code}: {_format_response_body(body)}"
        ) from exc
    except URLError as exc:
        raise ThreatStreamError(f"Could not reach ThreatStream: {exc.reason}") from exc


def _parse_response_body(body: str) -> Any:
    if not body:
        return None
    try:
        return json.loads(body)
    except json.JSONDecodeError:
        return body


def _format_response_body(body: str) -> str:
    parsed = _parse_response_body(body)
    if isinstance(parsed, (dict, list)):
        return json.dumps(parsed, indent=2, sort_keys=True)
    return str(parsed)


def _env_bool(name: str, default: bool | None = None) -> bool | None:
    value = os.environ.get(name)
    if value is None or value == "":
        return default
    if value.lower() in {"1", "true", "yes", "y", "on"}:
        return True
    if value.lower() in {"0", "false", "no", "n", "off"}:
        return False
    raise ValueError(f"{name} must be a boolean value")


def _env_int(name: str, default: int | None = None) -> int | None:
    value = os.environ.get(name)
    if value is None or value == "":
        return default
    return int(value)


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Submit an IP, domain, email, or URL indicator to ThreatStream without UI approval."
    )
    parser.add_argument(
        "indicator",
        help="Indicator value, for example 1.2.3.4, example.com, user@example.com, or https://example.com/path",
    )
    parser.add_argument(
        "-t",
        "--tags",
        default=None,
        help="Comma-separated tag names, for example phishing,case-123",
    )
    parser.add_argument(
        "--indicator-type",
        choices=sorted(INDICATOR_FIELDS),
        required=True,
        help="Observable type for the indicator.",
    )
    parser.add_argument("--itype", required=True, help="ThreatStream indicator type, for example mal_ip")
    parser.add_argument(
        "--env-file",
        default=None,
        help="Path to .env file. Defaults to .env next to threatstream_submit.py.",
    )
    parser.add_argument("--classification", choices=["public", "private"], default=None)
    parser.add_argument("--confidence", type=int, choices=range(0, 101), metavar="0-100", default=None)
    parser.add_argument(
        "--severity",
        choices=["low", "medium", "high", "very-high"],
        default=None,
    )
    parser.add_argument(
        "--allow-unresolved",
        action="store_true",
        default=None,
        help="Set meta.allow_unresolved=true, useful for unresolved domains.",
    )
    parser.add_argument(
        "--source-confidence-weight",
        type=int,
        choices=range(0, 101),
        metavar="0-100",
        default=None,
    )
    parser.add_argument(
        "--tag-tlp",
        choices=["red", "amber", "amber+strict", "green", "clear", "white"],
        default=None,
        help="TLP visibility applied to every tag. Defaults to red, which makes tags private.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the payload that would be submitted without calling ThreatStream.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    load_dotenv(args.env_file)

    classification = args.classification or os.environ.get("THREATSTREAM_CLASSIFICATION")
    confidence = args.confidence if args.confidence is not None else _env_int("THREATSTREAM_CONFIDENCE")
    severity = args.severity or os.environ.get("THREATSTREAM_SEVERITY")
    source_confidence_weight = (
        args.source_confidence_weight
        if args.source_confidence_weight is not None
        else _env_int("THREATSTREAM_SOURCE_CONFIDENCE_WEIGHT")
    )
    allow_unresolved = (
        args.allow_unresolved
        if args.allow_unresolved is not None
        else _env_bool("THREATSTREAM_ALLOW_UNRESOLVED")
    )
    tag_tlp = args.tag_tlp or os.environ.get("THREATSTREAM_TAG_TLP") or DEFAULT_TAG_TLP

    payload = build_payload(
        args.indicator,
        args.indicator_type,
        args.itype,
        args.tags,
        classification=classification,
        confidence=confidence,
        severity=severity,
        allow_unresolved=allow_unresolved,
        source_confidence_weight=source_confidence_weight,
        tag_tlp=tag_tlp,
    )

    if args.dry_run:
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 0

    try:
        result = submit_indicator(
            args.indicator,
            args.indicator_type,
            args.itype,
            args.tags,
            classification=classification,
            confidence=confidence,
            severity=severity,
            allow_unresolved=allow_unresolved,
            source_confidence_weight=source_confidence_weight,
            tag_tlp=tag_tlp,
        )
    except (ThreatStreamError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
