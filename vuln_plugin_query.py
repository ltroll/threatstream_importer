#!/usr/bin/env python3
"""Query a ThreatStream vulnerability-management integration transform for CVEs."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from threatstream_submit import DEFAULT_BASE_URL, ThreatStreamError, load_dotenv


DEFAULT_TRANSFORM_PATH = "/api/v1/integration_package/transform/"
DEFAULT_TRANSFORM_ID = "4425"
CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,19}$", re.IGNORECASE)


class TransformError(RuntimeError):
    """Raised when the ThreatStream transform request fails."""


def query_vulnerability_plugin(
    cves: str | list[str],
    *,
    transform_id: str | None = None,
    username: str | None = None,
    api_key: str | None = None,
    base_url: str | None = None,
    transform_path: str | None = None,
    timeout: int = 60,
    env_file: str | None = None,
) -> dict[str, Any]:
    """Run the vulnerability-management transform for one or more CVEs."""

    load_dotenv(env_file)
    cve_list = _parse_cves(cves)
    resolved_transform_id = transform_id or os.environ.get("THREATSTREAM_VULN_TRANSFORM_ID") or DEFAULT_TRANSFORM_ID
    resolved_base_url = (base_url or os.environ.get("THREATSTREAM_BASE_URL") or DEFAULT_BASE_URL).rstrip("/")
    resolved_path = transform_path or os.environ.get("THREATSTREAM_TRANSFORM_PATH") or DEFAULT_TRANSFORM_PATH

    request_body = {
        "transform_ids": [str(resolved_transform_id)],
        "entities": [
            {
                "entity_value": "vulnerability",
                "entity_fields": json.dumps({"cve_list": cve_list}),
            }
        ],
    }

    headers = _auth_headers(username=username, api_key=api_key)
    request = Request(
        f"{resolved_base_url}{resolved_path}",
        data=json.dumps(request_body).encode("utf-8"),
        method="POST",
        headers=headers,
    )

    try:
        with urlopen(request, timeout=timeout) as response:
            raw = json.loads(response.read().decode("utf-8"))
    except HTTPError as exc:
        text = exc.read().decode("utf-8", errors="replace")
        raise TransformError(f"ThreatStream transform returned HTTP {exc.code}: {text}") from exc
    except URLError as exc:
        raise TransformError(f"Could not reach ThreatStream: {exc.reason}") from exc
    except json.JSONDecodeError as exc:
        raise TransformError("ThreatStream transform returned non-JSON response") from exc

    return {
        "request": {"cves": cve_list, "transform_id": str(resolved_transform_id)},
        "summary": summarize_transform_response(raw),
        "raw": raw,
    }


def summarize_transform_response(response: dict[str, Any]) -> dict[str, Any]:
    """Extract useful rows from the ThreatStream transform widget response."""

    transform_responses = response.get("response", [])
    summaries: list[dict[str, Any]] = []
    for transform_response in transform_responses if isinstance(transform_responses, list) else []:
        transform_summary = {
            "transform_name": transform_response.get("transform_name"),
            "display_name": transform_response.get("display_name"),
            "transform_id": transform_response.get("transform_id"),
            "status": None,
            "asset_count": None,
            "cve_summary": [],
            "vulnerable_assets": [],
            "messages": [],
            "exceptions": [],
        }

        for result in transform_response.get("transform_result", []):
            transform_summary["status"] = result.get("status")
            json_data = result.get("json_data", {})
            widgets = json_data.get("widgets", []) if isinstance(json_data, dict) else []
            transform_summary["messages"].extend(json_data.get("messages", []) if isinstance(json_data, dict) else [])
            transform_summary["exceptions"].extend(json_data.get("exceptions", []) if isinstance(json_data, dict) else [])
            for widget in widgets if isinstance(widgets, list) else []:
                if widget.get("widgetType") == "Text":
                    text = _item_text(widget.get("item"))
                    asset_count = _parse_asset_count(text)
                    if asset_count is not None:
                        transform_summary["asset_count"] = asset_count
                elif widget.get("widgetType") == "Table":
                    table_name = widget.get("tableName")
                    rows = _table_rows(widget)
                    if table_name == "CVE Summary":
                        transform_summary["cve_summary"].extend(rows)
                    elif table_name == "Vulnerable Assets":
                        transform_summary["vulnerable_assets"].extend(rows)

        summaries.append(transform_summary)

    return {
        "message": response.get("message"),
        "last_updated": response.get("last_updated"),
        "transforms": summaries,
    }


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Query the ThreatStream vulnerability-management transform for CVE exposure."
    )
    parser.add_argument("cves", help="CVE or comma-separated CVEs, for example CVE-2025-14847,CVE-2026-41017")
    parser.add_argument("--env-file", default=None, help="Path to .env file. Defaults to .env next to scripts.")
    parser.add_argument("--transform-id", default=None, help=f"ThreatStream transform ID. Default: {DEFAULT_TRANSFORM_ID}")
    parser.add_argument("--raw", action="store_true", help="Print the raw ThreatStream response instead of the parsed summary.")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    try:
        result = query_vulnerability_plugin(
            args.cves,
            transform_id=args.transform_id,
            env_file=args.env_file,
        )
    except (ThreatStreamError, TransformError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print(json.dumps(result["raw"] if args.raw else result["summary"], indent=2, sort_keys=True))
    return 0


def _auth_headers(username: str | None = None, api_key: str | None = None) -> dict[str, str]:
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "User-Agent": "threatstream-vuln-plugin-query/1.0",
    }

    session_cookie = os.environ.get("THREATSTREAM_SESSION_COOKIE")
    csrf_token = os.environ.get("THREATSTREAM_CSRF_TOKEN")
    if session_cookie:
        headers["Cookie"] = session_cookie
    if csrf_token:
        headers["X-Csrftoken"] = csrf_token

    resolved_username = username or os.environ.get("THREATSTREAM_USERNAME")
    resolved_api_key = api_key or os.environ.get("THREATSTREAM_API_KEY")
    if resolved_username and resolved_api_key:
        headers["Authorization"] = f"apikey {resolved_username}:{resolved_api_key}"
    elif not session_cookie:
        raise ThreatStreamError("Missing ThreatStream API credentials or THREATSTREAM_SESSION_COOKIE in environment or .env")

    return headers


def _parse_cves(cves: str | list[str]) -> list[str]:
    if isinstance(cves, str):
        candidates = [value.strip().upper() for value in cves.split(",")]
    else:
        candidates = [value.strip().upper() for value in cves]

    parsed = [candidate for candidate in candidates if candidate]
    invalid = [candidate for candidate in parsed if not CVE_PATTERN.match(candidate)]
    if invalid:
        raise ValueError(f"Invalid CVE value(s): {', '.join(invalid)}")
    if not parsed:
        raise ValueError("At least one CVE is required")
    return parsed


def _table_rows(widget: dict[str, Any]) -> list[dict[str, Any]]:
    headings = widget.get("columnHeadings", [])
    rows = widget.get("rows", [])
    if not isinstance(headings, list) or not isinstance(rows, list):
        return []

    parsed_rows: list[dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, list):
            continue
        parsed_rows.append(
            {
                str(heading): _item_text(cell)
                for heading, cell in zip(headings, row)
            }
        )
    return parsed_rows


def _item_text(item: Any) -> Any:
    if not isinstance(item, dict):
        return item
    if item.get("itemType") == "Composite":
        values = [_item_text(child) for child in item.get("itemList", []) if isinstance(child, dict)]
        return ", ".join(str(value) for value in values if value is not None)
    return item.get("itemValue", item.get("itemLabel"))


def _parse_asset_count(text: Any) -> int | None:
    if not isinstance(text, str):
        return None
    match = re.search(r"Displaying\s*<b>\s*(\d+)\s*</b>\s*vulnerable assets", text, flags=re.IGNORECASE)
    if match:
        return int(match.group(1))
    match = re.search(r"discovered\s+(\d+)\s+vulnerable assets", text, flags=re.IGNORECASE)
    if match:
        return int(match.group(1))
    return None


if __name__ == "__main__":
    raise SystemExit(main())
