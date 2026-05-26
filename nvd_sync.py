#!/usr/bin/env python3
"""Sync recently modified NVD CVEs into ThreatStream vulnerability models."""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urljoin
from urllib.request import Request, urlopen

from kev_watcher import (
    DEFAULT_SEARCH_PATH,
    DEFAULT_TRUSTED_CIRCLE_ID,
    DEFAULT_VULNERABILITY_PATH,
    _build_url,
    _tag_objects,
    _threat_model_id,
)
from threatstream_submit import DEFAULT_BASE_URL, ThreatStreamError, load_dotenv


DEFAULT_NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
DEFAULT_LOOKBACK_MINUTES = 10
DEFAULT_RESULTS_PER_PAGE = 2000
DEFAULT_NVD_TAG_NAME = "nvd_sync"
DEFAULT_TAG_TLP = "red"


class NvdSyncError(RuntimeError):
    """Raised when the NVD sync cannot complete."""


class NvdClient:
    def __init__(self, *, base_url: str = DEFAULT_NVD_URL, api_key: str | None = None, timeout: int = 30) -> None:
        self.base_url = base_url
        self.timeout = timeout
        self.headers = {
            "Accept": "application/json",
            "User-Agent": "threatstream-nvd-sync/1.0",
        }
        if api_key:
            self.headers["apiKey"] = api_key

    def fetch_modified(self, start: datetime, end: datetime) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        start_index = 0

        while True:
            query = {
                "lastModStartDate": _nvd_datetime(start),
                "lastModEndDate": _nvd_datetime(end),
                "resultsPerPage": DEFAULT_RESULTS_PER_PAGE,
                "startIndex": start_index,
                "noRejected": "",
            }
            page = self._get(query)
            vulnerabilities = page.get("vulnerabilities", [])
            if not isinstance(vulnerabilities, list):
                raise NvdSyncError("NVD response did not include a vulnerabilities list")

            results.extend(vulnerabilities)
            total_results = int(page.get("totalResults", len(results)))
            start_index += int(page.get("resultsPerPage", len(vulnerabilities) or DEFAULT_RESULTS_PER_PAGE))
            if start_index >= total_results or not vulnerabilities:
                return results

    def _get(self, query: dict[str, Any]) -> dict[str, Any]:
        url = f"{self.base_url}?{urlencode(query)}"
        request = Request(url, headers=self.headers)
        try:
            with urlopen(request, timeout=self.timeout) as response:
                return json.loads(response.read().decode("utf-8"))
        except HTTPError as exc:
            text = exc.read().decode("utf-8", errors="replace")
            raise NvdSyncError(f"NVD returned HTTP {exc.code}: {text}") from exc
        except URLError as exc:
            raise NvdSyncError(f"Could not reach NVD: {exc.reason}") from exc
        except json.JSONDecodeError as exc:
            raise NvdSyncError("NVD returned non-JSON response") from exc


class ThreatStreamVulnerabilityClient:
    def __init__(
        self,
        *,
        username: str,
        api_key: str,
        base_url: str = DEFAULT_BASE_URL,
        search_path: str = DEFAULT_SEARCH_PATH,
        vulnerability_path: str = DEFAULT_VULNERABILITY_PATH,
        timeout: int = 30,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.search_path = search_path
        self.vulnerability_path = vulnerability_path
        self.timeout = timeout
        self.headers = {
            "Authorization": f"apikey {username}:{api_key}",
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": "threatstream-nvd-sync/1.0",
        }

    def search_vulnerability(self, cve_id: str, trusted_circle_id: str) -> list[dict[str, Any]]:
        query = {
            "model_type": "vulnerability",
            "name": cve_id,
            "trusted_circle_ids": trusted_circle_id,
            "limit": 20,
        }
        response = self._request("GET", self.search_path, query=query)
        objects = response.get("objects", response if isinstance(response, list) else [])
        if not isinstance(objects, list):
            raise ThreatStreamError("ThreatStream search response did not contain an objects list")
        return [obj for obj in objects if obj.get("name") == cve_id]

    def create_vulnerability(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self._request("POST", self.vulnerability_path, body=payload)

    def update_vulnerability(self, vulnerability: dict[str, Any], payload: dict[str, Any]) -> dict[str, Any]:
        resource_uri = vulnerability.get("resource_uri")
        if isinstance(resource_uri, str) and resource_uri:
            return self._request("PATCH", resource_uri, body=payload)

        vulnerability_id = _threat_model_id(vulnerability)
        if not vulnerability_id:
            raise ThreatStreamError("Matched vulnerability did not include id or resource_uri")
        return self._request("PATCH", urljoin(self.vulnerability_path, f"{vulnerability_id}/"), body=payload)

    def _request(
        self,
        method: str,
        path_or_url: str,
        *,
        query: dict[str, Any] | None = None,
        body: dict[str, Any] | None = None,
    ) -> Any:
        url = _build_url(self.base_url, path_or_url, query)
        data = json.dumps(body).encode("utf-8") if body is not None else None
        request = Request(url, data=data, method=method, headers=self.headers)
        try:
            with urlopen(request, timeout=self.timeout) as response:
                text = response.read().decode("utf-8")
                return json.loads(text) if text else {}
        except HTTPError as exc:
            text = exc.read().decode("utf-8", errors="replace")
            raise ThreatStreamError(f"{method} {url} returned HTTP {exc.code}: {text}") from exc
        except URLError as exc:
            raise ThreatStreamError(f"Could not reach ThreatStream: {exc.reason}") from exc
        except json.JSONDecodeError as exc:
            raise ThreatStreamError(f"{method} {url} returned non-JSON response") from exc


def process_once(args: argparse.Namespace) -> dict[str, Any]:
    load_dotenv(args.env_file)
    now = datetime.now(timezone.utc)
    end = _parse_datetime(args.end) if args.end else now
    start = _parse_datetime(args.start) if args.start else end - timedelta(minutes=args.minutes)

    nvd_client = NvdClient(
        base_url=args.nvd_url or os.environ.get("NVD_CVE_API_URL") or DEFAULT_NVD_URL,
        api_key=args.nvd_api_key or os.environ.get("NVD_API_KEY"),
    )
    nvd_vulnerabilities = nvd_client.fetch_modified(start, end)

    trusted_circle_id = args.trusted_circle_id or os.environ.get("NVD_TRUSTED_CIRCLE_ID") or DEFAULT_TRUSTED_CIRCLE_ID
    tag_tlp = args.tag_tlp or os.environ.get("NVD_TAG_TLP") or DEFAULT_TAG_TLP
    tags = _tag_objects(_resolve_tag_names(args), tag_tlp)
    planned = [_planned_item(item, trusted_circle_id, tags) for item in nvd_vulnerabilities]

    if args.dry_run:
        return {
            "window": {"start": _nvd_datetime(start), "end": _nvd_datetime(end)},
            "count": len(planned),
            "results": planned,
        }

    username = os.environ.get("THREATSTREAM_USERNAME")
    api_key = os.environ.get("THREATSTREAM_API_KEY")
    if not username or not api_key:
        raise ThreatStreamError("Missing THREATSTREAM_USERNAME or THREATSTREAM_API_KEY in environment or .env")

    threatstream = ThreatStreamVulnerabilityClient(
        username=username,
        api_key=api_key,
        base_url=os.environ.get("THREATSTREAM_BASE_URL") or DEFAULT_BASE_URL,
        search_path=os.environ.get("THREATSTREAM_THREAT_MODEL_SEARCH_PATH") or DEFAULT_SEARCH_PATH,
        vulnerability_path=os.environ.get("THREATSTREAM_VULNERABILITY_PATH") or DEFAULT_VULNERABILITY_PATH,
    )

    results: list[dict[str, Any]] = []
    for nvd_item in nvd_vulnerabilities:
        cve = nvd_item.get("cve", {})
        cve_id = cve.get("id")
        if not cve_id:
            continue

        payload = build_threatstream_payload(nvd_item, trusted_circle_id, tags)
        matches = threatstream.search_vulnerability(cve_id, trusted_circle_id)
        if matches:
            response = threatstream.update_vulnerability(matches[0], payload)
            action = "updated_existing"
        else:
            response = threatstream.create_vulnerability(payload)
            action = "created_vulnerability"
        results.append({"cveID": cve_id, "action": action, "response": response})

    return {
        "window": {"start": _nvd_datetime(start), "end": _nvd_datetime(end)},
        "count": len(results),
        "results": results,
    }


def build_threatstream_payload(
    nvd_item: dict[str, Any],
    trusted_circle_id: str,
    tags: list[dict[str, str]],
) -> dict[str, Any]:
    cve = nvd_item.get("cve", {})
    cve_id = cve.get("id")
    if not cve_id:
        raise NvdSyncError("NVD item did not include cve.id")

    return {
        "name": cve_id,
        "description": _threatstream_description(nvd_item),
        "tags": tags,
        "trusted_circle_ids": [int(trusted_circle_id)],
    }


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Sync NVD CVEs modified in a recent time window into ThreatStream vulnerabilities."
    )
    parser.add_argument("--env-file", default=None, help="Path to .env file. Defaults to .env next to scripts.")
    parser.add_argument("--nvd-url", default=None, help=f"NVD CVE API URL. Default: {DEFAULT_NVD_URL}")
    parser.add_argument("--nvd-api-key", default=None, help="NVD API key. Defaults to NVD_API_KEY from .env.")
    parser.add_argument("--minutes", type=int, default=DEFAULT_LOOKBACK_MINUTES, help="Look back this many minutes. Default: 10.")
    parser.add_argument("--start", default=None, help="UTC start datetime, for example 2026-05-26T12:00:00Z.")
    parser.add_argument("--end", default=None, help="UTC end datetime, for example 2026-05-26T12:10:00Z.")
    parser.add_argument("--trusted-circle-id", default=None, help=f"Trusted circle ID. Default: {DEFAULT_TRUSTED_CIRCLE_ID}")
    parser.add_argument(
        "--tag-name",
        default=None,
        help=f"Comma-separated tag name(s) to add. Default: {DEFAULT_NVD_TAG_NAME}",
    )
    parser.add_argument("--tag-tlp", default=None, help=f"Tag TLP. Default: {DEFAULT_TAG_TLP}")
    parser.add_argument("--dry-run", action="store_true", help="Show planned creates/updates without changing ThreatStream.")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    try:
        result = process_once(args)
    except (NvdSyncError, ThreatStreamError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


def _planned_item(nvd_item: dict[str, Any], trusted_circle_id: str, tags: list[dict[str, str]]) -> dict[str, Any]:
    cve = nvd_item.get("cve", {})
    cve_id = cve.get("id")
    metrics = _best_cvss_metrics(cve)
    return {
        "cveID": cve_id,
        "lastModified": cve.get("lastModified"),
        "published": cve.get("published"),
        "search": {
            "model_type": "vulnerability",
            "name": cve_id,
            "trusted_circle_ids": trusted_circle_id,
        },
        "cvss": metrics,
        "tags": tags,
    }


def _resolve_tag_names(args: argparse.Namespace) -> list[str]:
    tag_value = (
        args.tag_name
        or os.environ.get("NVD_TAG_OVERRIDE")
        or os.environ.get("nvd_tag_override")
        or os.environ.get("NVD_TAG_NAME")
        or DEFAULT_NVD_TAG_NAME
    )
    tag_names = [tag.strip() for tag in tag_value.split(",") if tag.strip()]
    if not tag_names:
        raise ValueError("At least one NVD tag must be configured")
    return tag_names


def _threatstream_description(nvd_item: dict[str, Any]) -> str:
    cve = nvd_item.get("cve", {})
    cve_id = cve.get("id", "unknown")
    descriptions = cve.get("descriptions", [])
    description = _english_value(descriptions) or ""
    metrics = _all_cvss_metrics(cve)
    weaknesses = _weaknesses(cve)
    references = _references(cve)

    lines = [
        "NVD synchronized vulnerability record.",
        f"CVE: {cve_id}",
        f"Published: {cve.get('published', '')}",
        f"Last Modified: {cve.get('lastModified', '')}",
        f"Status: {cve.get('vulnStatus', '')}",
        "",
        "Description:",
        description,
    ]

    if metrics:
        lines.extend(["", "CVSS:"])
        for metric in metrics:
            lines.append(
                "- {version}: score={score}, severity={severity}, vector={vector}, source={source}".format(
                    version=metric.get("version", ""),
                    score=metric.get("baseScore", ""),
                    severity=metric.get("baseSeverity", ""),
                    vector=metric.get("vectorString", ""),
                    source=metric.get("source", ""),
                )
            )

    if weaknesses:
        lines.extend(["", f"CWE: {', '.join(weaknesses)}"])

    if references:
        lines.extend(["", "References:"])
        lines.extend(f"- {reference}" for reference in references[:25])

    return "\n".join(str(line) for line in lines if line is not None).strip()


def _all_cvss_metrics(cve: dict[str, Any]) -> list[dict[str, Any]]:
    metrics = cve.get("metrics", {})
    selected: list[dict[str, Any]] = []
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        for metric in metrics.get(key, []) if isinstance(metrics.get(key), list) else []:
            cvss_data = metric.get("cvssData", {})
            selected.append(
                {
                    "version": cvss_data.get("version") or key,
                    "baseScore": cvss_data.get("baseScore"),
                    "baseSeverity": cvss_data.get("baseSeverity") or metric.get("baseSeverity"),
                    "vectorString": cvss_data.get("vectorString"),
                    "source": metric.get("source"),
                }
            )
    return selected


def _best_cvss_metrics(cve: dict[str, Any]) -> dict[str, Any] | None:
    metrics = _all_cvss_metrics(cve)
    return metrics[0] if metrics else None


def _weaknesses(cve: dict[str, Any]) -> list[str]:
    values: list[str] = []
    for weakness in cve.get("weaknesses", []) if isinstance(cve.get("weaknesses"), list) else []:
        for description in weakness.get("description", []):
            value = description.get("value")
            if value and value not in values:
                values.append(value)
    return values


def _references(cve: dict[str, Any]) -> list[str]:
    refs: list[str] = []
    for reference in cve.get("references", {}).get("referenceData", []):
        url = reference.get("url")
        if url and url not in refs:
            refs.append(url)
    return refs


def _english_value(items: list[dict[str, Any]]) -> str | None:
    for item in items:
        if item.get("lang") == "en" and item.get("value"):
            return str(item["value"])
    for item in items:
        if item.get("value"):
            return str(item["value"])
    return None


def _parse_datetime(value: str) -> datetime:
    normalized = value.replace("Z", "+00:00")
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _nvd_datetime(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


if __name__ == "__main__":
    raise SystemExit(main())
