#!/usr/bin/env python3
"""Watch CISA KEV for new CVEs and tag matching ThreatStream vulnerabilities."""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urljoin, urlparse
from urllib.request import Request, urlopen

from threatstream_submit import DEFAULT_BASE_URL, ThreatStreamError, load_dotenv


DEFAULT_KEV_URL = (
    "https://raw.githubusercontent.com/cisagov/kev-data/develop/"
    "known_exploited_vulnerabilities.json"
)
DEFAULT_INTERVAL_SECONDS = 600
DEFAULT_STATE_FILE = "kev_watcher_state.json"
DEFAULT_TRUSTED_CIRCLE_ID = "310"
DEFAULT_TAG_NAME = "cisa_kev"
DEFAULT_TAG_TLP = "red"
DEFAULT_SEARCH_PATH = "/api/v1/threat_model_search/"
DEFAULT_VULNERABILITY_PATH = "/api/v1/vulnerability/"
DEFAULT_VULNERABILITY_TAG_PATH_TEMPLATE = "/api/v1/vulnerability/{id}/tag/"


class KevWatcherError(RuntimeError):
    """Raised when KEV watcher work cannot be completed."""


def fetch_json(url: str, *, timeout: int = 30) -> dict[str, Any]:
    request = Request(_normalize_github_url(url), headers={"Accept": "application/json"})
    try:
        with urlopen(request, timeout=timeout) as response:
            return json.loads(response.read().decode("utf-8"))
    except HTTPError as exc:
        raise KevWatcherError(f"GET {url} returned HTTP {exc.code}") from exc
    except URLError as exc:
        raise KevWatcherError(f"Could not fetch {url}: {exc.reason}") from exc
    except json.JSONDecodeError as exc:
        raise KevWatcherError(f"Response from {url} was not valid JSON") from exc


def load_state(path: str | Path) -> dict[str, Any]:
    state_path = Path(path)
    if not state_path.exists():
        return {"seen_cves": [], "processed_cves": {}, "last_checked": None}
    try:
        state = json.loads(state_path.read_text())
    except json.JSONDecodeError as exc:
        raise KevWatcherError(f"State file {state_path} is not valid JSON") from exc

    state.setdefault("seen_cves", [])
    state.setdefault("processed_cves", {})
    state.setdefault("last_checked", None)
    return state


def save_state(path: str | Path, state: dict[str, Any]) -> None:
    state_path = Path(path)
    state_path.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n")


def get_new_vulnerabilities(
    kev_catalog: dict[str, Any],
    state: dict[str, Any],
    *,
    process_existing: bool = False,
    days_back: int | None = None,
) -> list[dict[str, Any]]:
    vulnerabilities = kev_catalog.get("vulnerabilities")
    if not isinstance(vulnerabilities, list):
        raise KevWatcherError("KEV catalog did not include a vulnerabilities list")

    if days_back is not None:
        return _vulnerabilities_added_since(vulnerabilities, days_back)

    seen = set(state.get("seen_cves", []))
    if not seen and not process_existing:
        state["seen_cves"] = sorted(_cve_ids(vulnerabilities))
        return []

    return [vuln for vuln in vulnerabilities if vuln.get("cveID") not in seen]


class ThreatStreamClient:
    def __init__(
        self,
        *,
        username: str,
        api_key: str,
        base_url: str = DEFAULT_BASE_URL,
        search_path: str = DEFAULT_SEARCH_PATH,
        vulnerability_path: str = DEFAULT_VULNERABILITY_PATH,
        vulnerability_tag_path_template: str = DEFAULT_VULNERABILITY_TAG_PATH_TEMPLATE,
        timeout: int = 30,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.search_path = search_path
        self.vulnerability_path = vulnerability_path
        self.vulnerability_tag_path_template = vulnerability_tag_path_template
        self.timeout = timeout
        self.headers = {
            "Authorization": f"apikey {username}:{api_key}",
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": "kev-watcher/1.0",
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

    def add_tag_to_vulnerability(self, vulnerability: dict[str, Any], tag_name: str, tag_tlp: str) -> dict[str, Any]:
        vulnerability_id = _threat_model_id(vulnerability)
        if not vulnerability_id:
            raise ThreatStreamError("Matched vulnerability did not include id or resource_uri")

        path = self.vulnerability_tag_path_template.format(id=vulnerability_id)
        return self._request("POST", path, body={"tags": [{"name": tag_name, "tlp": tag_tlp}]})

    def create_placeholder_vulnerability(
        self,
        kev_vulnerability: dict[str, Any],
        trusted_circle_id: str,
        tag_name: str,
        tag_tlp: str,
    ) -> dict[str, Any]:
        cve_id = kev_vulnerability["cveID"]
        payload = {
            "name": cve_id,
            "description": _placeholder_description(kev_vulnerability),
            "tags": [{"name": tag_name, "tlp": tag_tlp}],
            "trusted_circle_ids": [int(trusted_circle_id)],
        }
        return self._request("POST", self.vulnerability_path, body=payload)

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
    state_file = args.state_file or os.environ.get("KEV_WATCHER_STATE_FILE") or DEFAULT_STATE_FILE
    state = load_state(state_file)
    catalog = fetch_json(args.kev_url or os.environ.get("KEV_URL") or DEFAULT_KEV_URL)
    new_vulnerabilities = get_new_vulnerabilities(
        catalog,
        state,
        process_existing=args.process_existing,
        days_back=args.days_back,
    )

    trusted_circle_id = args.trusted_circle_id or os.environ.get("KEV_TRUSTED_CIRCLE_ID") or DEFAULT_TRUSTED_CIRCLE_ID
    tag_name = args.tag_name or os.environ.get("KEV_TAG_NAME") or DEFAULT_TAG_NAME
    tag_tlp = args.tag_tlp or os.environ.get("KEV_TAG_TLP") or DEFAULT_TAG_TLP

    if args.dry_run:
        results = [
            {
                "cveID": vulnerability.get("cveID"),
                "action": "dry-run",
                "search": {
                    "model_type": "vulnerability",
                    "name": vulnerability.get("cveID"),
                    "trusted_circle_ids": trusted_circle_id,
                },
                "tag": {"name": tag_name, "tlp": tag_tlp},
            }
            for vulnerability in new_vulnerabilities
            if vulnerability.get("cveID")
        ]
        return {
            "catalogVersion": catalog.get("catalogVersion"),
            "dateReleased": catalog.get("dateReleased"),
            "selection": _selection_summary(args),
            "new_count": len(new_vulnerabilities),
            "results": results,
            "state_file": state_file,
        }

    username = os.environ.get("THREATSTREAM_USERNAME")
    api_key = os.environ.get("THREATSTREAM_API_KEY")
    if not username or not api_key:
        raise ThreatStreamError("Missing THREATSTREAM_USERNAME or THREATSTREAM_API_KEY in environment or .env")

    client = ThreatStreamClient(
        username=username,
        api_key=api_key,
        base_url=os.environ.get("THREATSTREAM_BASE_URL") or DEFAULT_BASE_URL,
        search_path=os.environ.get("THREATSTREAM_THREAT_MODEL_SEARCH_PATH") or DEFAULT_SEARCH_PATH,
        vulnerability_path=os.environ.get("THREATSTREAM_VULNERABILITY_PATH") or DEFAULT_VULNERABILITY_PATH,
        vulnerability_tag_path_template=(
            os.environ.get("THREATSTREAM_VULNERABILITY_TAG_PATH_TEMPLATE")
            or DEFAULT_VULNERABILITY_TAG_PATH_TEMPLATE
        ),
    )

    results: list[dict[str, Any]] = []
    for vulnerability in new_vulnerabilities:
        cve_id = vulnerability.get("cveID")
        if not cve_id:
            continue

        matches = client.search_vulnerability(cve_id, trusted_circle_id)
        if matches:
            updated = client.add_tag_to_vulnerability(matches[0], tag_name, tag_tlp)
            action = "tagged_existing"
        else:
            updated = client.create_placeholder_vulnerability(vulnerability, trusted_circle_id, tag_name, tag_tlp)
            action = "created_placeholder"

        state["processed_cves"][cve_id] = {
            "action": action,
            "processed_at": _utc_now(),
        }
        results.append({"cveID": cve_id, "action": action, "response": updated})

    seen = set(state.get("seen_cves", []))
    seen.update(_cve_ids(catalog.get("vulnerabilities", [])))
    state["seen_cves"] = sorted(seen)
    state["last_checked"] = _utc_now()

    if not args.dry_run:
        save_state(state_file, state)

    return {
        "catalogVersion": catalog.get("catalogVersion"),
        "dateReleased": catalog.get("dateReleased"),
        "selection": _selection_summary(args),
        "new_count": len(new_vulnerabilities),
        "results": results,
        "state_file": state_file,
    }


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Check CISA KEV for new CVEs and tag/create ThreatStream vulnerability models."
    )
    parser.add_argument("--env-file", default=None, help="Path to .env file. Defaults to .env next to scripts.")
    parser.add_argument("--kev-url", default=None, help="CISA KEV JSON URL. GitHub blob URLs are converted to raw.")
    parser.add_argument("--state-file", default=None, help=f"State file path. Default: {DEFAULT_STATE_FILE}")
    parser.add_argument("--trusted-circle-id", default=None, help=f"Trusted circle ID. Default: {DEFAULT_TRUSTED_CIRCLE_ID}")
    parser.add_argument("--tag-name", default=None, help=f"Tag to add. Default: {DEFAULT_TAG_NAME}")
    parser.add_argument("--tag-tlp", default=None, help=f"Tag TLP. Default: {DEFAULT_TAG_TLP}")
    parser.add_argument("--interval", type=int, default=None, help="Loop interval in seconds. Default: 600.")
    parser.add_argument(
        "--once",
        "--run-once",
        action="store_true",
        dest="once",
        help="Run one check and exit. Useful when scheduling with cron.",
    )
    parser.add_argument(
        "--day",
        "--days",
        type=int,
        dest="days_back",
        default=None,
        help="Process KEVs added within the last N days, bypassing saved-state filtering.",
    )
    parser.add_argument(
        "--process-existing",
        action="store_true",
        help="Process the full current KEV catalog instead of using the first run as a baseline.",
    )
    parser.add_argument("--dry-run", action="store_true", help="Show what would be processed without changing state or ThreatStream.")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    interval = args.interval or int(os.environ.get("KEV_WATCH_INTERVAL_SECONDS", DEFAULT_INTERVAL_SECONDS))

    while True:
        try:
            result = process_once(args)
            print(json.dumps(result, indent=2, sort_keys=True))
        except (KevWatcherError, ThreatStreamError, ValueError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            if args.once:
                return 1

        if args.once:
            return 0
        time.sleep(interval)


def _normalize_github_url(url: str) -> str:
    parsed = urlparse(url)
    if parsed.netloc == "github.com" and "/blob/" in parsed.path:
        owner_repo, branch_file = parsed.path.lstrip("/").split("/blob/", 1)
        return f"https://raw.githubusercontent.com/{owner_repo}/{branch_file}"
    return url


def _build_url(base_url: str, path_or_url: str, query: dict[str, Any] | None = None) -> str:
    if path_or_url.startswith("http://") or path_or_url.startswith("https://"):
        url = path_or_url
    else:
        url = urljoin(f"{base_url}/", path_or_url.lstrip("/"))
    if query:
        url = f"{url}?{urlencode(query)}"
    return url


def _threat_model_id(threat_model: dict[str, Any]) -> str | None:
    if threat_model.get("id") is not None:
        return str(threat_model["id"])

    resource_uri = threat_model.get("resource_uri")
    if not isinstance(resource_uri, str):
        return None

    parts = [part for part in resource_uri.strip("/").split("/") if part]
    return parts[-1] if parts else None


def _vulnerabilities_added_since(vulnerabilities: list[Any], days_back: int) -> list[dict[str, Any]]:
    if days_back < 0:
        raise ValueError("--day/--days must be 0 or greater")

    cutoff = (datetime.now(timezone.utc).date() - timedelta(days=days_back)).isoformat()
    selected: list[dict[str, Any]] = []
    for vulnerability in vulnerabilities:
        if not isinstance(vulnerability, dict):
            continue
        date_added = vulnerability.get("dateAdded")
        if isinstance(date_added, str) and date_added >= cutoff:
            selected.append(vulnerability)
    return selected


def _selection_summary(args: argparse.Namespace) -> dict[str, Any]:
    if args.days_back is not None:
        return {"mode": "days_back", "days": args.days_back}
    if args.process_existing:
        return {"mode": "process_existing"}
    return {"mode": "new_since_state"}


def _placeholder_description(vulnerability: dict[str, Any]) -> str:
    parts = [
        "Placeholder created from CISA Known Exploited Vulnerabilities catalog.",
        f"CVE: {vulnerability.get('cveID', '')}",
        f"Vendor/Project: {vulnerability.get('vendorProject', '')}",
        f"Product: {vulnerability.get('product', '')}",
        f"Name: {vulnerability.get('vulnerabilityName', '')}",
        f"Date Added: {vulnerability.get('dateAdded', '')}",
        f"Due Date: {vulnerability.get('dueDate', '')}",
        f"Required Action: {vulnerability.get('requiredAction', '')}",
        f"Description: {vulnerability.get('shortDescription', '')}",
    ]
    return "\n".join(part for part in parts if not part.endswith(": "))


def _cve_ids(vulnerabilities: list[Any]) -> set[str]:
    return {vuln["cveID"] for vuln in vulnerabilities if isinstance(vuln, dict) and vuln.get("cveID")}


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


if __name__ == "__main__":
    raise SystemExit(main())
