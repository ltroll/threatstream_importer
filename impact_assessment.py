#!/usr/bin/env python3
"""Assess organization impact for tagged ThreatStream vulnerability models."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from kev_watcher import (
    DEFAULT_SEARCH_PATH,
    DEFAULT_TAG_TLP,
    DEFAULT_VULNERABILITY_PATH,
    DEFAULT_VULNERABILITY_TAG_PATH_TEMPLATE,
    _build_url,
    _tag_objects,
    _threat_model_id,
)
from threatstream_submit import DEFAULT_BASE_URL, ThreatStreamError, load_dotenv
from vuln_plugin_query import CVE_PATTERN, TransformError, query_vulnerability_plugin


DEFAULT_MARKER_TAG = "sample_impacted"
DEFAULT_IMPACTED_TAG_PREFIX = "impacted"
DEFAULT_IMPACTED_DOMAIN_TAG_PREFIX = "impacted_domain"
DEFAULT_TAG_SEPARATOR = ":"
DEFAULT_TAG_SEARCH_MODE = "exact"
DEFAULT_SEARCH_ENDPOINT = "vulnerability"
DEFAULT_PAGE_SIZE = 100
DEFAULT_MAX_PAGES = 20


class ImpactAssessmentError(RuntimeError):
    """Raised when impact assessment cannot complete."""


class ThreatModelClient:
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
            "User-Agent": "threatstream-impact-assessment/1.0",
        }

    def search_vulnerabilities_by_tag(
        self,
        marker_tag: str,
        *,
        organization_id: str | None = None,
        limit: int = 0,
        page_size: int = DEFAULT_PAGE_SIZE,
        max_pages: int = DEFAULT_MAX_PAGES,
        tag_search_mode: str = DEFAULT_TAG_SEARCH_MODE,
        search_endpoint: str = DEFAULT_SEARCH_ENDPOINT,
    ) -> list[dict[str, Any]]:
        if search_endpoint == "vulnerability":
            return self._search_vulnerability_endpoint(
                marker_tag,
                organization_id=organization_id,
                limit=limit,
                page_size=page_size,
                max_pages=max_pages,
                tag_search_mode=tag_search_mode,
            )
        if search_endpoint != "threat_model_search":
            raise ValueError("--search-endpoint must be vulnerability or threat_model_search")

        query: dict[str, Any] = {
            "model_type": "vulnerability",
            "limit": limit,
        }
        if tag_search_mode == "exact":
            query["tags.name"] = marker_tag
        elif tag_search_mode == "contains":
            query["value"] = marker_tag
        else:
            raise ValueError("--tag-search-mode must be exact or contains")

        if organization_id:
            query["organization_id"] = organization_id

        response = self._request("GET", self.search_path, query=query)
        objects = response.get("objects", response if isinstance(response, list) else [])
        if not isinstance(objects, list):
            raise ThreatStreamError("ThreatStream search response did not contain an objects list")

        return [
            threat_model
            for threat_model in objects
            if CVE_PATTERN.match(str(threat_model.get("name", "")))
            and _tag_matches(threat_model, marker_tag, tag_search_mode)
        ]

    def _search_vulnerability_endpoint(
        self,
        marker_tag: str,
        *,
        organization_id: str | None,
        limit: int,
        page_size: int,
        max_pages: int,
        tag_search_mode: str,
    ) -> list[dict[str, Any]]:
        page_limit = limit if limit and limit > 0 else page_size
        offset = 0
        pages_read = 0
        matches: list[dict[str, Any]] = []

        while pages_read < max_pages:
            query: dict[str, Any] = {"limit": page_limit, "offset": offset}
            if organization_id:
                query["organization_id"] = organization_id

            response = self._request("GET", self.vulnerability_path, query=query)
            objects = response.get("objects", response if isinstance(response, list) else [])
            if not isinstance(objects, list):
                raise ThreatStreamError("ThreatStream vulnerability response did not contain an objects list")

            matches.extend(
                threat_model
                for threat_model in objects
                if CVE_PATTERN.match(str(threat_model.get("name", "")))
                and _tag_matches(threat_model, marker_tag, tag_search_mode)
            )
            pages_read += 1

            if limit and limit > 0:
                break
            if len(objects) < page_limit:
                break
            offset += page_limit

        return matches

    def add_tags_to_vulnerability(self, vulnerability: dict[str, Any], tags: list[dict[str, str]]) -> dict[str, Any]:
        vulnerability_id = _threat_model_id(vulnerability)
        if not vulnerability_id:
            raise ThreatStreamError("Vulnerability did not include id or resource_uri for tagging")

        path = self.vulnerability_tag_path_template.format(id=vulnerability_id)
        return self._request("POST", path, body={"tags": tags})

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


def assess_impacted_models(args: argparse.Namespace) -> dict[str, Any]:
    load_dotenv(args.env_file)
    marker_tag = args.marker_tag or os.environ.get("IMPACT_MARKER_TAG") or DEFAULT_MARKER_TAG
    tag_search_mode = args.tag_search_mode or os.environ.get("IMPACT_TAG_SEARCH_MODE") or DEFAULT_TAG_SEARCH_MODE
    search_endpoint = args.search_endpoint or os.environ.get("IMPACT_SEARCH_ENDPOINT") or DEFAULT_SEARCH_ENDPOINT
    organization_id = args.organization_id or os.environ.get("IMPACT_ORGANIZATION_ID") or os.environ.get("NVD_ORGANIZATION_ID")
    page_size = args.page_size or int(os.environ.get("IMPACT_PAGE_SIZE", DEFAULT_PAGE_SIZE))
    max_pages = args.max_pages or int(os.environ.get("IMPACT_MAX_PAGES", DEFAULT_MAX_PAGES))
    query_plan = build_query_plan(
        marker_tag=marker_tag,
        organization_id=organization_id,
        limit=args.limit,
        page_size=page_size,
        max_pages=max_pages,
        tag_search_mode=tag_search_mode,
        search_endpoint=search_endpoint,
    )

    if args.show_query:
        return query_plan

    username = os.environ.get("THREATSTREAM_USERNAME")
    api_key = os.environ.get("THREATSTREAM_API_KEY")
    if not username or not api_key:
        raise ThreatStreamError("Missing THREATSTREAM_USERNAME or THREATSTREAM_API_KEY in environment or .env")

    client = ThreatModelClient(
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
    threat_models = client.search_vulnerabilities_by_tag(
        marker_tag,
        organization_id=organization_id,
        limit=args.limit,
        page_size=page_size,
        max_pages=max_pages,
        tag_search_mode=tag_search_mode,
        search_endpoint=search_endpoint,
    )

    results: list[dict[str, Any]] = []
    for threat_model in threat_models:
        cve_id = str(threat_model.get("name", "")).upper()
        plugin_result = query_vulnerability_plugin(cve_id, env_file=args.env_file)
        impact = summarize_impact(plugin_result["summary"])
        result_tags = build_result_tags(impact, args)
        tag_response = None
        if args.apply_tags:
            tag_response = client.add_tags_to_vulnerability(threat_model, result_tags)

        results.append(
            {
                "cveID": cve_id,
                "threat_model_id": _threat_model_id(threat_model),
                "impacted": impact["impacted"],
                "impacted_domain": ",".join(impact["domains"]),
                "impacted_assets": impact["assets"],
                "tags": result_tags,
                "tag_response": tag_response,
            }
        )

    return {
        "marker_tag": marker_tag,
        "tag_search_mode": tag_search_mode,
        "search_endpoint": search_endpoint,
        "organization_id": organization_id,
        "page_size": page_size,
        "max_pages": max_pages,
        "apply_tags": args.apply_tags,
        "count": len(results),
        "results": results,
    }


def summarize_impact(plugin_summary: dict[str, Any]) -> dict[str, Any]:
    assets: list[dict[str, Any]] = []
    impacted_count = 0
    for transform in plugin_summary.get("transforms", []):
        if not isinstance(transform, dict):
            continue
        transform_assets = transform.get("vulnerable_assets", [])
        if isinstance(transform_assets, list):
            assets.extend(asset for asset in transform_assets if isinstance(asset, dict))
        if isinstance(transform.get("asset_count"), int):
            impacted_count = max(impacted_count, transform["asset_count"])

    if impacted_count == 0 and assets:
        impacted_count = len(assets)

    domains = sorted(
        {
            domain
            for asset in assets
            for domain in [_domain_from_dns(str(asset.get("DNS Name", "") or ""))]
            if domain
        }
    )
    return {"impacted": impacted_count, "domains": domains, "assets": assets}


def build_result_tags(impact: dict[str, Any], args: argparse.Namespace) -> list[dict[str, str]]:
    impacted_prefix = (
        args.impacted_prefix
        or os.environ.get("IMPACTED_TAG_PREFIX")
        or DEFAULT_IMPACTED_TAG_PREFIX
    )
    domain_prefix = (
        args.impacted_domain_prefix
        or os.environ.get("IMPACTED_DOMAIN_TAG_PREFIX")
        or DEFAULT_IMPACTED_DOMAIN_TAG_PREFIX
    )
    separator = args.tag_separator or os.environ.get("IMPACT_TAG_SEPARATOR") or DEFAULT_TAG_SEPARATOR
    tag_tlp = args.tag_tlp or os.environ.get("IMPACT_TAG_TLP") or DEFAULT_TAG_TLP

    tag_names = [f"{impacted_prefix}{separator}{impact['impacted']}"]
    tag_names.extend(f"{domain_prefix}{separator}{domain}" for domain in impact["domains"])
    return _tag_objects(tag_names, tag_tlp)


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Query tagged vulnerability threat models and assess vulnerable asset impact."
    )
    parser.add_argument("--env-file", default=None, help="Path to .env file. Defaults to .env next to scripts.")
    parser.add_argument("--marker-tag", default=None, help=f"Tag substring used to select models. Default: {DEFAULT_MARKER_TAG}")
    parser.add_argument(
        "--tag-search-mode",
        choices=["exact", "contains"],
        default=None,
        help="Use exact tags.name filtering or keyword contains fallback. Default: exact.",
    )
    parser.add_argument(
        "--search-endpoint",
        choices=["vulnerability", "threat_model_search"],
        default=None,
        help="Endpoint used to discover candidate CVE models. Default: vulnerability.",
    )
    parser.add_argument("--organization-id", default=None, help="Optional org ID filter for ThreatStream threat model search.")
    parser.add_argument("--limit", type=int, default=0, help="ThreatStream single-page limit. If set, disables pagination.")
    parser.add_argument("--page-size", type=int, default=None, help=f"Vulnerability endpoint page size. Default: {DEFAULT_PAGE_SIZE}.")
    parser.add_argument("--max-pages", type=int, default=None, help=f"Maximum vulnerability endpoint pages to scan. Default: {DEFAULT_MAX_PAGES}.")
    parser.add_argument("--show-query", action="store_true", help="Print the planned ThreatStream query and exit.")
    parser.add_argument("--apply-tags", action="store_true", help="Apply impact result tags back to each threat model.")
    parser.add_argument("--impacted-prefix", default=None, help=f"Impacted count tag prefix. Default: {DEFAULT_IMPACTED_TAG_PREFIX}")
    parser.add_argument(
        "--impacted-domain-prefix",
        default=None,
        help=f"Impacted domain tag prefix. Default: {DEFAULT_IMPACTED_DOMAIN_TAG_PREFIX}",
    )
    parser.add_argument("--tag-separator", default=None, help=f"Tag prefix/value separator. Default: {DEFAULT_TAG_SEPARATOR}")
    parser.add_argument("--tag-tlp", default=None, help=f"Tag TLP for applied tags. Default: {DEFAULT_TAG_TLP}")
    return parser.parse_args(argv)


def build_query_plan(
    *,
    marker_tag: str,
    organization_id: str | None,
    limit: int,
    page_size: int,
    max_pages: int,
    tag_search_mode: str,
    search_endpoint: str,
) -> dict[str, Any]:
    if search_endpoint == "vulnerability":
        page_limit = limit if limit and limit > 0 else page_size
        first_query: dict[str, Any] = {"limit": page_limit, "offset": 0}
        if organization_id:
            first_query["organization_id"] = organization_id
        return {
            "search_endpoint": search_endpoint,
            "method": "GET",
            "path": os.environ.get("THREATSTREAM_VULNERABILITY_PATH") or DEFAULT_VULNERABILITY_PATH,
            "first_query": first_query,
            "pagination": {
                "enabled": not bool(limit and limit > 0),
                "page_size": page_size,
                "max_pages": max_pages,
            },
            "local_filter": {
                "model_name_pattern": CVE_PATTERN.pattern,
                "tag_search_mode": tag_search_mode,
                "marker_tag": marker_tag,
            },
        }

    query: dict[str, Any] = {"model_type": "vulnerability", "limit": limit}
    if tag_search_mode == "exact":
        query["tags.name"] = marker_tag
    elif tag_search_mode == "contains":
        query["value"] = marker_tag
    else:
        raise ValueError("--tag-search-mode must be exact or contains")
    if organization_id:
        query["organization_id"] = organization_id

    return {
        "search_endpoint": search_endpoint,
        "method": "GET",
        "path": os.environ.get("THREATSTREAM_THREAT_MODEL_SEARCH_PATH") or DEFAULT_SEARCH_PATH,
        "query": query,
        "local_filter": {
            "model_name_pattern": CVE_PATTERN.pattern,
            "tag_search_mode": tag_search_mode,
            "marker_tag": marker_tag,
        },
    }


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    try:
        result = assess_impacted_models(args)
    except (ThreatStreamError, TransformError, ImpactAssessmentError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


def _tag_matches(threat_model: dict[str, Any], marker_tag: str, mode: str) -> bool:
    marker = marker_tag.lower()
    tag_names = [tag.lower() for tag in _tag_names(threat_model)]
    if mode == "exact":
        return marker in tag_names
    return any(marker in tag for tag in tag_names)


def _tag_names(threat_model: dict[str, Any]) -> list[str]:
    names: list[str] = []
    tags = threat_model.get("tags", [])
    if isinstance(tags, list):
        for tag in tags:
            if isinstance(tag, dict) and tag.get("name"):
                names.append(str(tag["name"]))
            elif isinstance(tag, str):
                names.append(tag)
    elif isinstance(tags, str):
        names.extend(tag.strip() for tag in tags.split(",") if tag.strip())

    for key, value in threat_model.items():
        if key.startswith("tags.") and key.endswith(".name") and value:
            names.append(str(value))
    return names


def _domain_from_dns(dns_name: str) -> str | None:
    dns_name = dns_name.strip().strip(".").lower()
    if not dns_name or "." not in dns_name:
        return None

    labels = [label for label in dns_name.split(".") if label]
    if len(labels) < 2:
        return None
    return ".".join(labels[-2:])


if __name__ == "__main__":
    raise SystemExit(main())
