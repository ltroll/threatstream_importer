#!/usr/bin/env python3
"""Search ThreatStream threat models by tag."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from kev_watcher import DEFAULT_SEARCH_PATH, DEFAULT_TAG_TLP, DEFAULT_VULNERABILITY_TAG_PATH_TEMPLATE, _build_url, _tag_objects, _threat_model_id
from threatstream_submit import DEFAULT_BASE_URL, ThreatStreamError, load_dotenv
from vuln_plugin_query import CVE_PATTERN, TransformError, query_vulnerability_plugin


CVE_IN_TEXT_PATTERN = re.compile(r"CVE-\d{4}-\d{4,19}", re.IGNORECASE)
DEFAULT_EXPOSED_TAG_PREFIX = "exposed-devices"


class ThreatModelSearchError(RuntimeError):
    """Raised when ThreatStream threat model search fails."""


def search_threat_models_by_tag(
    tag: str,
    *,
    model_type: str | None = None,
    modified_minutes: int | None = None,
    username: str | None = None,
    api_key: str | None = None,
    base_url: str | None = None,
    search_path: str | None = None,
    limit: int = 100,
    env_file: str | None = None,
) -> dict[str, Any]:
    """Search ThreatStream threat models whose tag name matches tag."""

    load_dotenv(env_file)
    resolved_username = username or os.environ.get("THREATSTREAM_USERNAME")
    resolved_api_key = api_key or os.environ.get("THREATSTREAM_API_KEY")
    if not resolved_username or not resolved_api_key:
        raise ThreatStreamError("Missing THREATSTREAM_USERNAME or THREATSTREAM_API_KEY in environment or .env")

    resolved_base_url = (base_url or os.environ.get("THREATSTREAM_BASE_URL") or DEFAULT_BASE_URL).rstrip("/")
    resolved_search_path = search_path or os.environ.get("THREATSTREAM_THREAT_MODEL_SEARCH_PATH") or DEFAULT_SEARCH_PATH
    query = {
        "tags.name": tag,
        "limit": limit,
    }
    if model_type:
        query["model_type"] = model_type
    if modified_minutes is not None:
        query["modified_ts__gte"] = _threatstream_datetime(datetime.now(timezone.utc) - timedelta(minutes=modified_minutes))
    url = _build_url(resolved_base_url, resolved_search_path, query)
    request = Request(
        url,
        headers={
            "Accept": "application/json",
            "Authorization": f"apikey {resolved_username}:{resolved_api_key}",
            "User-Agent": "threatstream-tag-search/1.0",
        },
    )

    try:
        with urlopen(request, timeout=30) as response:
            body = json.loads(response.read().decode("utf-8"))
    except HTTPError as exc:
        text = exc.read().decode("utf-8", errors="replace")
        raise ThreatModelSearchError(f"ThreatStream returned HTTP {exc.code}: {text}") from exc
    except URLError as exc:
        raise ThreatModelSearchError(f"Could not reach ThreatStream: {exc.reason}") from exc
    except json.JSONDecodeError as exc:
        raise ThreatModelSearchError("ThreatStream returned non-JSON response") from exc

    objects = body.get("objects", body if isinstance(body, list) else [])
    if not isinstance(objects, list):
        raise ThreatModelSearchError("ThreatStream response did not contain a threat model list")

    return {
        "query": query,
        "url": url,
        "count": len(objects),
        "objects": objects,
        "raw": body,
    }


def search_threat_models_by_tags(
    tags: str | list[str],
    *,
    model_type: str | None = None,
    modified_minutes: int | None = None,
    limit: int = 100,
    env_file: str | None = None,
) -> dict[str, Any]:
    """Search once per tag and merge duplicate threat models."""

    tag_names = _parse_tag_names(tags) if isinstance(tags, str) else tags
    merged: dict[str, dict[str, Any]] = {}
    searches: list[dict[str, Any]] = []

    for tag in tag_names:
        result = search_threat_models_by_tag(
            tag,
            model_type=model_type,
            modified_minutes=modified_minutes,
            limit=limit,
            env_file=env_file,
        )
        searches.append({"tag": tag, "query": result["query"], "url": result["url"], "count": result["count"]})
        for threat_model in result["objects"]:
            key = _threat_model_key(threat_model)
            if key not in merged:
                copied = dict(threat_model)
                copied["matched_search_tags"] = [tag]
                merged[key] = copied
            elif tag not in merged[key]["matched_search_tags"]:
                merged[key]["matched_search_tags"].append(tag)

    objects = list(merged.values())
    return {
        "searches": searches,
        "count": len(objects),
        "objects": objects,
    }


def add_tags_to_threat_model(
    threat_model: dict[str, Any],
    tags: list[dict[str, str]],
    *,
    username: str | None = None,
    api_key: str | None = None,
    base_url: str | None = None,
    tag_path_template: str | None = None,
) -> dict[str, Any]:
    resolved_username = username or os.environ.get("THREATSTREAM_USERNAME")
    resolved_api_key = api_key or os.environ.get("THREATSTREAM_API_KEY")
    if not resolved_username or not resolved_api_key:
        raise ThreatStreamError("Missing THREATSTREAM_USERNAME or THREATSTREAM_API_KEY in environment or .env")

    threat_model_id = _threat_model_id(threat_model)
    if not threat_model_id:
        raise ThreatModelSearchError("Threat model did not include id or resource_uri for tagging")

    resolved_base_url = (base_url or os.environ.get("THREATSTREAM_BASE_URL") or DEFAULT_BASE_URL).rstrip("/")
    resolved_template = (
        tag_path_template
        or os.environ.get("THREATSTREAM_VULNERABILITY_TAG_PATH_TEMPLATE")
        or DEFAULT_VULNERABILITY_TAG_PATH_TEMPLATE
    )
    url = _build_url(resolved_base_url, resolved_template.format(id=threat_model_id))
    request = Request(
        url,
        data=json.dumps({"tags": tags}).encode("utf-8"),
        method="POST",
        headers={
            "Accept": "application/json",
            "Authorization": f"apikey {resolved_username}:{resolved_api_key}",
            "Content-Type": "application/json",
            "User-Agent": "threatstream-tag-search/1.0",
        },
    )

    try:
        with urlopen(request, timeout=30) as response:
            text = response.read().decode("utf-8")
            return json.loads(text) if text else {}
    except HTTPError as exc:
        text = exc.read().decode("utf-8", errors="replace")
        raise ThreatModelSearchError(f"ThreatStream tag request returned HTTP {exc.code}: {text}") from exc
    except URLError as exc:
        raise ThreatModelSearchError(f"Could not reach ThreatStream: {exc.reason}") from exc
    except json.JSONDecodeError as exc:
        raise ThreatModelSearchError("ThreatStream tag request returned non-JSON response") from exc


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Search all ThreatStream threat models for a tag.")
    parser.add_argument("--tag", required=True, help="Tag name or comma-separated tag names to search for.")
    parser.add_argument("--model-type", default=None, help="Optional Threat Model type, for example vulnerability, actor, malware, tipreport.")
    parser.add_argument("--modified-minutes", type=int, default=None, help="Only search models modified within the last N minutes.")
    parser.add_argument("--limit", type=int, default=100, help="Maximum results to return. Default: 100.")
    parser.add_argument("--env-file", default=None, help="Path to .env file. Defaults to .env next to scripts.")
    parser.add_argument(
        "--lookup-exposure",
        action="store_true",
        help="If a model name contains a CVE, query the vulnerability exposure integration for that CVE.",
    )
    parser.add_argument(
        "--tag-exposed",
        action="store_true",
        help="After exposure lookup, tag models with exposed-devices:<count> when count is greater than zero.",
    )
    parser.add_argument("--tag-found", default=None, help="Comma-separated tags to add when exposure count is greater than zero.")
    parser.add_argument("--tag-missed", default=None, help="Comma-separated tags to add when exposure count is zero.")
    parser.add_argument("--tag-all", default=None, help="Comma-separated tags to add to every returned model.")
    parser.add_argument(
        "--skip-if-tagged",
        default=None,
        help="Comma-separated tag names. Skip exposure lookup/result tagging when a model already has any of these tags.",
    )
    parser.add_argument(
        "--results-raw",
        "--raw",
        action="store_true",
        dest="results_raw",
        help="Print the full query/result wrapper including raw ThreatStream response.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    try:
        result = search_threat_models_by_tags(
            args.tag,
            model_type=args.model_type,
            modified_minutes=args.modified_minutes,
            limit=args.limit,
            env_file=args.env_file,
        )
        if args.tag_all:
            add_static_tags(result["objects"], args.tag_all)
        if args.lookup_exposure or args.tag_exposed or args.tag_found or args.tag_missed:
            add_exposure_lookups(
                result["objects"],
                env_file=args.env_file,
                tag_exposed=args.tag_exposed,
                tag_found=args.tag_found,
                tag_missed=args.tag_missed,
                skip_if_tagged=args.skip_if_tagged,
            )
    except (ThreatStreamError, ThreatModelSearchError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except (TransformError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print(json.dumps(result if args.results_raw else result["objects"], indent=2, sort_keys=True))
    return 0


def add_exposure_lookups(
    threat_models: list[dict[str, Any]],
    *,
    env_file: str | None = None,
    tag_exposed: bool = False,
    tag_found: str | None = None,
    tag_missed: str | None = None,
    skip_if_tagged: str | None = None,
) -> None:
    tag_prefix = os.environ.get("EXPOSED_DEVICES_TAG_PREFIX") or DEFAULT_EXPOSED_TAG_PREFIX
    tag_tlp = os.environ.get("EXPOSED_DEVICES_TAG_TLP") or DEFAULT_TAG_TLP
    skip_tags = set(_parse_tag_names(skip_if_tagged)) if skip_if_tagged else set()
    for threat_model in threat_models:
        present_tags = set(_tag_names(threat_model))
        matched_skip_tags = sorted(skip_tags.intersection(present_tags))
        if matched_skip_tags:
            threat_model["exposure_lookup"] = {
                "performed": False,
                "reason": "skipped because model already has a skip tag",
                "skip_tags": matched_skip_tags,
            }
            continue

        cve_id = _cve_from_name(str(threat_model.get("name", "")))
        if not cve_id:
            threat_model["exposure_lookup"] = {
                "performed": False,
                "reason": "model name did not contain a valid CVE",
            }
            continue

        plugin_result = query_vulnerability_plugin(cve_id, env_file=env_file)
        asset_count = _asset_count(plugin_result["summary"])
        threat_model["exposure_lookup"] = {
            "performed": True,
            "cveID": cve_id,
            "asset_count": asset_count,
            "summary": plugin_result["summary"],
        }
        if tag_exposed and asset_count > 0:
            tags = _tag_objects([f"{tag_prefix}:{asset_count}"], tag_tlp)
            threat_model["exposure_lookup"]["tag_response"] = add_tags_to_threat_model(threat_model, tags)
        static_result_tags = _tags_for_exposure_count(asset_count, tag_found, tag_missed, tag_tlp)
        if static_result_tags:
            threat_model["exposure_lookup"]["static_tag_response"] = add_tags_to_threat_model(threat_model, static_result_tags)


def add_static_tags(threat_models: list[dict[str, Any]], tag_value: str) -> None:
    tag_tlp = os.environ.get("EXPOSED_DEVICES_TAG_TLP") or DEFAULT_TAG_TLP
    tags = _tag_objects(_parse_tag_names(tag_value), tag_tlp)
    for threat_model in threat_models:
        threat_model["tag_all_response"] = add_tags_to_threat_model(threat_model, tags)


def _cve_from_name(name: str) -> str | None:
    match = CVE_IN_TEXT_PATTERN.search(name)
    if not match:
        return None
    cve_id = match.group(0).upper()
    return cve_id if CVE_PATTERN.match(cve_id) else None


def _asset_count(plugin_summary: dict[str, Any]) -> int:
    count = 0
    for transform in plugin_summary.get("transforms", []):
        if not isinstance(transform, dict):
            continue
        if isinstance(transform.get("asset_count"), int):
            count = max(count, transform["asset_count"])
        assets = transform.get("vulnerable_assets", [])
        if isinstance(assets, list):
            count = max(count, len(assets))
    return count


def _tag_names(threat_model: dict[str, Any]) -> list[str]:
    tags = threat_model.get("tags", [])
    if isinstance(tags, list):
        names = []
        for tag in tags:
            if isinstance(tag, dict) and tag.get("name"):
                names.append(str(tag["name"]))
            elif isinstance(tag, str):
                names.append(tag)
        return names
    if isinstance(tags, str):
        return [tag.strip() for tag in tags.split(",") if tag.strip()]
    return []


def _tags_for_exposure_count(
    asset_count: int,
    tag_found: str | None,
    tag_missed: str | None,
    tag_tlp: str,
) -> list[dict[str, str]]:
    if asset_count > 0 and tag_found:
        return _tag_objects(_parse_tag_names(tag_found), tag_tlp)
    if asset_count == 0 and tag_missed:
        return _tag_objects(_parse_tag_names(tag_missed), tag_tlp)
    return []


def _parse_tag_names(tag_value: str) -> list[str]:
    tags = [tag.strip() for tag in tag_value.split(",") if tag.strip()]
    if not tags:
        raise ValueError("Tag arguments must include at least one tag name")
    return tags


def _threat_model_key(threat_model: dict[str, Any]) -> str:
    threat_model_id = _threat_model_id(threat_model)
    if threat_model_id:
        return f"id:{threat_model_id}"
    return f"name:{threat_model.get('model_type', '')}:{threat_model.get('name', '')}"


def _threatstream_datetime(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")


if __name__ == "__main__":
    raise SystemExit(main())
