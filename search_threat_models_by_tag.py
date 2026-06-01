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

from kev_watcher import DEFAULT_SEARCH_PATH, DEFAULT_TAG_TLP, _build_url, _tag_objects, _threat_model_id
from threatstream_submit import DEFAULT_BASE_URL, ThreatStreamError, load_dotenv
from vuln_plugin_query import CVE_PATTERN, TransformError, query_vulnerability_plugin


CVE_IN_TEXT_PATTERN = re.compile(r"CVE-\d{4}-\d{4,19}", re.IGNORECASE)
DEFAULT_EXPOSED_TAG_PREFIX = "exposed-devices"
DEFAULT_THREAT_MODEL_TAG_PATH_TEMPLATE = "/api/v1/{entity_type}/{id}/tag/"
MODEL_TYPE_TO_TAG_ENTITY = {
    "actor": "actor",
    "attack pattern": "attackpattern",
    "attackpattern": "attackpattern",
    "campaign": "campaign",
    "incident": "incident",
    "malware": "malware",
    "signature": "signature",
    "threat bulletin": "tipreport",
    "tipreport": "tipreport",
    "ttp": "ttp",
    "vulnerability": "vulnerability",
}


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


def search_vulnerability_models_by_cve(
    cve_id: str,
    *,
    limit: int = 100,
    env_file: str | None = None,
) -> list[dict[str, Any]]:
    """Find vulnerability threat models whose name exactly matches a CVE."""

    load_dotenv(env_file)
    resolved_username = os.environ.get("THREATSTREAM_USERNAME")
    resolved_api_key = os.environ.get("THREATSTREAM_API_KEY")
    if not resolved_username or not resolved_api_key:
        raise ThreatStreamError("Missing THREATSTREAM_USERNAME or THREATSTREAM_API_KEY in environment or .env")

    base_url = (os.environ.get("THREATSTREAM_BASE_URL") or DEFAULT_BASE_URL).rstrip("/")
    search_path = os.environ.get("THREATSTREAM_THREAT_MODEL_SEARCH_PATH") or DEFAULT_SEARCH_PATH
    query = {
        "model_type": "vulnerability",
        "name": cve_id,
        "limit": limit,
    }
    url = _build_url(base_url, search_path, query)
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
        raise ThreatModelSearchError(f"ThreatStream vulnerability search returned HTTP {exc.code}: {text}") from exc
    except URLError as exc:
        raise ThreatModelSearchError(f"Could not reach ThreatStream: {exc.reason}") from exc
    except json.JSONDecodeError as exc:
        raise ThreatModelSearchError("ThreatStream vulnerability search returned non-JSON response") from exc

    objects = body.get("objects", body if isinstance(body, list) else [])
    if not isinstance(objects, list):
        raise ThreatModelSearchError("ThreatStream vulnerability search response did not contain a model list")
    return [model for model in objects if str(model.get("name", "")).upper() == cve_id.upper()]


def search_threat_models_by_tags(
    tags: str | list[str],
    *,
    model_type: str | list[str] | None = None,
    modified_minutes: int | None = None,
    limit: int = 100,
    env_file: str | None = None,
) -> dict[str, Any]:
    """Search once per tag and merge duplicate threat models."""

    tag_names = _parse_tag_names(tags) if isinstance(tags, str) else tags
    model_types = _parse_csv_values(model_type) if isinstance(model_type, str) else model_type
    if not model_types:
        model_types = [None]
    merged: dict[str, dict[str, Any]] = {}
    searches: list[dict[str, Any]] = []

    for tag in tag_names:
        for current_model_type in model_types:
            result = search_threat_models_by_tag(
                tag,
                model_type=current_model_type,
                modified_minutes=modified_minutes,
                limit=limit,
                env_file=env_file,
            )
            searches.append(
                {
                    "tag": tag,
                    "model_type": current_model_type,
                    "query": result["query"],
                    "url": result["url"],
                    "count": result["count"],
                }
            )
            for threat_model in result["objects"]:
                key = _threat_model_key(threat_model)
                if key not in merged:
                    copied = dict(threat_model)
                    copied["matched_search_tags"] = [tag]
                    copied["matched_model_types"] = [current_model_type] if current_model_type else []
                    merged[key] = copied
                else:
                    if tag not in merged[key]["matched_search_tags"]:
                        merged[key]["matched_search_tags"].append(tag)
                    if current_model_type and current_model_type not in merged[key]["matched_model_types"]:
                        merged[key]["matched_model_types"].append(current_model_type)

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
    entity_type = _tag_entity_type(threat_model)
    if not entity_type:
        raise ThreatModelSearchError("Threat model did not include model_type or resource_uri for tagging")

    resolved_base_url = (base_url or os.environ.get("THREATSTREAM_BASE_URL") or DEFAULT_BASE_URL).rstrip("/")
    resolved_template = (
        tag_path_template
        or os.environ.get("THREATSTREAM_THREAT_MODEL_TAG_PATH_TEMPLATE")
        or DEFAULT_THREAT_MODEL_TAG_PATH_TEMPLATE
    )
    url = _build_url(resolved_base_url, resolved_template.format(entity_type=entity_type, id=threat_model_id))
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
    parser.add_argument("--model-type", default=None, help="Optional Threat Model type or comma-separated types, for example vulnerability,tipreport.")
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
        "--tag-vuln-models",
        action="store_true",
        help="When exposure is found from another model type, also tag vulnerability models with the same CVE.",
    )
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
                tag_vuln_models=args.tag_vuln_models,
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
    tag_vuln_models: bool = False,
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

        cve_match = _cve_from_threat_model(threat_model)
        if not cve_match:
            threat_model["exposure_lookup"] = {
                "performed": False,
                "reason": "model name and tags did not contain a valid CVE",
            }
            continue

        cve_id = cve_match["cveID"]
        plugin_result = query_vulnerability_plugin(cve_id, env_file=env_file)
        asset_count = _asset_count(plugin_result["summary"])
        threat_model["exposure_lookup"] = {
            "performed": True,
            "cveID": cve_id,
            "cve_source": cve_match["source"],
            "cve_source_value": cve_match["value"],
            "asset_count": asset_count,
            "summary": plugin_result["summary"],
        }
        result_tags: list[dict[str, str]] = []
        if tag_exposed and asset_count > 0:
            result_tags.extend(_tag_objects([f"{tag_prefix}:{asset_count}"], tag_tlp))
        static_result_tags = _tags_for_exposure_count(asset_count, tag_found, tag_missed, tag_tlp)
        result_tags.extend(static_result_tags)
        if result_tags:
            threat_model["exposure_lookup"]["tag_response"] = add_tags_to_threat_model(threat_model, result_tags)
        if tag_vuln_models and asset_count > 0 and result_tags:
            threat_model["exposure_lookup"]["vulnerability_tag_responses"] = tag_matching_vulnerability_models(
                cve_id,
                result_tags,
                source_threat_model=threat_model,
                env_file=env_file,
            )


def add_static_tags(threat_models: list[dict[str, Any]], tag_value: str) -> None:
    tag_tlp = os.environ.get("EXPOSED_DEVICES_TAG_TLP") or DEFAULT_TAG_TLP
    tags = _tag_objects(_parse_tag_names(tag_value), tag_tlp)
    for threat_model in threat_models:
        threat_model["tag_all_response"] = add_tags_to_threat_model(threat_model, tags)


def tag_matching_vulnerability_models(
    cve_id: str,
    tags: list[dict[str, str]],
    *,
    source_threat_model: dict[str, Any],
    env_file: str | None,
) -> list[dict[str, Any]]:
    source_id = _threat_model_id(source_threat_model)
    responses: list[dict[str, Any]] = []
    for vulnerability_model in search_vulnerability_models_by_cve(cve_id, env_file=env_file):
        if _threat_model_id(vulnerability_model) == source_id:
            continue
        responses.append(
            {
                "threat_model_id": _threat_model_id(vulnerability_model),
                "name": vulnerability_model.get("name"),
                "response": add_tags_to_threat_model(vulnerability_model, tags),
            }
        )
    return responses


def _cve_from_name(name: str) -> str | None:
    match = CVE_IN_TEXT_PATTERN.search(name)
    if not match:
        return None
    cve_id = match.group(0).upper()
    return cve_id if CVE_PATTERN.match(cve_id) else None


def _cve_from_threat_model(threat_model: dict[str, Any]) -> dict[str, str] | None:
    name = str(threat_model.get("name", ""))
    cve_id = _cve_from_name(name)
    if cve_id:
        return {"cveID": cve_id, "source": "name", "value": name}

    for tag in _tag_names(threat_model):
        cve_id = _cve_from_name(tag)
        if cve_id:
            return {"cveID": cve_id, "source": "tag", "value": tag}
    return None


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
    tags = _parse_csv_values(tag_value)
    if not tags:
        raise ValueError("Tag arguments must include at least one tag name")
    return tags


def _parse_csv_values(value: str | None) -> list[str]:
    if not value:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]


def _threat_model_key(threat_model: dict[str, Any]) -> str:
    threat_model_id = _threat_model_id(threat_model)
    if threat_model_id:
        return f"id:{threat_model_id}"
    return f"name:{threat_model.get('model_type', '')}:{threat_model.get('name', '')}"


def _tag_entity_type(threat_model: dict[str, Any]) -> str | None:
    model_type = str(threat_model.get("model_type", "")).strip().lower()
    if model_type in MODEL_TYPE_TO_TAG_ENTITY:
        return MODEL_TYPE_TO_TAG_ENTITY[model_type]

    resource_uri = threat_model.get("resource_uri")
    if isinstance(resource_uri, str):
        parts = [part for part in resource_uri.strip("/").split("/") if part]
        if len(parts) >= 3 and parts[-1].isdigit():
            return parts[-2]
    return None


def _threatstream_datetime(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")


if __name__ == "__main__":
    raise SystemExit(main())
