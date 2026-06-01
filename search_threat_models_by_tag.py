#!/usr/bin/env python3
"""Search ThreatStream threat models by tag."""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from kev_watcher import DEFAULT_SEARCH_PATH, _build_url
from threatstream_submit import DEFAULT_BASE_URL, ThreatStreamError, load_dotenv


class ThreatModelSearchError(RuntimeError):
    """Raised when ThreatStream threat model search fails."""


def search_threat_models_by_tag(
    tag: str,
    *,
    model_type: str | None = None,
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


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Search all ThreatStream threat models for a tag.")
    parser.add_argument("--tag", required=True, help="Tag name to search for.")
    parser.add_argument("--model-type", default=None, help="Optional Threat Model type, for example vulnerability, actor, malware, tipreport.")
    parser.add_argument("--limit", type=int, default=100, help="Maximum results to return. Default: 100.")
    parser.add_argument("--env-file", default=None, help="Path to .env file. Defaults to .env next to scripts.")
    parser.add_argument("--raw", action="store_true", help="Print raw ThreatStream response.")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    try:
        result = search_threat_models_by_tag(
            args.tag,
            model_type=args.model_type,
            limit=args.limit,
            env_file=args.env_file,
        )
    except (ThreatStreamError, ThreatModelSearchError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print(json.dumps(result["raw"] if args.raw else result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
