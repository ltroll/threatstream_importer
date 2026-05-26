# ThreatStream Indicator Submitter

Submit IP, domain, email, and URL indicators to Anomali ThreatStream from the command line or from another
Python script. The script uses the ThreatStream direct import API, which imports valid JSON without
requiring approval in the ThreatStream UI:

```text
PATCH https://api.threatstream.com/api/v2/intelligence/
```

You must have the ThreatStream permission required for import without approval.

## Files

- `threatstream_submit.py` - importable module and command-line tool.
- `.env.example` - template for local credentials and defaults.
- `.env` - your local secrets file. This file is ignored by git.
- `Threatstream API Reference.txt` - local reference documentation.

## Setup

Copy the example environment file and fill in your ThreatStream username and API key:

```bash
cp .env.example .env
```

Required values:

```bash
THREATSTREAM_USERNAME=you@example.com
THREATSTREAM_API_KEY=your-api-key
```

Optional defaults:

```bash
THREATSTREAM_BASE_URL=https://api.threatstream.com
THREATSTREAM_CLASSIFICATION=private
THREATSTREAM_CONFIDENCE=60
THREATSTREAM_SEVERITY=high
THREATSTREAM_ALLOW_UNRESOLVED=true
THREATSTREAM_SOURCE_CONFIDENCE_WEIGHT=100
THREATSTREAM_TAG_TLP=red
```

No third-party Python packages are required.

## Command-Line Usage

Submit an IP:

```bash
python3 threatstream_submit.py 1.2.3.4 \
  --indicator-type ip \
  --itype mal_ip \
  --tags case-123,phishing
```

Submit a domain:

```bash
python3 threatstream_submit.py bad.example.com \
  --indicator-type domain \
  --itype mal_domain \
  --tags case-123,malware \
  --classification private \
  --confidence 80 \
  --severity high \
  --allow-unresolved
```

Submit an email:

```bash
python3 threatstream_submit.py user@example.com \
  --indicator-type email \
  --itype compromised_email \
  --tags case-123,phishing \
  --confidence 80
```

Submit a URL:

```bash
python3 threatstream_submit.py https://bad.example.com/login \
  --indicator-type url \
  --itype phish_url \
  --tags case-123,phishing
```

Preview the JSON payload without submitting:

```bash
python3 threatstream_submit.py 5.253.63.134 \
  --indicator-type ip \
  --itype bot_ip \
  --tags botnet,case-456 \
  --dry-run
```

Use a different env file:

```bash
python3 threatstream_submit.py example.com \
  --indicator-type domain \
  --itype apt_domain \
  --env-file /secure/path/threatstream.env
```

Required CLI arguments:

- `indicator` - the indicator value, such as `1.2.3.4` or `bad.example.com`.
- `--indicator-type` - currently `ip`, `domain`, `email`, or `url`.
- `--itype` - the ThreatStream indicator type, such as `mal_ip`, `bot_ip`, `mal_domain`, `compromised_email`, or `phish_url`.

Common optional arguments:

- `--tags` - comma-separated tag names.
- `--classification` - `public` or `private`.
- `--confidence` - integer from `0` to `100`.
- `--severity` - `low`, `medium`, `high`, or `very-high`.
- `--allow-unresolved` - sends `allow_unresolved: true` in the `meta` object.
- `--source-confidence-weight` - integer from `0` to `100`.
- `--tag-tlp` - applies a tag visibility value to every submitted tag. Defaults to `red`, which makes tags private.

## Import From Python

```python
from threatstream_submit import submit_indicator

result = submit_indicator(
    indicator="1.2.3.4",
    indicator_type="ip",
    itype="mal_ip",
    tags="case-123,phishing",
    classification="private",
    confidence=80,
    severity="high",
)

print(result)
```

The module loads `.env` automatically from the same directory as `threatstream_submit.py`. You can
also set `THREATSTREAM_USERNAME` and `THREATSTREAM_API_KEY` in the process environment before
calling `submit_indicator`.

## Notes

- The API key is sent in the `Authorization` header as recommended by the ThreatStream reference.
- The script never prints the username or API key.
- For IP indicators, the payload uses the ThreatStream `srcip` field.
- For domain indicators, the payload uses the ThreatStream `domain` field.
- For email indicators, the payload uses the ThreatStream `email` field.
- For URL indicators, the payload uses the ThreatStream `url` field.
- Tags are private by default and are sent as ThreatStream tag objects, for example `{"name": "case-123", "tlp": "red"}`.

## CISA KEV Watcher

`kev_watcher.py` checks the CISA Known Exploited Vulnerabilities JSON catalog for newly added CVEs.
For each new CVE, it searches ThreatStream Threat Model vulnerabilities in trusted circle `310`. If it
finds a vulnerability named exactly like the CVE, it adds the private tag `cisa_kev`. If no matching
vulnerability is found, it creates a placeholder vulnerability with that tag.

Run one dry-run check against the current catalog:

```bash
python3 kev_watcher.py --once --dry-run --process-existing
```

Start the watcher loop. It checks every 10 minutes by default:

```bash
python3 kev_watcher.py
```

Run once for cron:

```bash
python3 kev_watcher.py --run-once
```

Test against KEVs added in the last 5 days:

```bash
python3 kev_watcher.py --run-once --dry-run --day 5
```

On the first real run, the script records the current KEV catalog as its baseline and does not process
all existing KEVs. To process the full current catalog intentionally, use:

```bash
python3 kev_watcher.py --once --process-existing
```

Relevant `.env` settings:

```bash
KEV_URL=https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json
KEV_WATCH_INTERVAL_SECONDS=600
KEV_WATCHER_STATE_FILE=kev_watcher_state.json
KEV_TRUSTED_CIRCLE_ID=310
KEV_TAG_NAME=cisa_kev
KEV_TAG_TLP=red
THREATSTREAM_THREAT_MODEL_SEARCH_PATH=/api/v1/threat_model_search/
THREATSTREAM_VULNERABILITY_PATH=/api/v1/vulnerability/
THREATSTREAM_VULNERABILITY_TAG_PATH_TEMPLATE=/api/v1/vulnerability/{id}/tag/
```

The watcher stores processed CVEs in `kev_watcher_state.json`, which is ignored by git.

The updated API reference documents the Threat Model search endpoint used by the watcher:
`/api/v1/threat_model_search/?model_type=vulnerability&name=<CVE>&trusted_circle_ids=310`.
For existing matches, the watcher uses the documented tag endpoint:
`POST /api/v1/vulnerability/<id>/tag/` with `{"tags": [{"name": "cisa_kev", "tlp": "red"}]}`.
The placeholder vulnerability creation path remains tenant-configurable through the `.env` path
settings above; run `--dry-run` first to confirm the CVEs that would be processed.
