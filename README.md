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
KEV_TAG_OVERRIDE=
KEV_TAG_TLP=red
THREATSTREAM_THREAT_MODEL_SEARCH_PATH=/api/v1/threat_model_search/
THREATSTREAM_VULNERABILITY_PATH=/api/v1/vulnerability/
THREATSTREAM_VULNERABILITY_TAG_PATH_TEMPLATE=/api/v1/vulnerability/{id}/tag/
```

To apply org-specific tags instead of only `cisa_kev`, set a comma-separated override:

```bash
KEV_TAG_OVERRIDE=company_cisa_kev,pir-004,ir-004-02
```

The lowercase form `kev_tag_override=company_cisa_kev,pir-004,ir-004-02` is also supported.

The watcher stores processed CVEs in `kev_watcher_state.json`, which is ignored by git.

The updated API reference documents the Threat Model search endpoint used by the watcher:
`/api/v1/threat_model_search/?model_type=vulnerability&name=<CVE>&trusted_circle_ids=310`.
For existing matches, the watcher uses the documented tag endpoint:
`POST /api/v1/vulnerability/<id>/tag/` with `{"tags": [{"name": "cisa_kev", "tlp": "red"}]}`.
The placeholder vulnerability creation path remains tenant-configurable through the `.env` path
settings above; run `--dry-run` first to confirm the CVEs that would be processed.

## NVD Vulnerability Sync

`nvd_sync.py` queries the NVD CVE 2.0 API for CVEs modified in a recent window, searches
ThreatStream for a vulnerability named exactly like each CVE, then creates or updates the
ThreatStream vulnerability model. By default it looks back 10 minutes.

Dry-run the last 10 minutes:

```bash
python3 nvd_sync.py --dry-run
```

Sync a specific UTC window:

```bash
python3 nvd_sync.py --start 2026-05-26T12:00:00Z --end 2026-05-26T12:10:00Z
```

Cron-friendly 10-minute entry:

```cron
*/10 * * * * cd /path/to/threatstream_importer && /usr/bin/python3 -B nvd_sync.py --env-file /path/to/threatstream_importer/.env >> /path/to/threatstream_importer/nvd_sync.log 2>&1
```

Relevant `.env` settings:

```bash
NVD_CVE_API_URL=https://services.nvd.nist.gov/rest/json/cves/2.0
NVD_API_KEY=
NVD_TRUSTED_CIRCLE_ID=
NVD_ORGANIZATION_ID=
NVD_TAG_NAME=nvd_sync
NVD_TAG_OVERRIDE=
NVD_TAG_TLP=red
```

Set `NVD_ORGANIZATION_ID` to your ThreatStream organization ID so the sync only updates CVE
models your org owns. If an exact CVE exists only as a shared/external model, the sync will not touch
it and will create a new vulnerability model for your org-managed workflow instead. `NVD_TRUSTED_CIRCLE_ID`
is optional for this script and is not set by default.

Set `NVD_TAG_OVERRIDE=company_nvd_sync,pir-004` to apply comma-separated org-specific tags.
The sync writes the NVD description, CVSS scores, CWE IDs, published/modified dates, status, and
reference links into the ThreatStream vulnerability description.

## Vulnerability Plugin Query

`vuln_plugin_query.py` calls a ThreatStream integration transform for one or more CVEs and returns a
parsed summary of the CVE summary and vulnerable asset tables.

Query one CVE:

```bash
python3 vuln_plugin_query.py CVE-2025-14847
```

Query multiple CVEs:

```bash
python3 vuln_plugin_query.py CVE-2025-14847,CVE-2026-41017
```

Print the raw ThreatStream transform response:

```bash
python3 vuln_plugin_query.py CVE-2025-14847 --raw
```

Import from another script:

```python
from vuln_plugin_query import query_vulnerability_plugin

result = query_vulnerability_plugin("CVE-2025-14847")
print(result["summary"])
```

Relevant `.env` settings:

```bash
THREATSTREAM_TRANSFORM_PATH=/api/v1/integration_package/transform/
THREATSTREAM_VULN_TRANSFORM_ID=4425
```

The script uses `THREATSTREAM_USERNAME` and `THREATSTREAM_API_KEY` by default. If this transform
endpoint only accepts UI-backed auth in your tenant, set `THREATSTREAM_SESSION_COOKIE` and
`THREATSTREAM_CSRF_TOKEN` in `.env` instead.

## Impact Assessment

`impact_assessment.py` searches vulnerability threat models whose tags contain a marker tag, runs
the vulnerability-management plugin for each CVE, and reports impacted asset counts plus impacted
asset domains.

Run without writing tags:

```bash
python3 impact_assessment.py
```

Apply impact result tags back to each threat model:

```bash
python3 impact_assessment.py --apply-tags
```

Example output fields:

```json
{
  "cveID": "CVE-2025-14847",
  "impacted": 2,
  "impacted_domain": "domain.com"
}
```

Relevant `.env` settings:

```bash
IMPACT_MARKER_TAG=sample_impacted
IMPACT_ORGANIZATION_ID=
IMPACTED_TAG_PREFIX=impacted
IMPACTED_DOMAIN_TAG_PREFIX=impacted_domain
IMPACT_TAG_SEPARATOR=:
IMPACT_TAG_TLP=red
```

With the defaults, applied tags look like `impacted:2` and `impacted_domain:domain.com`. To make
them org-unique, set values such as `IMPACTED_TAG_PREFIX=mycompany_impacted` and
`IMPACTED_DOMAIN_TAG_PREFIX=mycompany_impacted_domain`.
