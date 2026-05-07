# ThreatStream Indicator Submitter

Submit IP and domain indicators to Anomali ThreatStream from the command line or from another
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
- `--indicator-type` - currently `ip` or `domain`.
- `--itype` - the ThreatStream indicator type, such as `mal_ip`, `bot_ip`, or `mal_domain`.

Common optional arguments:

- `--tags` - comma-separated tag names.
- `--classification` - `public` or `private`.
- `--confidence` - integer from `0` to `100`.
- `--severity` - `low`, `medium`, `high`, or `very-high`.
- `--allow-unresolved` - sends `allow_unresolved: true` in the `meta` object.
- `--source-confidence-weight` - integer from `0` to `100`.
- `--tag-tlp` - applies a tag visibility value to every submitted tag.

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
- Tags are sent as ThreatStream tag objects, for example `{"name": "case-123"}`.
