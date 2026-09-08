# pySigma backend for Parseable

Convert [Sigma](https://github.com/SigmaHQ/sigma) detection rules into SQL accepted by
[Parseable](https://github.com/parseablehq/parseable).

The backend generates SQL only. It does not create alerts, send queries, discover datasets,
or infer how fields are stored in your Parseable instance.

## Requirements

- Python 3.10 or newer
- pySigma 1.x
- Parseable v3.2.1 or newer when executing generated CIDR queries
- A Parseable dataset when executing the generated SQL

## Installation

The package is not yet published. Install it from a checkout:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e .
```

For the `sigma` command-line interface:

```bash
python -m pip install sigma-cli
```

Confirm that the plugin is available:

```bash
sigma list targets
sigma list pipelines parseable
```

## Quick start

Convert a rule into a complete query:

```bash
sigma convert \
  --target parseable \
  --backend-option dataset=windows-events \
  examples/powershell.yml
```

Example output:

```sql
SELECT "Image", "CommandLine", "User"
FROM "windows-events"
WHERE LOWER("Image") LIKE '%\\powershell.exe' ESCAPE '\'
  AND LOWER("CommandLine") LIKE '%-encodedcommand%' ESCAPE '\'
```

The backend quotes dataset and column names, so dotted names such as `service.name` are
rendered as one SQL identifier: `"service.name"`.

### Python API

```python
from pathlib import Path

from sigma.backends.parseable import ParseableBackend
from sigma.collection import SigmaCollection

rules = SigmaCollection.from_yaml(Path("rule.yml").read_text())
backend = ParseableBackend(dataset="windows-events")

for query in backend.convert(rules):
    print(query)
```

`convert()` returns a list because a Sigma document may contain multiple rules or
conditions.

## Output formats

The default format produces a complete query and requires a dataset:

```bash
sigma convert -t parseable -O dataset=windows-events rule.yml
```

```sql
SELECT * FROM "windows-events" WHERE "EventID" = 4625
```

The `predicate` format produces only the condition for embedding in another query. It does
not require a dataset:

```bash
sigma convert -t parseable -f predicate rule.yml
```

```sql
"EventID" = 4625
```

## Backend options

| Option                  | Default                       | Description                                                  |
| ----------------------- | ----------------------------- | ------------------------------------------------------------ |
| `dataset`               | none                          | Dataset in the `FROM` clause; required for default output    |
| `limit`                 | none                          | Positive integer appended as `LIMIT`                         |
| `default_search_fields` | `body,message,event.original` | Comma-separated columns searched by fieldless Sigma keywords |

Example:

```bash
sigma convert \
  -t parseable \
  -O dataset=application-logs \
  -O limit=500 \
  -O default_search_fields=body,message,log \
  rule.yml
```

Every configured search field must exist in the target dataset. DataFusion rejects a query
that references a missing column.

## Field mapping pipelines

Sigma rules use abstract field names. Parseable queries must use the exact columns created
at ingestion. Select the pipeline matching your stored event schema:

| Pipeline           | Use when                                                              |
| ------------------ | --------------------------------------------------------------------- |
| `parseable_otlp`   | OTLP log attributes are stored as literal semantic-convention columns |
| `parseable_ecs`    | Nested ECS documents are flattened by Parseable using underscores     |
| `parseable_sysmon` | Events use native Sysmon fields                                       |

### OpenTelemetry

```bash
sigma convert \
  -t parseable \
  -p parseable_otlp \
  -O dataset=otel-events \
  rule.yml
```

Representative mappings:

| Sigma             | Parseable OTLP            |
| ----------------- | ------------------------- |
| `Image`           | `process.executable.path` |
| `CommandLine`     | `process.command_line`    |
| `ProcessId`       | `process.pid`             |
| `ParentProcessId` | `process.parent_pid`      |
| `SourceIp`        | `source.address`          |
| `DestinationIp`   | `destination.address`     |
| `DestinationPort` | `destination.port`        |
| `TargetFilename`  | `file.path`               |
| `QueryName`       | `dns.question.name`       |
| `Computer`        | `host.name`               |

Mappings are scoped by Sigma log source where field meaning changes. The pipeline does not
invent fields without a standard OpenTelemetry equivalent.

### ECS

```bash
sigma convert \
  -t parseable \
  -p parseable_ecs \
  -O dataset=ecs-events \
  rule.yml
```

Nested ECS input such as `{"source":{"ip":"192.0.2.1"}}` becomes the Parseable column
`source_ip`.

| Sigma            | Flattened ECS               |
| ---------------- | --------------------------- |
| `EventID`        | `event_code`                |
| `Channel`        | `winlog_channel`            |
| `Image`          | `process_executable`        |
| `CommandLine`    | `process_command_line`      |
| `ParentImage`    | `process_parent_executable` |
| `User`           | `user_name`                 |
| `SourceIp`       | `source_ip`                 |
| `DestinationIp`  | `destination_ip`            |
| `TargetFilename` | `file_path`                 |
| `QueryName`      | `dns_question_name`         |

Use a custom pipeline if your events contain literal dotted ECS keys or use different column
names.

### Sysmon

```bash
sigma convert \
  -t parseable \
  -p parseable_sysmon \
  -O dataset=sysmon-events \
  rule.yml
```

This pipeline retains native Sysmon fields and adds the appropriate `Channel` and `EventID`
conditions for generic Windows log sources. For Sysmon normalized to nested ECS before
ingestion, chain the pipelines:

```bash
sigma convert \
  -t parseable \
  -p parseable_sysmon \
  -p parseable_ecs \
  -O dataset=ecs-sysmon-events \
  rule.yml
```

### Custom schemas

Built-in pipelines cannot know organization-specific column names. Define a pySigma pipeline
for the schema actually present in your dataset:

```yaml
name: My Parseable field mapping
priority: 30
allowed_backends:
  - parseable
transformations:
  - id: organization_fields
    type: field_name_mapping
    mapping:
      Image: exe_path
      CommandLine: command
      User: username
      SourceIp: client_ip
```

```bash
sigma convert \
  -t parseable \
  -p company-parseable.yml \
  -O dataset=company-events \
  rule.yml
```

Always compare generated columns with the Parseable dataset schema before deploying rules.

## Supported Sigma features

The backend supports:

- Case-insensitive Sigma string matching and the `cased` modifier
- `contains`, `startswith`, `endswith`, `exists`, `fieldref`, and comparison modifiers
- Sigma `*` and `?` wildcards
- String and numeric lists
- Regular expressions bound to a field
- Null checks and Boolean conditions
- Fieldless string and numeric keyword searches
- IPv4 and IPv6 CIDR expressions through Parseable's `ip_in_cidr` SQL function

Unsupported constructs fail explicitly with `SigmaFeatureNotSupportedByBackendError`:

- Sigma correlation rules
- Timestamp-part modifiers such as `minute` and `hour`
- Fieldless regular expressions

CIDR conversion requires a Parseable deployment that provides `ip_in_cidr(ip, cidr)`. The
function correctly parses IPv4 and IPv6 rather than approximating address ranges as text.

## Placeholders

Sigma placeholders such as `%Administrators%` are deployment-specific values. Resolve them
with a processing pipeline before conversion:

```bash
sigma convert \
  -t parseable \
  -p examples/placeholder-pipeline.yml \
  -O dataset=windows-events \
  examples/placeholder-rule.yml
```

Do not replace unknown placeholders with wildcards; that changes the detection's meaning.

## Development

Install development dependencies and run local checks:

```bash
python -m pip install -e '.[test]'
pytest tests -m 'not integration'
ruff check .
python -m build
```

Live tests require `PARSEABLE_URL`, `PARSEABLE_INGESTION_URL`, and `PARSEABLE_API_KEY`.
They use fixture datasets and are intentionally excluded from the default test command:

```bash
pytest tests/integration -m integration
```

The GitHub Actions corpus job checks conversion against a pinned Sigma corpus. Detailed
results and regression thresholds live in [`reports/`](reports/) rather than this README.
Successful conversion means valid SQL was generated; it does not prove that a deployment has
matching columns or representative data.

## License

MIT
