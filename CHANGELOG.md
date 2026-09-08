# Changelog

All notable changes to this project are documented here.

## 0.1.0 - 2026-09-08

Initial release.

### Added

- Parseable SQL and predicate output formats.
- Sigma CLI and Python API integration through pySigma plugin discovery.
- Case-sensitive and case-insensitive string matching, wildcards, lists, comparisons,
  regular expressions, null checks, existence checks, field references, and fieldless
  keyword searches.
- IPv4 and IPv6 CIDR conversion using Parseable's `ip_in_cidr` SQL function. CIDR queries
  require Parseable v3.2.1 or newer.
- Built-in processing pipelines for Parseable OTLP, flattened ECS, and native Sysmon schemas.
- Custom placeholder and field-mapping pipeline support.
- Unit and live Parseable integration tests.
- Pinned Sigma corpus compatibility regression checks in GitHub Actions.

### Known limitations

- Sigma correlation rules are not supported.
- Timestamp-part modifiers are not supported.
- Fieldless regular expressions are not supported.
- Deployment-specific Sigma placeholders require values supplied through a processing
  pipeline.
