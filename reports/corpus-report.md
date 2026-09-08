# Parseable backend Sigma corpus compatibility

- Corpus commit: `5c9b21756f4e3ba137c1773ac9ba5a8332188961`
- Corpus date: `2026-09-07T12:54:20+02:00`
- pySigma: `1.5.0`
- Files: **3783**
- Parsed rule objects: **3783**
- Generated predicates: **3758**
- Successful files: **3758 (99.34%)**

## Status

| Status              | Files |
| ------------------- | ----: |
| `success`           |  3758 |
| `pipeline_required` |    25 |

## Compatibility meaning

A successful file parsed and generated one or more Parseable SQL predicates without conversion errors. This proves backend syntax coverage, not that abstract Sigma fields exist in every Parseable dataset. Production use still requires field and dataset mapping plus representative live-data tests.

## Results by corpus tree

| Tree                     | Success | Unsupported | Pipeline required | Other | Total |
| ------------------------ | ------: | ----------: | ----------------: | ----: | ----: |
| `rules`                  |    3144 |           0 |                 0 |     0 |  3144 |
| `rules-compliance`       |       3 |           0 |                 0 |     0 |     3 |
| `rules-emerging-threats` |     471 |           0 |                 2 |     0 |   473 |
| `rules-placeholder`      |       0 |           0 |                23 |     0 |    23 |
| `rules-threat-hunting`   |     140 |           0 |                 0 |     0 |   140 |

## Top non-success reasons

| Reason                                                                                                 | Files |
| ------------------------------------------------------------------------------------------------------ | ----: |
| `pipeline_required:Attempt to convert unhandled placeholder 'dc_machine_accounts' into query.`         |     3 |
| `pipeline_required:Attempt to convert unhandled placeholder 'Administrators' into query.`              |     2 |
| `pipeline_required:Attempt to convert unhandled placeholder 'Admins_Workstations' into query.`         |     2 |
| `pipeline_required:Attempt to convert unhandled placeholder 'known_cdcs' into query.`                  |     2 |
| `pipeline_required:Attempt to convert unhandled placeholder 'ApprovedUserUpn' into query.`             |     1 |
| `pipeline_required:Attempt to convert unhandled placeholder 'Approved_Inviters' into query.`           |     1 |
| `pipeline_required:Attempt to convert unhandled placeholder 'DC-MACHINE-NAME' into query.`             |     1 |
| `pipeline_required:Attempt to convert unhandled placeholder 'HomeTenantID' into query.`                |     1 |
| `pipeline_required:Attempt to convert unhandled placeholder 'Important_AppIds' into query.`            |     1 |
| `pipeline_required:Attempt to convert unhandled placeholder 'KNOWN_LOCATION' into query.`              |     1 |
| `pipeline_required:Attempt to convert unhandled placeholder 'Known_Location' into query.`              |     1 |
| `pipeline_required:Attempt to convert unhandled placeholder 'Legitimate_Countries' into query.`        |     1 |
| `pipeline_required:Attempt to convert unhandled placeholder 'ServerSystems' into query.`               |     1 |
| `pipeline_required:Attempt to convert unhandled placeholder 'UnLegitCountries' into query.`            |     1 |
| `pipeline_required:Attempt to convert unhandled placeholder 'Workstations' into query.`                |     1 |
| `pipeline_required:Attempt to convert unhandled placeholder 'domain_controller_hostnames' into query.` |     1 |
| `pipeline_required:Attempt to convert unhandled placeholder 'internal_domains' into query.`            |     1 |
| `pipeline_required:Attempt to convert unhandled placeholder 'legit_ips' into query.`                   |     1 |
| `pipeline_required:Attempt to convert unhandled placeholder 'legtimate_identifiers' into query.`       |     1 |
| `pipeline_required:Attempt to convert unhandled placeholder 'userdomain' into query.`                  |     1 |

## Interpretation

- `success`: backend generated one or more predicates.
- `unsupported`: feature deliberately rejected to prevent incorrect SQL.
- `pipeline_required`: placeholder or field transformation needs a processing pipeline.
- `backend_gap`: pySigma reached an unimplemented conversion path.
- `conversion_error`: pySigma-level conversion error needing review.
- `backend_bug`: unexpected exception; highest-priority backend defect.
- `parse_error`: corpus file did not parse under installed pySigma.

## Release interpretation

- No unexpected backend exceptions remain in this snapshot.
- Placeholder rules require deployment-specific values and are correctly not converted blindly.
- IPv4 and IPv6 CIDR rules use Parseable's `ip_in_cidr` SQL function.
- Unbound numeric keywords search configured default fields with numeric token boundaries.
- A future corpus commit can change these numbers; rerun this script for every release.

Full per-file results and product/category/modifier matrices are emitted in the CI `corpus-report` artifact.
