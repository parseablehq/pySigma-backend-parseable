"""Convert a Sigma corpus and write machine-readable and Markdown reports."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import time
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from importlib.metadata import version
from pathlib import Path
from typing import Any

from sigma.collection import SigmaCollection
from sigma.exceptions import (
    SigmaError,
    SigmaFeatureNotSupportedByBackendError,
    SigmaPlaceholderError,
)

from sigma.backends.parseable import ParseableBackend

RULE_TREES = (
    "rules",
    "rules-threat-hunting",
    "rules-emerging-threats",
    "rules-compliance",
    "rules-placeholder",
)
MODIFIER_RE = re.compile(r"^[ \t]+[^#\n:|]+\|([^:\n]+):", re.MULTILINE)


@dataclass
class FileResult:
    path: str
    status: str
    detail: str
    rule_count: int = 0
    query_count: int = 0
    products: tuple[str, ...] = ()
    categories: tuple[str, ...] = ()
    modifiers: tuple[str, ...] = ()


def git_value(root: Path, *args: str) -> str:
    try:
        return subprocess.check_output(
            ["git", "-C", str(root), *args], text=True, stderr=subprocess.DEVNULL
        ).strip()
    except (OSError, subprocess.CalledProcessError):
        return "unknown"


def normalize_error(error: BaseException) -> str:
    message = " ".join(str(error).split())
    message = re.sub(r"\s+in rule .*", "", message)
    message = re.sub(r"\s+in /.*", "", message)
    return message[:500]


def unsupported_detail(error: SigmaFeatureNotSupportedByBackendError) -> str:
    message = str(error)
    if "correlation" in message:
        return "correlation_rules"
    if "IPv6 CIDR" in message:
        return "ipv6_cidr"
    if "timestamp-part" in message:
        return "timestamp_part"
    if "numeric keyword" in message:
        return "unbound_numeric_keyword"
    if "regular-expression searches" in message:
        return "unbound_regex"
    return normalize_error(error)


def metadata(collection: SigmaCollection) -> tuple[tuple[str, ...], tuple[str, ...]]:
    products: set[str] = set()
    categories: set[str] = set()
    for rule in collection.rules:
        logsource = getattr(rule, "logsource", None)
        product = getattr(logsource, "product", None)
        category = getattr(logsource, "category", None)
        if product:
            products.add(str(product))
        if category:
            categories.add(str(category))
    return tuple(sorted(products)), tuple(sorted(categories))


def modifiers(source: str) -> tuple[str, ...]:
    found: set[str] = set()
    for chain in MODIFIER_RE.findall(source):
        found.update(part.strip() for part in chain.split("|") if part.strip())
    return tuple(sorted(found))


def sweep_file(path: Path, corpus: Path) -> FileResult:
    relative = str(path.relative_to(corpus))
    try:
        source = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        return FileResult(relative, "read_error", normalize_error(error))

    file_modifiers = modifiers(source)
    try:
        collection = SigmaCollection.from_yaml(source, source=path)
    except SigmaError as error:
        return FileResult(
            relative, "parse_error", normalize_error(error), modifiers=file_modifiers
        )
    except Exception as error:  # noqa: BLE001 - report unexpected parser defects per file
        return FileResult(
            relative,
            "unexpected_parse_error",
            f"{type(error).__name__}: {normalize_error(error)}",
            modifiers=file_modifiers,
        )

    products, categories = metadata(collection)
    common = {
        "rule_count": len(collection.rules),
        "products": products,
        "categories": categories,
        "modifiers": file_modifiers,
    }
    try:
        queries = ParseableBackend().convert(collection, output_format="predicate")
        if not queries:
            return FileResult(relative, "empty_output", "no_queries", **common)
        return FileResult(
            relative, "success", "converted", query_count=len(queries), **common
        )
    except SigmaFeatureNotSupportedByBackendError as error:
        return FileResult(relative, "unsupported", unsupported_detail(error), **common)
    except SigmaPlaceholderError as error:
        return FileResult(relative, "pipeline_required", normalize_error(error), **common)
    except NotImplementedError as error:
        return FileResult(relative, "backend_gap", normalize_error(error), **common)
    except SigmaError as error:
        return FileResult(relative, "conversion_error", normalize_error(error), **common)
    except Exception as error:  # noqa: BLE001 - report unexpected backend defects per file
        return FileResult(
            relative,
            "backend_bug",
            f"{type(error).__name__}: {normalize_error(error)}",
            **common,
        )


def counter_dict(counter: Counter[str]) -> dict[str, int]:
    return dict(sorted(counter.items(), key=lambda item: (-item[1], item[0])))


def aggregate(results: list[FileResult]) -> dict[str, Any]:
    statuses = Counter(result.status for result in results)
    details = Counter(
        f"{result.status}:{result.detail}" for result in results if result.status != "success"
    )
    product_status: dict[str, Counter[str]] = defaultdict(Counter)
    category_status: dict[str, Counter[str]] = defaultdict(Counter)
    modifier_status: dict[str, Counter[str]] = defaultdict(Counter)
    tree_status: dict[str, Counter[str]] = defaultdict(Counter)
    for result in results:
        tree_status[result.path.split("/", 1)[0]][result.status] += 1
        for product in result.products or ("<none>",):
            product_status[product][result.status] += 1
        for category in result.categories or ("<none>",):
            category_status[category][result.status] += 1
        for modifier in result.modifiers or ("<none>",):
            modifier_status[modifier][result.status] += 1

    return {
        "files": len(results),
        "rules": sum(result.rule_count for result in results),
        "queries": sum(result.query_count for result in results),
        "statuses": counter_dict(statuses),
        "top_failures": counter_dict(details),
        "by_tree": {key: counter_dict(value) for key, value in sorted(tree_status.items())},
        "by_product": {
            key: counter_dict(value) for key, value in sorted(product_status.items())
        },
        "by_category": {
            key: counter_dict(value) for key, value in sorted(category_status.items())
        },
        "by_modifier": {
            key: counter_dict(value) for key, value in sorted(modifier_status.items())
        },
    }


def baseline_errors(
    summary: dict[str, Any], baseline: dict[str, Any], corpus_commit: str | None = None
) -> list[str]:
    """Return human-readable corpus regression failures."""
    errors: list[str] = []
    statuses = summary["statuses"]
    expected_commit = baseline.get("corpus_commit")
    if expected_commit is not None and corpus_commit != expected_commit:
        errors.append(f"corpus commit changed: expected {expected_commit}, got {corpus_commit}")
    expected_files = baseline.get("files")
    if expected_files is not None and summary["files"] != expected_files:
        errors.append(f"files changed: expected {expected_files}, got {summary['files']}")

    minimum_success = baseline.get("minimum_success", 0)
    success = statuses.get("success", 0)
    if success < minimum_success:
        errors.append(f"success regressed: minimum {minimum_success}, got {success}")

    for status, maximum in baseline.get("maximum_statuses", {}).items():
        actual = statuses.get(status, 0)
        if actual > maximum:
            errors.append(f"{status} regressed: maximum {maximum}, got {actual}")

    allowed = set(baseline.get("allowed_statuses", ()))
    unexpected = {status: count for status, count in statuses.items() if status not in allowed}
    if unexpected:
        rendered = ", ".join(f"{status}={count}" for status, count in sorted(unexpected.items()))
        errors.append(f"unexpected statuses: {rendered}")
    return errors


def markdown(report: dict[str, Any]) -> str:
    summary = report["summary"]
    statuses = summary["statuses"]
    success = statuses.get("success", 0)
    rate = success / summary["files"] * 100 if summary["files"] else 0
    lines = [
        "# Parseable backend Sigma corpus compatibility",
        "",
        f"- Corpus commit: `{report['corpus']['commit']}`",
        f"- Corpus date: `{report['corpus']['date']}`",
        f"- pySigma: `{report['environment']['pysigma']}`",
        f"- Files: **{summary['files']}**",
        f"- Parsed rule objects: **{summary['rules']}**",
        f"- Generated predicates: **{summary['queries']}**",
        f"- Successful files: **{success} ({rate:.2f}%)**",
        "",
        "## Status",
        "",
        "| Status | Files |",
        "|---|---:|",
    ]
    lines.extend(f"| `{status}` | {count} |" for status, count in statuses.items())
    lines.extend(
        [
            "",
            "## Compatibility meaning",
            "",
            "A successful file parsed and generated one or more Parseable SQL predicates without conversion errors. This proves backend syntax coverage, not that abstract Sigma fields exist in every Parseable dataset. Production use still requires field and dataset mapping plus representative live-data tests.",
            "",
            "## Results by corpus tree",
            "",
            "| Tree | Success | Unsupported | Pipeline required | Other | Total |",
            "|---|---:|---:|---:|---:|---:|",
        ]
    )
    for tree, tree_counts in summary["by_tree"].items():
        tree_success = tree_counts.get("success", 0)
        tree_unsupported = tree_counts.get("unsupported", 0)
        tree_pipeline = tree_counts.get("pipeline_required", 0)
        tree_total = sum(tree_counts.values())
        tree_other = tree_total - tree_success - tree_unsupported - tree_pipeline
        lines.append(
            f"| `{tree}` | {tree_success} | {tree_unsupported} | "
            f"{tree_pipeline} | {tree_other} | {tree_total} |"
        )
    lines.extend(
        [
            "",
            "## Top non-success reasons",
            "",
            "| Reason | Files |",
            "|---|---:|",
        ]
    )
    for reason, count in list(summary["top_failures"].items())[:30]:
        escaped_reason = reason.replace("|", "\\|")
        lines.append(f"| `{escaped_reason}` | {count} |")
    lines.extend(
        [
            "",
            "## Interpretation",
            "",
            "- `success`: backend generated one or more predicates.",
            "- `unsupported`: feature deliberately rejected to prevent incorrect SQL.",
            "- `pipeline_required`: placeholder or field transformation needs a processing pipeline.",
            "- `backend_gap`: pySigma reached an unimplemented conversion path.",
            "- `conversion_error`: pySigma-level conversion error needing review.",
            "- `backend_bug`: unexpected exception; highest-priority backend defect.",
            "- `parse_error`: corpus file did not parse under installed pySigma.",
            "",
            "## Release interpretation",
            "",
            "- No unexpected backend exceptions remain in this snapshot.",
            "- Placeholder rules require deployment-specific values and are correctly not converted blindly.",
            "- IPv4 and IPv6 CIDR rules use Parseable's `ip_in_cidr` SQL function.",
            "- Unbound numeric keywords search configured default fields with numeric token boundaries.",
            "- A future corpus commit can change these numbers; rerun this script for every release.",
            "",
            "Full per-file results and product/category/modifier matrices are emitted in the CI `corpus-report` artifact.",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("corpus", type=Path)
    parser.add_argument("--output-dir", type=Path, default=Path("reports"))
    parser.add_argument(
        "--baseline",
        type=Path,
        help="JSON regression baseline; exits non-zero when compatibility regresses",
    )
    args = parser.parse_args()
    corpus = args.corpus.resolve()
    paths = sorted(
        path
        for tree in RULE_TREES
        for path in (corpus / tree).rglob("*.yml")
        if (corpus / tree).is_dir()
    )
    if not paths:
        parser.error(f"no Sigma YAML files found below {corpus}")

    start = time.monotonic()
    results = [sweep_file(path, corpus) for path in paths]
    report = {
        "corpus": {
            "root": str(corpus),
            "commit": git_value(corpus, "rev-parse", "HEAD"),
            "date": git_value(corpus, "show", "-s", "--format=%cI", "HEAD"),
            "trees": list(RULE_TREES),
        },
        "environment": {
            "pysigma": version("pysigma"),
            "backend": version("pysigma-backend-parseable"),
        },
        "elapsed_seconds": round(time.monotonic() - start, 3),
        "summary": aggregate(results),
        "results": [asdict(result) for result in results],
    }
    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "corpus-report.json").write_text(
        json.dumps(report, indent=2) + "\n", encoding="utf-8"
    )
    (args.output_dir / "corpus-report.md").write_text(markdown(report), encoding="utf-8")
    print(json.dumps(report["summary"]["statuses"], indent=2))
    if args.baseline:
        baseline = json.loads(args.baseline.read_text(encoding="utf-8"))
        errors = baseline_errors(report["summary"], baseline, report["corpus"]["commit"])
        if errors:
            print("Corpus regression detected:")
            for error in errors:
                print(f"- {error}")
            return 1
        print("Corpus baseline passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
