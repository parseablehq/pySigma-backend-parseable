"""Live semantic checks for built-in Parseable schema pipelines."""

from __future__ import annotations

import os

import pytest
import requests
from sigma.collection import SigmaCollection

from sigma.backends.parseable import ParseableBackend
from sigma.pipelines.parseable import (
    parseable_ecs_pipeline,
    parseable_otlp_pipeline,
    parseable_sysmon_pipeline,
)

pytestmark = pytest.mark.integration

DATASET = "sigma-pipeline-integration-test"
START_TIME = "2020-01-01T00:00:00Z"
END_TIME = "2030-01-01T00:00:00Z"
RULE = r"""
title: Pipeline live test
status: test
logsource:
  product: windows
  category: process_creation
fields:
  - case_id
detection:
  selection:
    Image|endswith: '\powershell.exe'
    CommandLine|contains: '-EncodedCommand'
  condition: selection
"""


def _query(pipeline) -> tuple[str, list[str]]:
    url = os.getenv("PARSEABLE_URL", "").rstrip("/")
    api_key = os.getenv("PARSEABLE_API_KEY", "")
    if not url or not api_key:
        pytest.skip("PARSEABLE_URL and PARSEABLE_API_KEY are required")
    sql = ParseableBackend(pipeline, dataset=DATASET).convert(
        SigmaCollection.from_yaml(RULE)
    )[0]
    response = requests.post(
        f"{url}/api/v1/query",
        headers={"X-API-Key": api_key},
        json={"query": sql, "startTime": START_TIME, "endTime": END_TIME},
        timeout=30,
    )
    if not response.ok:
        pytest.fail(f"Parseable returned {response.status_code}: {response.text}\nSQL: {sql}")
    return sql, sorted(row["case_id"] for row in response.json())


def test_otlp_pipeline_live_semantics():
    sql, rows = _query(parseable_otlp_pipeline())
    assert '"process.executable.path"' in sql
    assert rows == ["pipeline-otlp"]


def test_flattened_ecs_pipeline_live_semantics():
    sql, rows = _query(parseable_sysmon_pipeline() + parseable_ecs_pipeline())
    assert '"process_executable"' in sql
    assert '"event_code" = 1' in sql
    assert rows == ["pipeline-ecs"]


def test_native_sysmon_pipeline_live_semantics():
    sql, rows = _query(parseable_sysmon_pipeline())
    assert '"Image"' in sql
    assert '"EventID" = 1' in sql
    assert rows == ["pipeline-sysmon"]
