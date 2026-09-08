"""Semantic checks against a live Parseable fixture dataset.

Run after ingesting all JSON fixtures into ``sigma-integration-test``:

    set -a; source .env; set +a
    pytest -m integration tests/integration
"""

from __future__ import annotations

import os

import pytest
import requests
from sigma.collection import SigmaCollection

from sigma.backends.parseable import ParseableBackend

pytestmark = pytest.mark.integration

DATASET = "sigma-integration-test"
START_TIME = "2020-01-01T00:00:00Z"
END_TIME = "2030-01-01T00:00:00Z"


def _credentials() -> tuple[str, str]:
    url = os.getenv("PARSEABLE_URL", "").rstrip("/")
    api_key = os.getenv("PARSEABLE_API_KEY", "")
    if not url or not api_key:
        pytest.skip("PARSEABLE_URL and PARSEABLE_API_KEY are required")
    return url, api_key


def _query(sql: str) -> list[str]:
    url, api_key = _credentials()
    response = requests.post(
        f"{url}/api/v1/query",
        headers={"X-API-Key": api_key},
        json={"query": sql, "startTime": START_TIME, "endTime": END_TIME},
        timeout=30,
    )
    if not response.ok:
        pytest.fail(f"Parseable returned {response.status_code}: {response.text}\nSQL: {sql}")
    return sorted(row["case_id"] for row in response.json())


def _sigma_query(detection: str) -> str:
    source = f"""
title: Live Parseable test
status: test
logsource:
  category: process_creation
fields:
  - case_id
detection:
{detection}
"""
    return ParseableBackend(dataset=DATASET, default_search_fields="message").convert(
        SigmaCollection.from_yaml(source)
    )[0]


@pytest.mark.parametrize(
    ("detection", "expected"),
    [
        (
            """  selection:
    CommandLine|contains: EncodedCommand
  condition: selection""",
            ["case-uppercase", "powershell-positive"],
        ),
        (
            """  selection:
    service.name: checkout
  condition: selection""",
            ["case-uppercase", "powershell-near-miss", "powershell-positive"],
        ),
        (
            """  selection:
    score|gte: 10
  condition: selection""",
            ["case-uppercase", "powershell-positive", "windows-temp-positive"],
        ),
        (
            """  selection:
    Image: null
  condition: selection""",
            [
                "cidr-above",
                "cidr-below",
                "cidr-inside-last-subnet",
                "cidr-inside-one",
                "cidr-invalid-octet",
                "cidr-invalid-text",
                "cidr-ipv6-inside",
                "cidr-ipv6-outside",
                "cidr-lower-bound",
                "cidr-upper-bound",
                "explicit-null",
                "missing-optional-fields",
                "numeric-keyword-six",
                "numeric-keyword-sixty",
                "numeric-keyword-status",
                "numeric-keyword-status-near",
            ],
        ),
        (
            """  selection:
    CommandLine|re|i: ^foo-[0-9]+-bar$
  condition: selection""",
            ["regex-positive"],
        ),
        (
            r"""  selection:
    CommandLine|contains: '\Windows\Temp\payload.exe'
  condition: selection""",
            ["windows-temp-positive"],
        ),
        (
            """  selection:
    SourceIp|cidr: 192.168.0.0/16
  condition: selection""",
            [
                "cidr-inside-last-subnet",
                "cidr-inside-one",
                "cidr-lower-bound",
                "cidr-upper-bound",
            ],
        ),
        (
            """  selection:
    SourceIp|cidr: 2001:db8::/32
  condition: selection""",
            ["cidr-ipv6-inside"],
        ),
    ],
)
def test_generated_sql_semantics(detection: str, expected: list[str]):
    assert _query(_sigma_query(detection)) == expected


def test_apostrophe_is_escaped_and_matches():
    query = _sigma_query(
        """  selection:
    User: "O'Brien"
  condition: selection"""
    )
    assert "o''brien" in query
    assert _query(query) == ["apostrophe"]


def test_numeric_keyword_matches_whole_numeric_token_only():
    query = _sigma_query(
        """  keywords:
    - 200
  condition: keywords"""
    )
    assert _query(query) == ["numeric-keyword-status"]
