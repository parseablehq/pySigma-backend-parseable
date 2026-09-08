import pytest
from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaConfigurationError

from sigma.backends.parseable import ParseableBackend


def convert(detection: str, *, output_format: str = "default", **options):
    rule = f"""
title: Test rule
status: test
logsource:
  category: process_creation
detection:
{detection}
"""
    return ParseableBackend(**options).convert(
        SigmaCollection.from_yaml(rule), output_format=output_format
    )


def test_and_query():
    assert convert(
        """  selection:
    Image: powershell.exe
    EventID: 1
  condition: selection""",
        dataset="windows-events",
    ) == [
        'SELECT * FROM "windows-events" WHERE LOWER("Image") = \'powershell.exe\' AND "EventID" = 1'
    ]


def test_case_insensitive_contains_and_dotted_field():
    assert convert(
        """  selection:
    service.name|contains: CheckOut
  condition: selection""",
        dataset="otel-logs",
    ) == [
        'SELECT * FROM "otel-logs" WHERE LOWER("service.name") LIKE \'%checkout%\' ESCAPE \'\\\''
    ]


def test_cased_value():
    assert convert(
        """  selection:
    User|cased: Admin
  condition: selection""",
        dataset="auth",
    ) == ['SELECT * FROM "auth" WHERE "User" = \'Admin\'']


def test_or_becomes_in():
    assert convert(
        """  selection:
    Level:
      - ERROR
      - FATAL
  condition: selection""",
        dataset="logs",
    ) == ['SELECT * FROM "logs" WHERE LOWER("Level") IN (\'error\', \'fatal\')']


def test_predicate_does_not_require_dataset():
    assert convert(
        """  selection:
    EventID: 4625
  condition: selection""",
        output_format="predicate",
    ) == ['"EventID" = 4625']


def test_dataset_required_for_default_format():
    with pytest.raises(SigmaConfigurationError, match="dataset required"):
        convert(
            """  selection:
    EventID: 4625
  condition: selection"""
        )


def test_identifier_and_value_quotes_are_doubled():
    assert convert(
        """  selection:
    'odd"field': "O'Brien"
  condition: selection""",
        dataset='odd"dataset',
    ) == [
        'SELECT * FROM "odd""dataset" WHERE LOWER("odd""field") = \'o\'\'brien\''
    ]


@pytest.mark.parametrize("limit", [0, -1, "1; DROP TABLE logs", "1.5"])
def test_invalid_limit_rejected(limit):
    with pytest.raises(SigmaConfigurationError, match="positive integer"):
        ParseableBackend(dataset="logs", limit=limit)


def test_limit():
    assert convert(
        """  selection:
    EventID: 1
  condition: selection""",
        dataset="logs",
        limit="10",
    ) == ['SELECT * FROM "logs" WHERE "EventID" = 1 LIMIT 10']


def test_regex_exists_comparison_and_fieldref():
    assert convert(
        """  selection:
    command|re: "foo.*bar"
    user|exists: true
    score|gte: 5
    source|fieldref: destination
  condition: selection""",
        dataset="events",
    ) == [
        'SELECT * FROM "events" WHERE regexp_like("command", \'foo.*bar\') AND "user" IS NOT NULL AND "score" >= 5 AND LOWER("source") = LOWER("destination")'
    ]


def test_mixed_and_cased_wildcards_use_like():
    assert convert(
        """  selection:
    field|cased: Foo*Bar?
  condition: selection""",
        dataset="events",
    ) == [
        'SELECT * FROM "events" WHERE "field" LIKE \'Foo%Bar_\' ESCAPE \'\\\''
    ]


def test_regex_quote_is_sql_escaped():
    assert convert(
        """  selection:
    field|re: "foo'bar"
  condition: selection""",
        dataset="events",
    ) == ['SELECT * FROM "events" WHERE regexp_like("field", \'foo\'\'bar\')']


def test_keyword_searches_default_fields():
    assert convert(
        """  keywords:
    - credential dumping
  condition: keywords""",
        dataset="logs",
        default_search_fields="body,message",
    ) == [
        'SELECT * FROM "logs" WHERE (LOWER("body") LIKE \'%credential dumping%\' ESCAPE \'\\\' OR LOWER("message") LIKE \'%credential dumping%\' ESCAPE \'\\\')'
    ]
