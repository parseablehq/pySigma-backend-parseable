import pytest
from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaConfigurationError

from sigma.backends.parseable import ParseableBackend


def convert_yaml(source: str, *, output_format: str = "predicate", **options):
    return ParseableBackend(**options).convert(
        SigmaCollection.from_yaml(source), output_format=output_format
    )


def rule(detection: str, *, fields: str = "") -> str:
    return f"""
title: Extended test rule
status: test
{fields}logsource:
  category: process_creation
detection:
{detection}
"""


def test_not_and_nested_boolean_precedence():
    result = convert_yaml(
        rule(
            """  image:
    Image|endswith: '\\cmd.exe'
  suspicious:
    CommandLine|contains:
      - whoami
      - ipconfig
  filter:
    User: SYSTEM
  condition: image and (1 of suspicious) and not filter"""
        )
    )
    assert result == [
        (
            "LOWER(\"Image\") LIKE '%\\\\cmd.exe' ESCAPE '\\' AND "
            "(LOWER(\"CommandLine\") LIKE '%whoami%' ESCAPE '\\' OR "
            "LOWER(\"CommandLine\") LIKE '%ipconfig%' ESCAPE '\\') AND "
            "(NOT LOWER(\"User\") = 'system')"
        )
    ]


def test_one_of_and_all_of_selections():
    one_of = convert_yaml(
        rule(
            """  selection_one:
    EventID: 1
  selection_two:
    EventID: 2
  condition: 1 of selection_*"""
        )
    )
    all_of = convert_yaml(
        rule(
            """  selection_one:
    EventID: 1
  selection_two:
    Channel: Security
  condition: all of selection_*"""
        )
    )
    assert one_of == ['"EventID" IN (1, 2)']
    assert all_of == ['"EventID" = 1 AND LOWER("Channel") = \'security\'']


def test_literal_sigma_wildcards_remain_literals():
    result = convert_yaml(
        rule(
            r"""  selection:
    literal_star: 'value\*suffix'
    literal_question: 'value\?suffix'
    percent_then_wildcard: 'value%part*'
    underscore_then_wildcard: 'value_part*'
  condition: selection"""
        )
    )
    assert result == [
        (
            "LOWER(\"literal_star\") = 'value*suffix' AND "
            "LOWER(\"literal_question\") = 'value?suffix' AND "
            "LOWER(\"percent_then_wildcard\") LIKE 'value\\%part%' ESCAPE '\\' AND "
            "LOWER(\"underscore_then_wildcard\") LIKE 'value\\_part%' ESCAPE '\\'"
        )
    ]


def test_windows_path_backslashes_are_preserved():
    result = convert_yaml(
        rule(
            r"""  selection:
    Image: 'C:\Windows\System32\cmd.exe'
    CommandLine|contains: '\Windows\Temp\payload.exe'
  condition: selection"""
        )
    )
    assert result == [
        (
            "LOWER(\"Image\") = 'c:\\windows\\system32\\cmd.exe' AND "
            "LOWER(\"CommandLine\") LIKE "
            "'%\\\\windows\\\\temp\\\\payload.exe%' ESCAPE '\\'"
        )
    ]


def test_unicode_casefolding():
    result = convert_yaml(
        rule(
            """  selection:
    User: Straße
    City|contains: İstanbul
  condition: selection"""
        )
    )
    assert result == [
        "LOWER(\"User\") = 'strasse' AND LOWER(\"City\") LIKE '%i̇stanbul%' ESCAPE '\\'"
    ]


def test_null_boolean_and_missing_field_checks():
    result = convert_yaml(
        rule(
            """  selection:
    nullable: null
    enabled: true
    present|exists: true
    absent|exists: false
  condition: selection"""
        )
    )
    assert result == [
        (
            '"nullable" IS NULL AND "enabled" = TRUE AND '
            '"present" IS NOT NULL AND "absent" IS NULL'
        )
    ]


def test_multiple_conditions_produce_multiple_queries():
    result = convert_yaml(
        rule(
            """  first:
    EventID: 1
  second:
    EventID: 2
  condition:
    - first
    - second"""
        )
    )
    assert result == ['"EventID" = 1', '"EventID" = 2']


def test_selected_fields_are_quoted_in_complete_query():
    result = convert_yaml(
        rule(
            """  selection:
    EventID: 1
  condition: selection""",
            fields="fields:\n  - service.name\n  - odd-field\n",
        ),
        output_format="default",
        dataset="events",
    )
    assert result == [
        'SELECT "service.name", "odd-field" FROM "events" WHERE "EventID" = 1'
    ]


def test_regex_flags_and_apostrophe_are_preserved_safely():
    result = convert_yaml(
        rule(
            """  selection:
    command|re|i: "foo'.*BAR"
  condition: selection"""
        )
    )
    assert result == ['regexp_like("command", \'(?i)foo\'\'.*BAR\')']


@pytest.mark.parametrize(
    ("modifier", "expected"),
    [
        ("contains", 'strpos(LOWER("left"), LOWER("right")) > 0'),
        ("startswith", 'starts_with(LOWER("left"), LOWER("right"))'),
        ("endswith", 'ends_with(LOWER("left"), LOWER("right"))'),
    ],
)
def test_fieldref_string_modifiers(modifier, expected):
    result = convert_yaml(
        rule(
            f"""  selection:
    left|fieldref|{modifier}: right
  condition: selection"""
        )
    )
    assert result == [expected]


def test_dataset_and_value_cannot_escape_sql_context():
    result = convert_yaml(
        rule(
            """  selection:
    message: "x'; DROP TABLE events; --"
  condition: selection"""
        ),
        output_format="default",
        dataset='logs"; DROP TABLE users; --',
    )
    assert result == [
        (
            'SELECT * FROM "logs""; DROP TABLE users; --" WHERE '
            "LOWER(\"message\") = 'x''; drop table events; --'"
        )
    ]


def test_keyword_search_rejects_empty_field_configuration():
    with pytest.raises(SigmaConfigurationError, match="default_search_fields"):
        convert_yaml(
            rule(
                """  keywords:
    - suspicious text
  condition: keywords"""
            ),
            default_search_fields="",
        )


def test_numeric_keyword_uses_token_boundaries_across_configured_fields():
    result = convert_yaml(
        rule(
            """  keywords:
    - 200
  condition: keywords"""
        ),
        default_search_fields="message,sc-status",
    )
    assert result == [
        (
            "(regexp_like(CAST(\"message\" AS VARCHAR), "
            "'(^|[^0-9.+-])200([^0-9.]|$)') OR "
            "regexp_like(CAST(\"sc-status\" AS VARCHAR), "
            "'(^|[^0-9.+-])200([^0-9.]|$)'))"
        )
    ]


def test_numeric_keyword_rejects_empty_field_configuration():
    with pytest.raises(SigmaConfigurationError, match="numeric keywords"):
        convert_yaml(
            rule(
                """  keywords:
    - 200
  condition: keywords"""
            ),
            default_search_fields="",
        )
