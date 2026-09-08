from sigma.collection import SigmaCollection
from sigma.plugins import InstalledSigmaPlugins

from sigma.backends.parseable import ParseableBackend
from sigma.pipelines.parseable import (
    parseable_ecs_pipeline,
    parseable_otlp_pipeline,
    parseable_sysmon_pipeline,
)


def convert(source: str, pipeline) -> str:
    return ParseableBackend(pipeline, dataset="events").convert(
        SigmaCollection.from_yaml(source)
    )[0]


def rule(logsource: str, detection: str, fields: str = "") -> str:
    return f"""
title: Pipeline test
status: test
logsource:
{logsource}
{fields}detection:
{detection}
"""


def test_pipeline_autodiscovery_and_backend_restriction():
    plugins = InstalledSigmaPlugins.autodiscover(
        include_backends=False,
        include_validators=False,
    )
    assert {
        "parseable_otlp",
        "parseable_ecs",
        "parseable_sysmon",
    } <= plugins.pipelines.keys()
    for pipeline_id in ("parseable_otlp", "parseable_ecs", "parseable_sysmon"):
        assert plugins.pipelines[pipeline_id]().allowed_backends == frozenset({"parseable"})


def test_otlp_process_fields_and_projection_use_literal_otel_attributes():
    query = convert(
        rule(
            "  product: windows\n  category: process_creation",
            """  selection:
    Image|endswith: '\\powershell.exe'
    CommandLine|contains: EncodedCommand
    ProcessId: 123
    ParentProcessId: 42
    User: alice
  condition: selection""",
            "fields:\n  - Image\n  - User\n",
        ),
        parseable_otlp_pipeline(),
    )
    assert query.startswith('SELECT "process.executable.path", "process.owner" FROM "events"')
    assert 'LOWER("process.executable.path") LIKE' in query
    assert 'LOWER("process.command_line") LIKE' in query
    assert '"process.pid" = 123' in query
    assert '"process.parent_pid" = 42' in query
    assert 'LOWER("process.owner") = \'alice\'' in query


def test_otlp_network_file_and_dns_mappings_are_logsource_scoped():
    network = convert(
        rule(
            "  category: network_connection",
            """  selection:
    SourceIp: 10.0.0.1
    SourcePort: 1234
    DestinationIp: 10.0.0.2
    DestinationPort: 443
    Protocol: tcp
    Image: curl
  condition: selection""",
        ),
        parseable_otlp_pipeline(),
    )
    file_query = convert(
        rule(
            "  category: file_event",
            """  selection:
    TargetFilename|endswith: /payload
  condition: selection""",
        ),
        parseable_otlp_pipeline(),
    )
    dns = convert(
        rule(
            "  category: dns_query",
            """  selection:
    QueryName: example.com
  condition: selection""",
        ),
        parseable_otlp_pipeline(),
    )
    assert all(
        field in network
        for field in (
            '"source.address"',
            '"source.port"',
            '"destination.address"',
            '"destination.port"',
            '"network.transport"',
            '"process.executable.path"',
        )
    )
    assert '"file.path"' in file_query
    assert '"dns.question.name"' in dns


def test_ecs_maps_documented_fields_and_prefixes_unmapped_windows_event_data():
    query = convert(
        rule(
            "  product: windows\n  service: security",
            """  selection:
    EventID: 4624
    SubjectUserName: alice
    TargetUserName: bob
    CustomField: value
  condition: selection""",
        ),
        parseable_ecs_pipeline(),
    )
    assert 'LOWER("winlog_channel") = \'security\'' in query
    assert '"event_code" = 4624' in query
    assert 'LOWER("user_name") = \'alice\'' in query
    assert 'LOWER("user_target_name") = \'bob\'' in query
    assert 'LOWER("winlog_event_data_CustomField") = \'value\'' in query


def test_sysmon_adds_canonical_channel_and_event_ids():
    process = convert(
        rule(
            "  product: windows\n  category: process_creation",
            """  selection:
    Image: cmd.exe
  condition: selection""",
        ),
        parseable_sysmon_pipeline(),
    )
    registry = convert(
        rule(
            "  product: windows\n  category: registry_event",
            """  selection:
    TargetObject|contains: Run
  condition: selection""",
        ),
        parseable_sysmon_pipeline(),
    )
    assert 'LOWER("Channel") = \'microsoft-windows-sysmon/operational\'' in process
    assert '"EventID" = 1' in process
    assert '"EventID" IN (12, 13, 14)' in registry


def test_sysmon_then_ecs_pipeline_maps_added_conditions_and_rule_fields():
    pipeline = parseable_sysmon_pipeline() + parseable_ecs_pipeline()
    query = convert(
        rule(
            "  product: windows\n  category: network_connection",
            """  selection:
    Image: curl.exe
    DestinationIp: 192.0.2.10
  condition: selection""",
        ),
        pipeline,
    )
    assert 'LOWER("winlog_channel") = \'microsoft-windows-sysmon/operational\'' in query
    assert '"event_code" = 3' in query
    assert 'LOWER("process_executable") = \'curl.exe\'' in query
    assert 'LOWER("destination_ip") = \'192.0.2.10\'' in query
