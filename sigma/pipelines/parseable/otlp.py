"""Mappings for OpenTelemetry semantic-convention attributes ingested through OTLP."""

from sigma.processing.conditions import LogsourceCondition
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.processing.transformations import FieldMappingTransformation

PROCESS_CATEGORIES = (
    "process_creation",
    "process_termination",
    "process_access",
    "process_tampering",
    "create_remote_thread",
    "raw_access_thread",
)
NETWORK_CATEGORIES = ("network_connection", "firewall", "proxy")
FILE_CATEGORIES = (
    "file_access",
    "file_change",
    "file_create",
    "file_delete",
    "file_delete_detected",
    "file_event",
    "file_executable_detected",
    "file_rename",
    "image_load",
)
PROCESS_CONTEXT_CATEGORIES = tuple(
    dict.fromkeys(PROCESS_CATEGORIES + NETWORK_CATEGORIES + FILE_CATEGORIES + ("dns_query",))
)


def _category_conditions(categories: tuple[str, ...]) -> list[LogsourceCondition]:
    return [LogsourceCondition(category=category) for category in categories]


def parseable_otlp_pipeline() -> ProcessingPipeline:
    """Map Sigma taxonomy fields to literal OTel attributes stored by Parseable OTLP."""
    return ProcessingPipeline(
        name="Parseable OTLP semantic-convention mappings",
        priority=20,
        allowed_backends=frozenset({"parseable"}),
        items=[
            ProcessingItem(
                identifier="parseable_otlp_host_fields",
                transformation=FieldMappingTransformation(
                    {
                        "Computer": "host.name",
                        "ComputerName": "host.name",
                    }
                ),
            ),
            ProcessingItem(
                identifier="parseable_otlp_process_fields",
                transformation=FieldMappingTransformation(
                    {
                        "Image": "process.executable.path",
                        "ProcessName": "process.executable.path",
                        "CommandLine": "process.command_line",
                        "CurrentDirectory": "process.working_directory",
                        "ProcessId": "process.pid",
                        "ProcessID": "process.pid",
                        "ParentProcessId": "process.parent_pid",
                        "ParentProcessID": "process.parent_pid",
                        "User": "process.owner",
                    }
                ),
                rule_conditions=_category_conditions(PROCESS_CONTEXT_CATEGORIES),
                rule_condition_linking=any,
            ),
            ProcessingItem(
                identifier="parseable_otlp_network_fields",
                transformation=FieldMappingTransformation(
                    {
                        "SourceIp": "source.address",
                        "SourceIP": "source.address",
                        "SourceAddress": "source.address",
                        "SourceHostname": "source.address",
                        "SourcePort": "source.port",
                        "DestinationIp": "destination.address",
                        "DestinationIP": "destination.address",
                        "DestinationAddress": "destination.address",
                        "DestinationHostname": "destination.address",
                        "DestinationPort": "destination.port",
                        "DestAddress": "destination.address",
                        "DestPort": "destination.port",
                        "Protocol": "network.transport",
                    }
                ),
                rule_conditions=_category_conditions(NETWORK_CATEGORIES),
                rule_condition_linking=any,
            ),
            ProcessingItem(
                identifier="parseable_otlp_file_fields",
                transformation=FieldMappingTransformation(
                    {
                        "TargetFilename": "file.path",
                        "FileName": "file.path",
                        "FilePath": "file.path",
                    }
                ),
                rule_conditions=_category_conditions(FILE_CATEGORIES),
                rule_condition_linking=any,
            ),
            ProcessingItem(
                identifier="parseable_otlp_dns_fields",
                transformation=FieldMappingTransformation(
                    {
                        "QueryName": "dns.question.name",
                    }
                ),
                rule_conditions=[LogsourceCondition(category="dns_query")],
            ),
        ],
    )
