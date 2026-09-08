"""Canonical generic Windows log-source mappings for native Sysmon events."""

from sigma.processing.conditions import LogsourceCondition
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.processing.transformations import AddConditionTransformation

SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"
SYSMON_EVENT_IDS: dict[str, int | list[int]] = {
    "process_creation": 1,
    "file_change": 2,
    "network_connection": 3,
    "sysmon_status": [4, 16],
    "process_termination": 5,
    "driver_load": 6,
    "image_load": 7,
    "create_remote_thread": 8,
    "raw_access_thread": 9,
    "process_access": 10,
    "file_event": 11,
    "registry_add": 12,
    "registry_delete": 12,
    "registry_set": 13,
    "registry_rename": 14,
    "registry_event": [12, 13, 14],
    "create_stream_hash": 15,
    "pipe_created": [17, 18],
    "wmi_event": [19, 20, 21],
    "dns_query": 22,
    "file_delete": 23,
    "clipboard_capture": 24,
    "process_tampering": 25,
    "file_delete_detected": 26,
    "file_block_executable": 27,
    "file_block_shredding": 28,
    "file_executable_detected": 29,
    "sysmon_error": 255,
}


def parseable_sysmon_pipeline() -> ProcessingPipeline:
    """Add native Sysmon channel and event IDs to generic Windows Sigma rules."""
    return ProcessingPipeline(
        name="Parseable native Sysmon log-source mappings",
        priority=10,
        allowed_backends=frozenset({"parseable"}),
        items=[
            ProcessingItem(
                identifier=f"parseable_sysmon_{category}",
                transformation=AddConditionTransformation(
                    {
                        "Channel": SYSMON_CHANNEL,
                        "EventID": event_ids,
                    }
                ),
                rule_conditions=[
                    LogsourceCondition(product="windows", category=category)
                ],
            )
            for category, event_ids in SYSMON_EVENT_IDS.items()
        ],
    )
