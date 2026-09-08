"""Built-in schema mappings for the Parseable backend."""

from .ecs import parseable_ecs_pipeline
from .otlp import parseable_otlp_pipeline
from .sysmon import parseable_sysmon_pipeline

pipelines = {
    "parseable_otlp": parseable_otlp_pipeline,
    "parseable_ecs": parseable_ecs_pipeline,
    "parseable_sysmon": parseable_sysmon_pipeline,
}

__all__ = [
    "parseable_ecs_pipeline",
    "parseable_otlp_pipeline",
    "parseable_sysmon_pipeline",
]
