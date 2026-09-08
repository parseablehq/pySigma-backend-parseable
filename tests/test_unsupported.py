import pytest
from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaFeatureNotSupportedByBackendError

from sigma.backends.parseable import ParseableBackend


def convert(source: str):
    return ParseableBackend(dataset="events").convert(SigmaCollection.from_yaml(source))


@pytest.mark.parametrize(
    ("modifier", "value", "message"),
    [
        ("minute", "5", "timestamp-part modifiers"),
        ("hour", "12", "timestamp-part modifiers"),
    ],
)
def test_unsupported_field_modifier_has_clear_error(modifier, value, message):
    source = f"""
title: Unsupported field modifier
logsource:
  category: test
detection:
  selection:
    field|{modifier}: {value}
  condition: selection
"""
    with pytest.raises(SigmaFeatureNotSupportedByBackendError, match=message):
        convert(source)


def test_correlation_rule_has_clear_error():
    source = """
title: Failed login
name: failed_login
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4625
  condition: selection
---
title: Failed-login burst
correlation:
  type: event_count
  rules: failed_login
  group-by: User
  timespan: 10m
  condition:
    gte: 10
"""
    with pytest.raises(SigmaFeatureNotSupportedByBackendError, match="correlation rules"):
        convert(source)
