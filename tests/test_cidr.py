from sigma.collection import SigmaCollection

from sigma.backends.parseable import ParseableBackend


def convert(cidr: str) -> str:
    source = f"""
title: CIDR test
logsource:
  category: network_connection
detection:
  selection:
    SourceIp|cidr: {cidr}
  condition: selection
"""
    return ParseableBackend().convert(
        SigmaCollection.from_yaml(source), output_format="predicate"
    )[0]


def test_ipv4_cidr_uses_parseable_udf():
    assert convert("192.168.0.0/16") == 'ip_in_cidr("SourceIp", \'192.168.0.0/16\')'


def test_ipv6_cidr_uses_parseable_udf():
    assert convert("2001:db8::/32") == 'ip_in_cidr("SourceIp", \'2001:db8::/32\')'
