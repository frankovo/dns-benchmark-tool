import time
from typing import List

import pytest

from dns_benchmark.core import DNSQueryResult, QueryStatus


@pytest.fixture
def sample_results() -> List[DNSQueryResult]:
    now = time.time()
    return [
        DNSQueryResult(
            resolver_ip="1.1.1.1",
            resolver_name="Cloudflare",
            domain="example.com",
            record_type="A",
            start_time=now,
            end_time=now + 0.020,
            latency_ms=20.0,
            status=QueryStatus.SUCCESS,
            answers=["93.184.216.34"],
            ttl=300,
        ),
        DNSQueryResult(
            resolver_ip="8.8.8.8",
            resolver_name="Google",
            domain="example.com",
            record_type="A",
            start_time=now,
            end_time=now + 0.050,
            latency_ms=50.0,
            status=QueryStatus.SUCCESS,
            answers=["93.184.216.34"],
            ttl=300,
        ),
        DNSQueryResult(
            resolver_ip="9.9.9.9",
            resolver_name="Quad9",
            domain="bad-domain.test",
            record_type="A",
            start_time=now,
            end_time=now + 0.100,
            latency_ms=100.0,
            status=QueryStatus.NXDOMAIN,
            answers=[],
            ttl=None,
            error_message="Non-existent domain",
        ),
    ]
