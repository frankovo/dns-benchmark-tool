"""
Tests for DoH, DoT, and DNSSEC additions.
"""

import asyncio
import time
from unittest.mock import AsyncMock, MagicMock, patch

import dns.flags
import dns.message
import dns.name
import dns.rdatatype
import pytest

from dns_benchmark.core import (
    DNSQueryEngine,
    DNSQueryResult,
    QueryProtocol,
    QueryStatus,
)


@pytest.fixture
def engine() -> DNSQueryEngine:
    return DNSQueryEngine(
        timeout=5.0,
        max_retries=0,
        enable_dnssec=True,
        enforce_dnssec=False,
    )


@pytest.fixture
def engine_enforced() -> DNSQueryEngine:
    return DNSQueryEngine(
        timeout=5.0,
        max_retries=0,
        enable_dnssec=True,
        enforce_dnssec=True,
    )


def _make_dns_wire_response(domain: str = "google.com", ad: bool = False) -> bytes:
    """Build a minimal valid DNS wire response for mocking."""
    qname = dns.name.from_text(domain)
    rdtype = dns.rdatatype.from_text("A")
    request = dns.message.make_query(qname, rdtype)
    response = dns.message.make_response(request)
    response.flags |= dns.flags.QR | dns.flags.RA
    if ad:
        response.flags |= dns.flags.AD
    # Add a minimal A record answer
    rrset = response.find_rrset(
        response.answer,
        qname,
        dns.rdataclass.IN,
        dns.rdatatype.A,
        create=True,
    )
    rrset.add(
        dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.A, "1.2.3.4"), ttl=300
    )
    return response.to_wire()


def test_query_protocol_values() -> None:
    assert QueryProtocol.PLAIN.value == "plain"
    assert QueryProtocol.DOH.value == "doh"
    assert QueryProtocol.DOT.value == "dot"


def test_dnssec_failed_status_exists() -> None:
    assert QueryStatus.DNSSEC_FAILED.value == "dnssec_failed"


def test_result_default_fields(engine: DNSQueryEngine) -> None:
    """protocol and dnssec_validated have correct defaults."""
    import time

    from dns_benchmark.core import DNSQueryResult

    result = DNSQueryResult(
        resolver_ip="1.1.1.1",
        resolver_name="Cloudflare",
        domain="example.com",
        record_type="A",
        start_time=time.time(),
        end_time=time.time(),
        latency_ms=10.0,
        status=QueryStatus.SUCCESS,
        answers=["1.2.3.4"],
        ttl=300,
    )
    assert result.protocol == QueryProtocol.PLAIN
    assert result.dnssec_validated is False


def test_result_to_dict_includes_protocol() -> None:
    result = DNSQueryResult(
        resolver_ip="1.1.1.1",
        resolver_name="Cloudflare",
        domain="example.com",
        record_type="A",
        start_time=time.time(),
        end_time=time.time(),
        latency_ms=10.0,
        status=QueryStatus.SUCCESS,
        answers=[],
        ttl=None,
        protocol=QueryProtocol.DOH,
        dnssec_validated=True,
    )
    d = result.to_dict()
    assert d["protocol"] == "doh"
    assert d["dnssec_validated"] is True


@pytest.mark.asyncio
async def test_query_single_doh_success(engine: DNSQueryEngine) -> None:
    wire = _make_dns_wire_response("google.com", ad=False)

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.content = wire
    mock_response.raise_for_status = MagicMock()

    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.post = AsyncMock(return_value=mock_response)

    with patch("dns_benchmark.core.httpx.AsyncClient", return_value=mock_client):
        result = await engine.query_single_doh(
            resolver_ip="1.1.1.1",
            resolver_name="Cloudflare",
            domain="google.com",
            doh_url="https://cloudflare-dns.com/dns-query",
        )

    assert result.status == QueryStatus.SUCCESS
    assert result.protocol == QueryProtocol.DOH
    assert result.latency_ms > 0
    assert result.answers == ["1.2.3.4"]


@pytest.mark.asyncio
async def test_query_single_doh_ad_flag(engine: DNSQueryEngine) -> None:
    wire = _make_dns_wire_response("cloudflare.com", ad=True)

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.content = wire
    mock_response.raise_for_status = MagicMock()

    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.post = AsyncMock(return_value=mock_response)

    with patch("dns_benchmark.core.httpx.AsyncClient", return_value=mock_client):
        result = await engine.query_single_doh(
            resolver_ip="1.1.1.1",
            resolver_name="Cloudflare",
            domain="cloudflare.com",
            doh_url="https://cloudflare-dns.com/dns-query",
        )

    assert result.dnssec_validated is True
    assert result.status == QueryStatus.SUCCESS


@pytest.mark.asyncio
async def test_query_single_doh_enforced_no_ad(engine_enforced: DNSQueryEngine) -> None:
    """enforce_dnssec=True + AD absent → DNSSEC_FAILED."""
    wire = _make_dns_wire_response("google.com", ad=False)

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.content = wire
    mock_response.raise_for_status = MagicMock()

    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.post = AsyncMock(return_value=mock_response)

    with patch("dns_benchmark.core.httpx.AsyncClient", return_value=mock_client):
        result = await engine_enforced.query_single_doh(
            resolver_ip="1.1.1.1",
            resolver_name="Cloudflare",
            domain="google.com",
            doh_url="https://cloudflare-dns.com/dns-query",
        )

    assert result.status == QueryStatus.DNSSEC_FAILED
    assert result.dnssec_validated is False


@pytest.mark.asyncio
async def test_query_single_doh_timeout(engine: DNSQueryEngine) -> None:
    import httpx

    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.post = AsyncMock(side_effect=httpx.TimeoutException("timeout"))

    with patch("dns_benchmark.core.httpx.AsyncClient", return_value=mock_client):
        result = await engine.query_single_doh(
            resolver_ip="1.1.1.1",
            resolver_name="Cloudflare",
            domain="google.com",
            doh_url="https://cloudflare-dns.com/dns-query",
        )

    assert result.status == QueryStatus.TIMEOUT
    assert result.protocol == QueryProtocol.DOH


@pytest.mark.asyncio
async def test_query_single_dot_success(engine: DNSQueryEngine) -> None:
    import struct

    wire = _make_dns_wire_response("google.com", ad=False)
    # reader returns 2-byte length then message
    length_bytes = struct.pack("!H", len(wire))

    mock_reader = AsyncMock()
    mock_reader.readexactly = AsyncMock(side_effect=[length_bytes, wire])

    mock_writer = MagicMock()
    mock_writer.write = MagicMock()
    mock_writer.drain = AsyncMock()
    mock_writer.close = MagicMock()
    mock_writer.wait_closed = AsyncMock()
    mock_writer.get_extra_info = MagicMock(return_value=None)

    with (
        patch(
            "dns_benchmark.core.asyncio.open_connection",
            new=AsyncMock(return_value=(mock_reader, mock_writer)),
        ),
        patch(
            "dns_benchmark.core.asyncio.wait_for",
            side_effect=[
                (mock_reader, mock_writer),
                length_bytes,  # readexactly(2)
                wire,  # readexactly(msg_len)
            ],
        ),
    ):
        result = await engine.query_single_dot(
            resolver_ip="1.1.1.1",
            resolver_name="Cloudflare",
            domain="google.com",
        )

    assert result.status == QueryStatus.SUCCESS
    assert result.protocol == QueryProtocol.DOT
    assert result.answers == ["1.2.3.4"]


@pytest.mark.asyncio
async def test_query_single_dot_tls_error(engine: DNSQueryEngine) -> None:
    import ssl

    ssl_error = ssl.SSLError("cert verify failed")

    with patch(
        "dns_benchmark.core.asyncio.open_connection",
        side_effect=ssl_error,
    ):
        result = await engine.query_single_dot(
            resolver_ip="1.1.1.1",
            resolver_name="Cloudflare",
            domain="google.com",
        )

    assert result.status == QueryStatus.TLS_ERROR
    assert result.protocol == QueryProtocol.DOT
    assert "TLS error" in (result.error_message or "")


@pytest.mark.asyncio
async def test_query_single_dot_timeout(engine: DNSQueryEngine) -> None:
    mock_connect = AsyncMock(
        side_effect=asyncio.TimeoutError("simulated connection timeout")
    )

    with patch(
        "dns_benchmark.core.asyncio.open_connection",
        new=mock_connect,
    ):
        result = await engine.query_single_dot(
            resolver_ip="1.1.1.1",
            resolver_name="Cloudflare",
            domain="google.com",
        )

    assert result.status == QueryStatus.TIMEOUT
    assert result.protocol == QueryProtocol.DOT


@pytest.mark.asyncio
async def test_run_benchmark_dispatches_doh(engine: DNSQueryEngine) -> None:
    mock_result = MagicMock()
    engine.query_single_doh = AsyncMock(return_value=mock_result)  # type: ignore

    await engine.run_benchmark(
        resolvers=[{"ip": "1.1.1.1", "name": "Cloudflare"}],
        domains=["google.com"],
        protocol=QueryProtocol.DOH,
        doh_urls={"1.1.1.1": "https://cloudflare-dns.com/dns-query"},
    )

    engine.query_single_doh.assert_called_once()
    call_kwargs = engine.query_single_doh.call_args.kwargs
    assert call_kwargs["doh_url"] == "https://cloudflare-dns.com/dns-query"


@pytest.mark.asyncio
async def test_run_benchmark_dispatches_dot(engine: DNSQueryEngine) -> None:
    mock_result = MagicMock()
    engine.query_single_dot = AsyncMock(return_value=mock_result)  # type: ignore

    await engine.run_benchmark(
        resolvers=[{"ip": "1.1.1.1", "name": "Cloudflare"}],
        domains=["google.com"],
        protocol=QueryProtocol.DOT,
    )

    engine.query_single_dot.assert_called_once()


@pytest.mark.asyncio
async def test_run_benchmark_dispatches_plain(engine: DNSQueryEngine) -> None:
    mock_result = MagicMock()
    engine.query_single = AsyncMock(return_value=mock_result)  # type: ignore

    await engine.run_benchmark(
        resolvers=[{"ip": "1.1.1.1", "name": "Cloudflare"}],
        domains=["google.com"],
        protocol=QueryProtocol.PLAIN,
    )

    engine.query_single.assert_called_once()


@pytest.mark.asyncio
async def test_dnssec_passive_no_status_change(engine: DNSQueryEngine) -> None:
    """AD=False with enforce_dnssec=False must NOT flip status to DNSSEC_FAILED."""
    wire = _make_dns_wire_response("google.com", ad=False)

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.content = wire
    mock_response.raise_for_status = MagicMock()

    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.post = AsyncMock(return_value=mock_response)

    with patch("dns_benchmark.core.httpx.AsyncClient", return_value=mock_client):
        result = await engine.query_single_doh(
            resolver_ip="1.1.1.1",
            resolver_name="Cloudflare",
            domain="google.com",
            doh_url="https://cloudflare-dns.com/dns-query",
        )

    # passive: status stays SUCCESS, dnssec_validated reflects reality
    assert result.status == QueryStatus.SUCCESS
    assert result.dnssec_validated is False
