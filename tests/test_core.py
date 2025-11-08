import json

import pytest

from dns_benchmark.core import DNSQueryEngine, QueryStatus, ResolverManager


class DummyDomain:
    def __init__(self, domain_name, name_server):
        self.domain_name = domain_name
        self.name_server = name_server


@pytest.mark.asyncio
async def test_query_success(monkeypatch):
    engine = DNSQueryEngine(max_concurrent_queries=1, timeout=0.1, max_retries=0)

    class FakeRRset(list):
        ttl = 300

    class FakeResponse:
        rrset = FakeRRset(["1.2.3.4"])

    async def fake_resolve(self, d, rt, raise_on_no_answer=False):
        return FakeResponse()

    monkeypatch.setattr("dns.asyncresolver.Resolver.resolve", fake_resolve)

    result = await engine.query_single("1.1.1.1", "Cloudflare", "example.com")
    assert result.status == QueryStatus.SUCCESS
    assert result.answers == ["1.2.3.4"]
    assert result.ttl == 300


@pytest.mark.asyncio
async def test_query_timeout(monkeypatch):
    engine = DNSQueryEngine(max_concurrent_queries=1, timeout=0.1, max_retries=0)

    import dns.exception

    # Patch Resolver.resolve to raise Timeout
    monkeypatch.setattr(
        "dns.asyncresolver.Resolver.resolve",
        lambda self, d, rt, raise_on_no_answer: (_ for _ in ()).throw(
            dns.exception.Timeout()
        ),
    )

    result = await engine.query_single("1.1.1.1", "Cloudflare", "example.com")
    assert result.status == QueryStatus.TIMEOUT
    assert "timeout" in result.error_message.lower()


@pytest.mark.asyncio
async def test_query_nxdomain(monkeypatch):
    engine = DNSQueryEngine(max_concurrent_queries=1, timeout=0.1, max_retries=0)

    import dns.resolver

    monkeypatch.setattr(
        "dns.asyncresolver.Resolver.resolve",
        lambda self, d, rt, raise_on_no_answer: (_ for _ in ()).throw(
            dns.resolver.NXDOMAIN()
        ),
    )

    result = await engine.query_single("8.8.8.8", "Google", "bad-domain.test")
    assert result.status == QueryStatus.NXDOMAIN


@pytest.mark.asyncio
async def test_query_nonameservers(monkeypatch):
    engine = DNSQueryEngine(max_concurrent_queries=1, timeout=0.1, max_retries=0)

    import dns.resolver

    monkeypatch.setattr(
        "dns.asyncresolver.Resolver.resolve",
        lambda self, d, rt, raise_on_no_answer: (_ for _ in ()).throw(
            dns.resolver.NoNameservers()
        ),
    )

    result = await engine.query_single("9.9.9.9", "Quad9", "example.com")
    assert result.status == QueryStatus.SERVFAIL


@pytest.mark.asyncio
async def test_query_connection_refused(monkeypatch):
    engine = DNSQueryEngine(max_concurrent_queries=1, timeout=0.1, max_retries=0)

    monkeypatch.setattr(
        "dns.asyncresolver.Resolver.resolve",
        lambda self, d, rt, raise_on_no_answer: (_ for _ in ()).throw(
            Exception("Connection refused")
        ),
    )

    result = await engine.query_single("208.67.222.222", "OpenDNS", "example.com")
    assert result.status == QueryStatus.CONNECTION_REFUSED


@pytest.mark.asyncio
async def test_query_unexpected(monkeypatch):
    engine = DNSQueryEngine(max_concurrent_queries=1, timeout=0.1, max_retries=0)

    # Force a generic exception
    monkeypatch.setattr(
        "dns.asyncresolver.Resolver.resolve",
        lambda self, d, rt, raise_on_no_answer: (_ for _ in ()).throw(
            Exception("Some random error")
        ),
    )

    result = await engine.query_single("1.1.1.1", "Cloudflare", "example.com")
    assert result.status == QueryStatus.UNKNOWN_ERROR
    assert "error" in result.error_message.lower()


@pytest.mark.asyncio
async def test_run_benchmark(monkeypatch):
    engine = DNSQueryEngine(max_concurrent_queries=1, timeout=0.1, max_retries=0)

    async def fake_query_single(resolver_ip, resolver_name, domain, record_type="A"):
        return {
            "resolver_ip": resolver_ip,
            "resolver_name": resolver_name,
            "domain": domain,
            "record_type": record_type,
            "result": "ok",
        }

    monkeypatch.setattr(engine, "query_single", fake_query_single)

    # ✅ Use "ip" instead of "resolver"
    resolvers = [{"name": "Google", "ip": "8.8.8.8"}]
    domains = ["example.com"]
    record_types = ["A", "AAAA"]

    results = await engine.run_benchmark(resolvers, domains, record_types)

    assert len(results) == len(resolvers) * len(domains) * len(record_types)
    assert results[0]["result"] == "ok"


@pytest.mark.asyncio
async def test_run_benchmark_empty_record_types(monkeypatch):
    engine = DNSQueryEngine(max_concurrent_queries=1, timeout=0.1, max_retries=0)

    async def fake_query_single(*args, **kwargs):
        return {"result": "ok"}

    monkeypatch.setattr(engine, "query_single", fake_query_single)

    resolvers = [{"name": "Google", "ip": "8.8.8.8"}]
    domains = ["example.com"]

    # record_types=None triggers default ["A"]
    results = await engine.run_benchmark(resolvers, domains, None)

    assert len(results) == 1
    assert results[0]["result"] == "ok"


def test_get_default_resolvers():
    resolvers = ResolverManager.get_default_resolvers()
    assert isinstance(resolvers, list)
    assert all("name" in r and "ip" in r for r in resolvers)
    names = [r["name"] for r in resolvers]
    assert "Cloudflare" in names
    assert "Google" in names


def test_load_resolvers_from_file(tmp_path):
    data = {
        "resolvers": [
            {"name": "TestDNS", "ip": "123.45.67.89"},
            {"name": "AnotherDNS", "ip": "98.76.54.32"},
        ]
    }
    file_path = tmp_path / "resolvers.json"
    file_path.write_text(json.dumps(data))

    resolvers = ResolverManager.load_resolvers_from_file(str(file_path))
    assert isinstance(resolvers, list)
    assert resolvers[0]["name"] == "TestDNS"
    assert resolvers[0]["ip"] == "123.45.67.89"
    assert resolvers[1]["name"] == "AnotherDNS"
