import json
import time

import pytest

from dns_benchmark.core import (
    DNSQueryEngine,
    DNSQueryResult,
    DomainManager,
    QueryStatus,
    ResolverManager,
)


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

    async def fake_query_single(
        resolver_ip, resolver_name, domain, record_type="A", **kwargs
    ):
        return {
            "resolver_ip": resolver_ip,
            "resolver_name": resolver_name,
            "domain": domain,
            "record_type": record_type,
            "result": "ok",
        }

    monkeypatch.setattr(engine, "query_single", fake_query_single)

    resolvers = [{"name": "Google", "ip": "8.8.8.8"}]
    domains = ["example.com"]
    record_types = ["A", "AAAA"]

    results = await engine.run_benchmark(
        resolvers, domains, record_types, use_cache=True
    )

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


@pytest.mark.asyncio
async def test_query_single_cache_hit(monkeypatch):
    engine = DNSQueryEngine(enable_cache=True)

    # Create a fake cached result
    cached_result = DNSQueryResult(
        resolver_ip="1.1.1.1",
        resolver_name="Cloudflare",
        domain="example.com",
        record_type="A",
        start_time=time.time(),
        end_time=time.time(),
        latency_ms=1.0,
        status=QueryStatus.SUCCESS,
        answers=["1.2.3.4"],
        ttl=300,
    )
    cache_key = engine._get_cache_key("1.1.1.1", "example.com", "A")
    engine.cache[cache_key] = cached_result

    # Call query_single with use_cache=True
    result = await engine.query_single(
        resolver_ip="1.1.1.1",
        resolver_name="Cloudflare",
        domain="example.com",
        record_type="A",
        use_cache=True,
        iteration=2,
    )

    assert result.cache_hit is True
    assert result.iteration == 2
    assert result.answers == ["1.2.3.4"]


@pytest.mark.asyncio
async def test_query_single_fallback(monkeypatch):
    engine = DNSQueryEngine(max_retries=-1)  # force skip loop

    # Patch resolver.resolve to raise if called (but it won't be called)
    monkeypatch.setattr(
        "dns.asyncresolver.Resolver.resolve",
        lambda self, d, rt, raise_on_no_answer=False: (_ for _ in ()).throw(
            Exception("boom")
        ),
    )

    result = await engine.query_single(
        resolver_ip="8.8.8.8",
        resolver_name="Google",
        domain="example.com",
        record_type="A",
        use_cache=False,
        iteration=1,
    )

    assert result.status == QueryStatus.UNKNOWN_ERROR
    assert "Unexpected error" in result.error_message
    assert result.cache_hit is False


@pytest.mark.asyncio
async def test_run_benchmark_with_warmup(monkeypatch, capsys):
    engine = DNSQueryEngine()

    # Fake query_single that always returns SUCCESS
    async def fake_query_single(
        resolver_ip, resolver_name, domain, record_type="A", **kwargs
    ):
        return DNSQueryResult(
            resolver_ip=resolver_ip,
            resolver_name=resolver_name,
            domain=domain,
            record_type=record_type,
            start_time=0,
            end_time=0,
            latency_ms=0,
            status=QueryStatus.SUCCESS,
            answers=["dummy"],
            ttl=60,
            iteration=kwargs.get("iteration", 0),
            cache_hit=False,
        )

    monkeypatch.setattr(engine, "query_single", fake_query_single)

    resolvers = [{"name": "Google", "ip": "8.8.8.8"}]
    domains = ["example.com"]

    # Exercise the warmup branch
    results = await engine.run_benchmark(resolvers, domains, ["A"], warmup=True)
    assert all(r.status == QueryStatus.SUCCESS for r in results)


@pytest.mark.asyncio
async def test_run_benchmark_with_warmup_fast_and_failure(monkeypatch, capsys):
    engine = DNSQueryEngine()

    # Fake query_single that returns a failure status
    async def fake_query_single(
        resolver_ip, resolver_name, domain, record_type="A", **kwargs
    ):
        return DNSQueryResult(
            resolver_ip=resolver_ip,
            resolver_name=resolver_name,
            domain=domain,
            record_type=record_type,
            start_time=0,
            end_time=0,
            latency_ms=0,
            status=QueryStatus.TIMEOUT,  # force failure
            answers=[],
            ttl=None,
            iteration=kwargs.get("iteration", 0),
            cache_hit=False,
        )

    monkeypatch.setattr(engine, "query_single", fake_query_single)

    resolvers = [{"name": "Google", "ip": "8.8.8.8"}]
    domains = ["example.com"]

    # Exercise warmup_fast branch and failure reporting
    results = await engine.run_benchmark(resolvers, domains, ["A"], warmup_fast=True)

    # Capture printed warning
    captured = capsys.readouterr()
    assert "Warmup failed" in captured.out
    assert all(r.status == QueryStatus.TIMEOUT for r in results)


def test_clear_cache():
    engine = DNSQueryEngine(enable_cache=True)

    # Insert a fake cached result
    result = DNSQueryResult(
        resolver_ip="1.1.1.1",
        resolver_name="Cloudflare",
        domain="example.com",
        record_type="A",
        start_time=time.time(),
        end_time=time.time(),
        latency_ms=1.0,
        status=QueryStatus.SUCCESS,
        answers=["1.2.3.4"],
        ttl=300,
    )
    engine.cache["1.1.1.1:example.com:A"] = result

    assert len(engine.cache) == 1
    engine.clear_cache()
    assert len(engine.cache) == 0


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


def test_match_resolver_name_string():
    """Test _match_resolver_name with string name."""
    resolver = {"name": "Cloudflare", "ip": "1.1.1.1"}
    assert ResolverManager._match_resolver_name(resolver, "cloudflare")
    assert ResolverManager._match_resolver_name(resolver, "Cloudflare")
    assert ResolverManager._match_resolver_name(resolver, "CLOUDFLARE")
    assert not ResolverManager._match_resolver_name(resolver, "Google")


def test_match_resolver_name_sequence():
    """Test _match_resolver_name with sequence name."""
    resolver = {"name": ["Cloudflare", "CF"], "ip": "1.1.1.1"}
    assert ResolverManager._match_resolver_name(resolver, "cloudflare")
    assert ResolverManager._match_resolver_name(resolver, "Cloudflare")
    assert not ResolverManager._match_resolver_name(
        resolver, "CF"
    )  # Only matches first item


def test_match_resolver_name_empty():
    """Test _match_resolver_name with empty/missing name."""
    resolver = {"ip": "1.1.1.1"}
    assert not ResolverManager._match_resolver_name(resolver, "test")

    resolver = {"name": "", "ip": "1.1.1.1"}
    assert not ResolverManager._match_resolver_name(resolver, "test")


def test_parse_resolver_string_single_ipv4():
    """Test parsing single IPv4 address."""
    result = ResolverManager.parse_resolver_string("8.8.8.8")
    assert len(result) == 1
    assert result[0] == {"name": "8.8.8.8", "ip": "8.8.8.8"}


def test_parse_resolver_string_multiple_ipv4():
    """Test parsing multiple IPv4 addresses."""
    result = ResolverManager.parse_resolver_string("8.8.8.8,1.1.1.1,9.9.9.9")
    assert len(result) == 3
    assert result[0] == {"name": "8.8.8.8", "ip": "8.8.8.8"}
    assert result[1] == {"name": "1.1.1.1", "ip": "1.1.1.1"}
    assert result[2] == {"name": "9.9.9.9", "ip": "9.9.9.9"}


def test_parse_resolver_string_ipv6():
    """Test parsing IPv6 addresses."""
    result = ResolverManager.parse_resolver_string(
        "2606:4700:4700::1111,2001:4860:4860::8888"
    )
    assert len(result) == 2
    assert result[0] == {"name": "2606:4700:4700::1111", "ip": "2606:4700:4700::1111"}
    assert result[1] == {"name": "2001:4860:4860::8888", "ip": "2001:4860:4860::8888"}


def test_parse_resolver_string_named_resolvers(monkeypatch):
    """Test parsing named resolvers from database."""
    mock_db = [
        {"name": "Cloudflare", "ip": "1.1.1.1"},
        {"name": "Google", "ip": "8.8.8.8"},
    ]
    monkeypatch.setattr(ResolverManager, "RESOLVERS_DATABASE", mock_db)

    result = ResolverManager.parse_resolver_string("Cloudflare,Google")
    assert len(result) == 2
    assert result[0] == {"name": "Cloudflare", "ip": "1.1.1.1"}
    assert result[1] == {"name": "Google", "ip": "8.8.8.8"}


def test_parse_resolver_string_mixed():
    """Test parsing mixed IPs and named resolvers."""
    result = ResolverManager.parse_resolver_string("8.8.8.8,1.1.1.1")
    assert len(result) == 2
    assert result[0]["ip"] == "8.8.8.8"
    assert result[1]["ip"] == "1.1.1.1"


def test_parse_resolver_string_with_whitespace():
    """Test parsing with whitespace around commas."""
    result = ResolverManager.parse_resolver_string("8.8.8.8 , 1.1.1.1 , 9.9.9.9")
    assert len(result) == 3
    assert result[0]["ip"] == "8.8.8.8"
    assert result[1]["ip"] == "1.1.1.1"
    assert result[2]["ip"] == "9.9.9.9"


def test_parse_resolver_string_fallback():
    """Test fallback for unrecognized names (treated as hostnames)."""
    result = ResolverManager.parse_resolver_string("custom.dns.server")
    assert len(result) == 1
    assert result[0] == {"name": "custom.dns.server", "ip": "custom.dns.server"}


def test_parse_resolvers_input_empty():
    """Test that empty input raises ValueError."""
    with pytest.raises(ValueError, match="Resolver input cannot be empty"):
        ResolverManager.parse_resolvers_input("")

    with pytest.raises(ValueError, match="Resolver input cannot be empty"):
        ResolverManager.parse_resolvers_input(None)


def test_parse_resolvers_input_file_exists(tmp_path, monkeypatch):
    """Test parsing when input is an existing file path."""
    file_path = tmp_path / "resolvers.json"
    file_path.write_text('[{"name": "Test", "ip": "1.2.3.4"}]')

    # Mock load_resolvers_from_file to return expected format
    def mock_load(path):
        return [{"name": "Test", "ip": "1.2.3.4"}]

    monkeypatch.setattr(ResolverManager, "load_resolvers_from_file", mock_load)

    result = ResolverManager.parse_resolvers_input(str(file_path))
    assert len(result) == 1
    assert result[0]["name"] == "Test"
    assert result[0]["ip"] == "1.2.3.4"


def test_parse_resolvers_input_comma_separated():
    """Test parsing comma-separated resolvers."""
    result = ResolverManager.parse_resolvers_input("8.8.8.8,1.1.1.1")
    assert len(result) == 2
    assert result[0]["ip"] == "8.8.8.8"
    assert result[1]["ip"] == "1.1.1.1"


def test_parse_resolvers_input_single_ipv4():
    """Test parsing single IPv4 address."""
    result = ResolverManager.parse_resolvers_input("8.8.8.8")
    assert len(result) == 1
    assert result[0] == {"name": "8.8.8.8", "ip": "8.8.8.8"}


def test_parse_resolvers_input_single_ipv6():
    """Test parsing single IPv6 address."""
    result = ResolverManager.parse_resolvers_input("2606:4700:4700::1111")
    assert len(result) == 1
    assert result[0] == {"name": "2606:4700:4700::1111", "ip": "2606:4700:4700::1111"}


def test_parse_resolvers_input_named_resolver(monkeypatch):
    """Test parsing single named resolver from database."""
    mock_db = [
        {"name": "Cloudflare", "ip": "1.1.1.1"},
        {"name": "Google", "ip": "8.8.8.8"},
    ]
    monkeypatch.setattr(ResolverManager, "RESOLVERS_DATABASE", mock_db)

    result = ResolverManager.parse_resolvers_input("Cloudflare")
    assert len(result) == 1
    assert result[0] == {"name": "Cloudflare", "ip": "1.1.1.1"}


def test_parse_resolvers_input_named_resolver_case_insensitive(monkeypatch):
    """Test that named resolver lookup is case insensitive."""
    mock_db = [{"name": "Cloudflare", "ip": "1.1.1.1"}]
    monkeypatch.setattr(ResolverManager, "RESOLVERS_DATABASE", mock_db)

    result = ResolverManager.parse_resolvers_input("cloudflare")
    assert len(result) == 1
    assert result[0]["name"] == "Cloudflare"


def test_parse_resolvers_input_invalid():
    """Test that invalid input raises ValueError."""
    with pytest.raises(ValueError, match="Invalid resolver input"):
        ResolverManager.parse_resolvers_input("nonexistent-file-12345.txt")


def test_parse_resolvers_input_sequence_values(monkeypatch):
    """Test parsing when database values are sequences."""
    mock_db = [
        {"name": ["Cloudflare", "CF"], "ip": ["1.1.1.1", "1.0.0.1"]},
    ]
    monkeypatch.setattr(ResolverManager, "RESOLVERS_DATABASE", mock_db)

    # Test with parse_resolver_string
    result = ResolverManager.parse_resolver_string("Cloudflare")
    assert len(result) == 1
    assert result[0]["name"] == "Cloudflare"
    assert result[0]["ip"] == "1.1.1.1"

    # Test with parse_resolvers_input
    result = ResolverManager.parse_resolvers_input("Cloudflare")
    assert len(result) == 1
    assert result[0]["name"] == "Cloudflare"
    assert result[0]["ip"] == "1.1.1.1"


def test_parse_resolvers_input_whitespace_handling():
    """Test that leading/trailing whitespace is handled."""
    result = ResolverManager.parse_resolvers_input("  8.8.8.8,1.1.1.1  ")
    assert len(result) == 2
    assert result[0]["ip"] == "8.8.8.8"


def test_parse_domain_string_single():
    """Test parsing single domain."""
    result = DomainManager.parse_domain_string("google.com")
    assert result == ["google.com"]


def test_parse_domain_string_multiple():
    """Test parsing multiple domains."""
    result = DomainManager.parse_domain_string("google.com,github.com,example.com")
    assert len(result) == 3
    assert "google.com" in result
    assert "github.com" in result
    assert "example.com" in result


def test_parse_domain_string_with_whitespace():
    """Test parsing domains with whitespace around commas."""
    result = DomainManager.parse_domain_string("google.com , github.com , example.com")
    assert len(result) == 3
    assert "google.com" in result
    assert "github.com" in result
    assert "example.com" in result


def test_parse_domain_string_mixed_case():
    """Test that domains are lowercased."""
    result = DomainManager.parse_domain_string("Google.com,GitHub.COM,Example.Com")
    assert len(result) == 3
    assert "google.com" in result
    assert "github.com" in result
    assert "example.com" in result


def test_parse_domain_string_trailing_dots():
    """Test that trailing dots (FQDN) are removed."""
    result = DomainManager.parse_domain_string("google.com.,github.com.,example.com.")
    assert len(result) == 3
    assert "google.com" in result
    assert "github.com" in result
    assert "example.com" in result


def test_parse_domain_string_duplicates():
    """Test that duplicates are removed while preserving order."""
    result = DomainManager.parse_domain_string(
        "google.com,github.com,google.com,example.com"
    )
    assert len(result) == 3
    assert result == ["google.com", "github.com", "example.com"]


def test_parse_domain_string_idn():
    """Test IDN (International Domain Name) handling."""
    result = DomainManager.parse_domain_string("münchen.de")
    # Should be converted to punycode
    assert len(result) == 1
    assert "xn--" in result[0] or "münchen.de" in result[0]


def test_parse_domain_string_empty_parts():
    """Test that empty parts are ignored."""
    result = DomainManager.parse_domain_string("google.com,,github.com,  ,example.com")
    assert len(result) == 3
    assert "google.com" in result
    assert "github.com" in result
    assert "example.com" in result


def test_parse_domain_string_short_domains():
    """Test handling of short/odd domains."""
    result = DomainManager.parse_domain_string("a.b,example.com")
    # Short domains are still included
    assert len(result) == 2


def test_parse_domains_input_empty():
    """Test that empty input raises ValueError."""
    with pytest.raises(ValueError, match="Domain input cannot be empty"):
        DomainManager.parse_domains_input("")

    with pytest.raises(ValueError, match="Domain input cannot be empty"):
        DomainManager.parse_domains_input(None)


def test_parse_domains_input_file_exists(tmp_path):
    """Test parsing when input is an existing file path."""
    file_path = tmp_path / "domains.txt"
    file_path.write_text("google.com\ngithub.com\nexample.com\n")

    result = DomainManager.parse_domains_input(str(file_path))
    assert len(result) == 3
    assert "google.com" in result
    assert "github.com" in result
    assert "example.com" in result


def test_parse_domains_input_comma_separated():
    """Test parsing comma-separated domains."""
    result = DomainManager.parse_domains_input("google.com,github.com,example.com")
    assert len(result) == 3
    assert "google.com" in result
    assert "github.com" in result
    assert "example.com" in result


def test_parse_domains_input_single_domain():
    """Test parsing single domain."""
    result = DomainManager.parse_domains_input("google.com")
    assert result == ["google.com"]


def test_parse_domains_input_single_domain_case():
    """Test that single domain is lowercased and stripped."""
    result = DomainManager.parse_domains_input("  Google.COM  ")
    assert result == ["google.com"]


def test_parse_domains_input_file_not_found():
    """Test that non-existent file raises FileNotFoundError."""
    with pytest.raises(FileNotFoundError):
        DomainManager.parse_domains_input(
            "nonexistent-file-12345"
        )  # No dot, so won't be treated as domain


def test_parse_domains_input_file_with_comments(tmp_path):
    """Test that comments in file are ignored."""
    file_path = tmp_path / "domains.txt"
    file_path.write_text(
        "# This is a comment\ngoogle.com\n# Another comment\ngithub.com\n"
    )

    result = DomainManager.parse_domains_input(str(file_path))
    assert len(result) == 2
    assert "google.com" in result
    assert "github.com" in result


def test_parse_domains_input_file_with_empty_lines(tmp_path):
    """Test that empty lines in file are ignored."""
    file_path = tmp_path / "domains.txt"
    file_path.write_text("google.com\n\n\ngithub.com\n\n")

    result = DomainManager.parse_domains_input(str(file_path))
    assert len(result) == 2
    assert "google.com" in result
    assert "github.com" in result


def test_parse_domains_input_whitespace_handling():
    """Test that leading/trailing whitespace is handled."""
    result = DomainManager.parse_domains_input("  google.com,github.com  ")
    assert len(result) == 2
    assert "google.com" in result
    assert "github.com" in result


def test_get_sample_domains():
    """Test that sample domains returns expected list."""
    result = DomainManager.get_sample_domains()
    assert isinstance(result, list)
    assert len(result) > 0
    assert "google.com" in result
    assert "github.com" in result


def test_load_domains_from_file(tmp_path):
    """Test loading domains from file."""
    file_path = tmp_path / "domains.txt"
    file_path.write_text("google.com\ngithub.com\nexample.com\n")

    result = DomainManager.load_domains_from_file(str(file_path))
    assert len(result) == 3
    assert "google.com" in result
    assert "github.com" in result
    assert "example.com" in result


def test_get_all_domains():
    """Test getting all domains from database."""
    result = DomainManager.get_all_domains()
    assert isinstance(result, list)
    # Should return the database
    assert result == DomainManager.DOMAINS_DATABASE


def test_get_domains_by_category():
    """Test filtering domains by category."""
    result = DomainManager.get_domains_by_category("popular")
    assert isinstance(result, list)
    # All returned domains should have the requested category
    for domain in result:
        assert domain.get("category") == "popular"


def test_get_categories():
    """Test getting all domain categories."""
    result = DomainManager.get_categories()
    assert isinstance(result, list)
    assert len(result) > 0
    # Should be sorted
    assert result == sorted(result)


def test_parse_domain_string_no_dots():
    """Test handling of domains without dots."""
    result = DomainManager.parse_domain_string("localhost,example.com")
    # Should still include items without dots
    assert len(result) == 2
    assert "localhost" in result
    assert "example.com" in result
