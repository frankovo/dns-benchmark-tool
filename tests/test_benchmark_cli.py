import csv
import importlib.util
import json
import re
import tempfile
import time
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import click
import pytest
from click.testing import CliRunner

from dns_benchmark.cli import (
    _resolve_protocol_and_doh_urls,
    cli,
    create_progress_bar,
)
from dns_benchmark.core import DNSQueryResult, QueryProtocol, QueryStatus


@pytest.fixture
def runner():
    return CliRunner()


@pytest.fixture
def temp_config_dir(monkeypatch):
    """Use a temporary directory for feedback state."""
    tmpdir = tempfile.TemporaryDirectory()
    monkeypatch.setattr(Path, "home", lambda: Path(tmpdir.name))
    yield Path(tmpdir.name)
    tmpdir.cleanup()


def test_protocol_plain():
    """Neither --doh nor --dot -> plain DNS, empty URL map."""
    protocol, url_map = _resolve_protocol_and_doh_urls(
        doh=False, dot=False, doh_url=None, resolvers=[]
    )
    assert protocol == QueryProtocol.PLAIN
    assert url_map == {}


def test_protocol_dot():
    """--dot -> DoT protocol, empty URL map."""
    protocol, url_map = _resolve_protocol_and_doh_urls(
        doh=False, dot=True, doh_url=None, resolvers=[]
    )
    assert protocol == QueryProtocol.DOT
    assert url_map == {}


def test_protocol_mutual_exclusion():
    """--doh and --dot together raise UsageError."""
    with pytest.raises(
        click.UsageError, match="--doh and --dot are mutually exclusive."
    ):
        _resolve_protocol_and_doh_urls(doh=True, dot=True, doh_url=None, resolvers=[])


def test_doh_explicit_urls():
    """--doh with --doh-url list matching resolver count."""
    resolvers = [
        {"name": "Google", "ip": "8.8.8.8"},
        {"name": "Cloudflare", "ip": "1.1.1.1"},
    ]
    doh_url = "https://dns.google/dns-query, https://cloudflare-dns.com/dns-query"
    protocol, url_map = _resolve_protocol_and_doh_urls(
        doh=True, dot=False, doh_url=doh_url, resolvers=resolvers
    )
    assert protocol == QueryProtocol.DOH
    assert url_map == {
        "8.8.8.8": "https://dns.google/dns-query",
        "1.1.1.1": "https://cloudflare-dns.com/dns-query",
    }


def test_doh_url_length_mismatch():
    """Number of explicit URLs must match resolver count."""
    resolvers = [
        {"name": "Google", "ip": "8.8.8.8"},
        {"name": "Cloudflare", "ip": "1.1.1.1"},
    ]
    with pytest.raises(
        click.UsageError,
        match="--doh-url has 1 URL\\(s\\) but --resolvers has 2 resolver\\(s\\). Counts must match.",
    ):
        _resolve_protocol_and_doh_urls(
            doh=True,
            dot=False,
            doh_url="https://dns.google/dns-query",
            resolvers=resolvers,
        )


def test_doh_fallback_to_database(monkeypatch):
    """Use doh_url from RESOLVERS_DATABASE when --doh-url is omitted."""
    # Mock the internal resolver database
    fake_db = [
        {"ip": "8.8.8.8", "name": "Google", "doh_url": "https://dns.google/dns-query"},
        {
            "ip": "1.1.1.1",
            "name": "Cloudflare",
            "doh_url": "https://cloudflare-dns.com/dns-query",
        },
    ]
    monkeypatch.setattr("dns_benchmark.cli.ResolverManager.RESOLVERS_DATABASE", fake_db)

    resolvers = [
        {"name": "Google", "ip": "8.8.8.8"},
        {"name": "Cloudflare", "ip": "1.1.1.1"},
    ]
    protocol, url_map = _resolve_protocol_and_doh_urls(
        doh=True, dot=False, doh_url=None, resolvers=resolvers
    )
    assert protocol == QueryProtocol.DOH
    assert url_map == {
        "8.8.8.8": "https://dns.google/dns-query",
        "1.1.1.1": "https://cloudflare-dns.com/dns-query",
    }


def test_doh_fallback_missing_url(monkeypatch):
    """Resolver without doh_url in database raises error."""
    fake_db = [
        {"ip": "8.8.8.8", "name": "Google", "doh_url": "https://dns.google/dns-query"},
        {"ip": "9.9.9.9", "name": "Quad9"},  # No doh_url
    ]
    monkeypatch.setattr("dns_benchmark.cli.ResolverManager.RESOLVERS_DATABASE", fake_db)

    resolvers = [
        {"name": "Google", "ip": "8.8.8.8"},
        {"name": "Quad9", "ip": "9.9.9.9"},
    ]
    with pytest.raises(
        click.UsageError,
        match="--doh requires a DoH URL for: Quad9. Use --doh-url to supply them explicitly.",
    ):
        _resolve_protocol_and_doh_urls(
            doh=True, dot=False, doh_url=None, resolvers=resolvers
        )


def test_doh_fallback_resolver_not_in_db(monkeypatch):
    """Resolver not found in database at all raises error (missing doh_url)."""
    fake_db = [
        {
            "ip": "1.1.1.1",
            "name": "Cloudflare",
            "doh_url": "https://cloudflare-dns.com/dns-query",
        },
    ]
    monkeypatch.setattr("dns_benchmark.cli.ResolverManager.RESOLVERS_DATABASE", fake_db)

    resolvers = [
        {"name": "Unknown", "ip": "192.0.2.1"},
    ]
    with pytest.raises(
        click.UsageError,
        match="--doh requires a DoH URL for: Unknown. Use --doh-url to supply them explicitly.",
    ):
        _resolve_protocol_and_doh_urls(
            doh=True, dot=False, doh_url=None, resolvers=resolvers
        )


def test_cli_configuration_and_warmup(monkeypatch):
    runner = CliRunner()

    # Patch managers to return dummy data
    monkeypatch.setattr(
        "dns_benchmark.cli.ResolverManager.get_default_resolvers",
        lambda: [{"name": "Google", "ip": "8.8.8.8"}],
    )
    monkeypatch.setattr(
        "dns_benchmark.cli.DomainManager.get_sample_domains", lambda: ["example.com"]
    )

    # Patch engine.run_benchmark to be async
    class DummyResult:
        cache_hit = False

    async def fake_run_benchmark(*a, **k):
        return [DummyResult()]

    monkeypatch.setattr(
        "dns_benchmark.cli.DNSQueryEngine.run_benchmark", fake_run_benchmark
    )

    # Patch BenchmarkAnalyzer to return dummy stats
    class DummyAnalyzer:
        def __init__(self, results):
            pass

        def get_overall_statistics(self):
            return {
                "total_queries": 1,
                "successful_queries": 1,
                "overall_success_rate": 100.0,
                "overall_avg_latency": 1.0,
                "overall_median_latency": 1.0,
                "fastest_resolver": "Google",
                "slowest_resolver": "Google",
            }

    monkeypatch.setattr("dns_benchmark.cli.BenchmarkAnalyzer", DummyAnalyzer)

    result = runner.invoke(cli, ["benchmark", "--use-defaults", "--warmup"])
    assert "Configuration:" in result.output
    assert "Running full warmup queries..." in result.output
    assert "=== BENCHMARK SUMMARY ===" in result.output


def test_benchmark_exports_csv_excel_pdf_json(tmp_path, sample_results):
    runner = CliRunner()
    outdir = tmp_path / "results"

    with patch(
        "dns_benchmark.core.DNSQueryEngine.run_benchmark", return_value=sample_results
    ):
        with (
            patch(
                "dns_benchmark.core.ResolverManager.get_default_resolvers",
                return_value=[
                    {"name": "Cloudflare", "ip": "1.1.1.1"},
                    {"name": "Google", "ip": "8.8.8.8"},
                ],
            ),
            patch(
                "dns_benchmark.core.DomainManager.get_sample_domains",
                return_value=["example.com", "bad-domain.test"],
            ),
        ):
            result = runner.invoke(
                cli,
                [
                    "benchmark",
                    "--use-defaults",
                    "--formats",
                    "csv,excel,pdf",
                    "--json",
                    "--domain-stats",
                    "--record-type-stats",
                    "--error-breakdown",
                    "--output",
                    str(outdir),
                    "--quiet",
                ],
            )
            assert result.exit_code == 0, f"CLI failed: {result.output}"

    # Verify outputs
    files = list(outdir.glob("dns_benchmark_*.json"))
    assert files, "JSON export missing"
    json_path = files[0]

    # CSV checks...
    assert list(outdir.glob("dns_benchmark_*_raw.csv")), "Raw CSV missing"
    assert list(outdir.glob("dns_benchmark_*_summary.csv")), "Summary CSV missing"
    assert list(outdir.glob("dns_benchmark_*_domains.csv")), "Domain stats CSV missing"
    assert list(
        outdir.glob("dns_benchmark_*_record_types.csv")
    ), "Record type stats CSV missing"
    assert list(outdir.glob("dns_benchmark_*_errors.csv")), "Error stats CSV missing"

    # Excel check
    assert list(outdir.glob("dns_benchmark_*.xlsx")), "Excel report missing"

    # PDF check only if weasyprint is installed
    if importlib.util.find_spec("weasyprint"):
        assert list(outdir.glob("dns_benchmark_*.pdf")), "PDF report missing"
    else:
        pytest.skip("weasyprint not installed; skipping PDF export check")

    # Validate JSON structure
    data = json.loads(Path(json_path).read_text())
    assert "overall" in data
    assert isinstance(data["resolver_stats"], list)
    assert isinstance(data["raw_results"], list)
    assert isinstance(data["domain_stats"], list)
    assert isinstance(data["record_type_stats"], list)
    assert isinstance(data["error_stats"], dict)


def test_create_progress_bar():
    bar = create_progress_bar(5, "Testing")
    assert bar.total == 5
    assert "Testing" in bar.desc
    bar.close()


def test_cli_validate_inputs_missing_files():
    runner = CliRunner()
    result = runner.invoke(cli, ["benchmark", "--record-types", "A"])
    assert result.exit_code == 0
    assert (
        "Either provide --resolvers and --domains or use --use-defaults"
        in result.output
    )


def test_cli_invalid_format():
    runner = CliRunner()
    # Use defaults so resolvers/domains load
    result = runner.invoke(cli, ["benchmark", "--use-defaults", "--formats", "badfmt"])
    assert result.exit_code == 0
    assert "Invalid format" in result.output


def test_cli_domain_file_not_found(monkeypatch):
    runner = CliRunner()

    # Make resolver loading succeed
    monkeypatch.setattr(
        "dns_benchmark.cli.ResolverManager.parse_resolvers_input",
        lambda path: [{"name": "Google", "ip": "8.8.8.8"}],
    )

    # Force domain loading to raise FileNotFoundError
    monkeypatch.setattr(
        "dns_benchmark.cli.DomainManager.parse_domains_input",
        lambda path: (_ for _ in ()).throw(FileNotFoundError("missing.txt")),
    )

    result = runner.invoke(
        cli, ["benchmark", "--resolvers", "resolvers.json", "--domains", "missing.txt"]
    )
    assert "Domain file not found" in result.output


def test_cli_domain_generic_error(monkeypatch):
    runner = CliRunner()

    # Make resolver loading succeed
    monkeypatch.setattr(
        "dns_benchmark.cli.ResolverManager.parse_resolvers_input",
        lambda path: [{"name": "Google", "ip": "8.8.8.8"}],
    )

    # Force domain loading to raise generic Exception
    monkeypatch.setattr(
        "dns_benchmark.cli.DomainManager.parse_domains_input",
        lambda path: (_ for _ in ()).throw(Exception("boom")),
    )

    result = runner.invoke(
        cli, ["benchmark", "--resolvers", "resolvers.json", "--domains", "bad.txt"]
    )
    assert "Error loading domains" in result.output


def strip_ansi(text: str) -> str:
    ansi_escape = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
    return ansi_escape.sub("", text)


def fake_stats():
    return [
        SimpleNamespace(
            resolver_name="Cloudflare",
            avg_latency=20.0,
            success_rate=100.0,
            successful_queries=5,
            total_queries=5,
        ),
        SimpleNamespace(
            resolver_name="Google",
            avg_latency=50.0,
            success_rate=90.0,
            successful_queries=9,
            total_queries=10,
        ),
    ]


def run_top_with_export(tmp_path, ext):
    runner = CliRunner()
    output_file = tmp_path / f"results{ext}"
    with patch(
        "dns_benchmark.cli.ResolverManager.get_all_resolvers",
        return_value=[
            {"name": "Cloudflare", "ip": "1.1.1.1"},
            {"name": "Google", "ip": "8.8.8.8"},
        ],
    ):
        with patch(
            "dns_benchmark.cli.DomainManager.get_sample_domains",
            return_value=["example.com"],
        ):
            with patch(
                "dns_benchmark.cli.DNSQueryEngine.run_benchmark", return_value=[]
            ):
                with patch(
                    "dns_benchmark.cli.BenchmarkAnalyzer.get_resolver_statistics",
                    return_value=fake_stats(),
                ):
                    result = runner.invoke(
                        cli, ["top", "--limit", "2", "-o", str(output_file)]
                    )
    return result, output_file


def test_top_export_json(tmp_path):
    result, output_file = run_top_with_export(tmp_path, ".json")
    assert result.exit_code == 0, result.output
    data = json.loads(output_file.read_text())
    assert "top_resolvers" in data
    assert any(r["name"] == "Cloudflare" for r in data["top_resolvers"])


def test_top_export_csv(tmp_path):
    result, output_file = run_top_with_export(tmp_path, ".csv")
    assert result.exit_code == 0, result.output
    rows = list(csv.reader(output_file.open()))
    assert rows[0][:2] == ["Rank", "Resolver"]
    assert any("Cloudflare" in row for row in rows)


def test_top_export_txt(tmp_path):
    result, output_file = run_top_with_export(tmp_path, ".txt")
    assert result.exit_code == 0, result.output
    text = output_file.read_text()
    assert "Top" in text
    assert "Cloudflare" in text
    assert "Google" in text


def test_top_command_runs(runner):
    """Ensure `top` command executes and prints results."""
    fake_stats = [
        SimpleNamespace(
            resolver_name="Cloudflare",
            avg_latency=20.0,
            success_rate=100.0,
            successful_queries=5,
            total_queries=5,
        ),
        SimpleNamespace(
            resolver_name="Google",
            avg_latency=50.0,
            success_rate=100.0,
            successful_queries=5,
            total_queries=5,
        ),
    ]

    with patch(
        "dns_benchmark.cli.ResolverManager.get_all_resolvers",
        return_value=[
            {"name": "Cloudflare", "ip": "1.1.1.1"},
            {"name": "Google", "ip": "8.8.8.8"},
        ],
    ):
        with patch(
            "dns_benchmark.cli.DomainManager.get_sample_domains",
            return_value=["example.com"],
        ):
            with patch(
                "dns_benchmark.cli.DNSQueryEngine.run_benchmark", return_value=[]
            ):
                with patch(
                    "dns_benchmark.cli.BenchmarkAnalyzer.get_resolver_statistics",
                    return_value=fake_stats,
                ):
                    result = runner.invoke(
                        cli, ["top", "--limit", "2", "--metric", "latency"]
                    )
                    assert result.exit_code == 0, result.output
                    clean_output = strip_ansi(result.output)
                    assert "Cloudflare" in clean_output
                    assert "Google" in clean_output


# Compare
def test_compare_command_runs(runner, sample_results, tmp_path):
    """Ensure `compare` command executes and can export results."""
    output_file = tmp_path / "results.json"
    with patch(
        "dns_benchmark.cli.DNSQueryEngine.run_benchmark", return_value=sample_results
    ):
        result = runner.invoke(
            cli, ["compare", "Cloudflare", "Google", "-o", str(output_file), "--quiet"]
        )
        assert result.exit_code == 0
        # Output file should be created
        assert output_file.exists()
        data = json.loads(output_file.read_text())
        assert "comparison" in data
        assert any(entry["resolver"] == "Cloudflare" for entry in data["comparison"])


@pytest.mark.parametrize("ext", [".json", ".csv"])
def test_compare_export(tmp_path, runner, sample_results, ext):
    output_file = tmp_path / f"compare{ext}"
    with patch(
        "dns_benchmark.cli.ResolverManager.get_all_resolvers",
        return_value=[
            {"name": "Cloudflare", "ip": "1.1.1.1"},
            {"name": "Google", "ip": "8.8.8.8"},
        ],
    ):
        with patch(
            "dns_benchmark.cli.DomainManager.get_sample_domains",
            return_value=["example.com"],
        ):
            with patch(
                "dns_benchmark.cli.DNSQueryEngine.run_benchmark",
                return_value=sample_results,
            ):
                result = runner.invoke(
                    cli, ["compare", "Cloudflare", "Google", "-o", str(output_file)]
                )
                assert result.exit_code == 0
                assert output_file.exists()
                if ext == ".json":
                    data = json.loads(output_file.read_text())
                    assert "comparison" in data
                    assert any(
                        r["resolver"] == "Cloudflare" for r in data["comparison"]
                    )
                else:
                    assert "Cloudflare" in output_file.read_text()


def test_compare_winner_logic(runner, sample_results):
    """Ensure fastest and most reliable resolvers are printed."""
    with patch(
        "dns_benchmark.cli.ResolverManager.get_all_resolvers",
        return_value=[
            {"name": "Cloudflare", "ip": "1.1.1.1"},
            {"name": "Google", "ip": "8.8.8.8"},
        ],
    ):
        with patch(
            "dns_benchmark.cli.DomainManager.get_sample_domains",
            return_value=["example.com"],
        ):
            with patch(
                "dns_benchmark.cli.DNSQueryEngine.run_benchmark",
                return_value=sample_results,
            ):
                result = runner.invoke(cli, ["compare", "Cloudflare", "Google"])
                assert result.exit_code == 0
                assert "🏆 Fastest" in result.output
                assert "🛡️  Most Reliable" in result.output


def test_compare_show_details(runner, sample_results):
    """Ensure per-domain breakdown is printed when --show-details is used."""
    with patch(
        "dns_benchmark.cli.ResolverManager.get_all_resolvers",
        return_value=[
            {"name": "Cloudflare", "ip": "1.1.1.1"},
            {"name": "Google", "ip": "8.8.8.8"},
        ],
    ):
        with patch(
            "dns_benchmark.cli.DomainManager.get_sample_domains",
            return_value=["example.com"],
        ):
            with patch(
                "dns_benchmark.cli.DNSQueryEngine.run_benchmark",
                return_value=sample_results,
            ):
                result = runner.invoke(
                    cli, ["compare", "Cloudflare", "Google", "--show-details"]
                )
                assert result.exit_code == 0
                assert "📋 Per-Domain Breakdown" in result.output
                assert "example.com" in result.output


# Monitoring
def test_monitoring_command_runs_once(runner, sample_results, tmp_path):
    """Run monitoring with duration=1 to exit quickly."""
    log_file = tmp_path / "monitor.log"
    with patch(
        "dns_benchmark.cli.DNSQueryEngine.run_benchmark", return_value=sample_results
    ):
        # Patch time.sleep to avoid waiting
        with patch("time.sleep", return_value=None):
            result = runner.invoke(
                cli,
                [
                    "monitoring",
                    "--use-defaults",
                    "--duration",
                    "1",
                    "--interval",
                    "1",
                    "-o",
                    str(log_file),
                ],
            )
            assert result.exit_code == 0
            # Log file should contain resolver stats
            text = log_file.read_text()
            assert "Cloudflare" in text
            assert "Google" in text


def test_monitoring_runs_once(runner, sample_results, tmp_path):
    """Run monitoring with duration=1 to exit after one loop."""
    log_file = tmp_path / "monitor.log"
    with patch(
        "dns_benchmark.cli.ResolverManager.get_default_resolvers",
        return_value=[
            {"name": "Cloudflare", "ip": "1.1.1.1"},
            {"name": "Google", "ip": "8.8.8.8"},
        ],
    ):
        with patch(
            "dns_benchmark.cli.DomainManager.get_sample_domains",
            return_value=["example.com"],
        ):
            with patch(
                "dns_benchmark.cli.DNSQueryEngine.run_benchmark",
                return_value=sample_results,
            ):
                with patch("time.sleep", return_value=None):
                    result = runner.invoke(
                        cli,
                        [
                            "monitoring",
                            "--use-defaults",
                            "--interval",
                            "1",
                            "--duration",
                            "1",
                            "--alert-latency",
                            "30",
                            "--alert-failure-rate",
                            "5",
                            "-o",
                            str(log_file),
                        ],
                    )
                    assert result.exit_code == 0
                    text = log_file.read_text()
                    assert "Cloudflare" in text
                    assert "Google" in text


def test_monitoring_alerts_triggered(runner, tmp_path):
    """Ensure alerts are printed when thresholds are exceeded."""
    now = time.time()
    results = [
        DNSQueryResult(
            resolver_ip="1.1.1.1",
            resolver_name="Cloudflare",
            domain="example.com",
            record_type="A",
            start_time=now,
            end_time=now + 0.200,
            latency_ms=200.0,
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
            end_time=now + 0.300,
            latency_ms=300.0,
            status=QueryStatus.NXDOMAIN,
            answers=[],
            ttl=None,
            error_message="NXDOMAIN",
        ),
    ]

    with patch(
        "dns_benchmark.cli.ResolverManager.get_default_resolvers",
        return_value=[
            {"name": "Cloudflare", "ip": "1.1.1.1"},
            {"name": "Google", "ip": "8.8.8.8"},
        ],
    ):
        with patch(
            "dns_benchmark.cli.DomainManager.get_sample_domains",
            return_value=["example.com"],
        ):
            with patch(
                "dns_benchmark.cli.DNSQueryEngine.run_benchmark", return_value=results
            ):
                with patch("time.sleep", return_value=None):
                    result = runner.invoke(
                        cli,
                        [
                            "monitoring",
                            "--use-defaults",
                            "--interval",
                            "1",
                            "--duration",
                            "1",
                            "--alert-latency",
                            "100",
                            "--alert-failure-rate",
                            "5",
                        ],
                    )
                    assert result.exit_code == 0
                    assert "⚠️  Cloudflare: High latency" in result.output
                    assert "⚠️  Google: High failure rate" in result.output


def test_monitoring_log_finalized(tmp_path, runner, sample_results):
    log_file = tmp_path / "monitor.log"
    with patch(
        "dns_benchmark.cli.ResolverManager.get_default_resolvers",
        return_value=[{"name": "Cloudflare", "ip": "1.1.1.1"}],
    ):
        with patch(
            "dns_benchmark.cli.DomainManager.get_sample_domains",
            return_value=["example.com"],
        ):
            with patch(
                "dns_benchmark.cli.DNSQueryEngine.run_benchmark",
                return_value=sample_results,
            ):
                with patch("time.sleep", return_value=None):
                    result = runner.invoke(
                        cli,
                        [
                            "monitoring",
                            "--use-defaults",
                            "--interval",
                            "1",
                            "--duration",
                            "1",
                            "-o",
                            str(log_file),
                        ],
                    )
                    assert result.exit_code == 0
                    text = log_file.read_text()
                    assert "Monitoring started" in text
                    assert "Monitoring ended" in text


def test_monitoring_with_files(runner, sample_results, tmp_path):
    """Ensure monitoring runs with --resolvers and --domains file inputs."""
    resolver_file = tmp_path / "resolvers.json"
    domain_file = tmp_path / "domains.txt"
    log_file = tmp_path / "monitor.log"

    # Write fake resolver and domain files
    resolver_file.write_text(
        json.dumps(
            [
                {"name": "Cloudflare", "ip": "1.1.1.1"},
                {"name": "Google", "ip": "8.8.8.8"},
            ]
        )
    )
    domain_file.write_text("example.com\nexample.org")

    with patch(
        "dns_benchmark.cli.ResolverManager.load_resolvers_from_file",
        return_value=[
            {"name": "Cloudflare", "ip": "1.1.1.1"},
            {"name": "Google", "ip": "8.8.8.8"},
        ],
    ):
        with patch(
            "dns_benchmark.cli.DomainManager.load_domains_from_file",
            return_value=["example.com", "example.org"],
        ):
            with patch(
                "dns_benchmark.cli.DNSQueryEngine.run_benchmark",
                return_value=sample_results,
            ):
                with patch("time.sleep", return_value=None):
                    result = runner.invoke(
                        cli,
                        [
                            "monitoring",
                            "--resolvers",
                            str(resolver_file),
                            "--domains",
                            str(domain_file),
                            "--interval",
                            "1",
                            "--duration",
                            "1",
                            "-o",
                            str(log_file),
                        ],
                    )
                    assert result.exit_code == 0
                    text = log_file.read_text()
                    assert "Cloudflare" in text
                    assert "Google" in text
