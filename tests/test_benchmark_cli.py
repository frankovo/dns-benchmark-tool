import json
import tempfile
from pathlib import Path
from unittest.mock import patch

import click
import pytest
from click.testing import CliRunner

from dns_benchmark.cli import (
    FeedbackManager,
    cli,
    create_progress_bar,
    feedback,
    reset_feedback,
    show_feedback_prompt,
)


@pytest.fixture
def temp_config_dir(monkeypatch):
    """Use a temporary directory for feedback state."""
    tmpdir = tempfile.TemporaryDirectory()
    monkeypatch.setattr(Path, "home", lambda: Path(tmpdir.name))
    yield Path(tmpdir.name)
    tmpdir.cleanup()


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

    # Patch run_benchmark to return our sample results, avoiding network
    with patch(
        "dns_benchmark.core.DNSQueryEngine.run_benchmark", return_value=sample_results
    ):
        # Also patch default resolvers/domains to keep totals small
        with patch(
            "dns_benchmark.core.ResolverManager.get_default_resolvers",
            return_value=[
                {"name": "Cloudflare", "ip": "1.1.1.1"},
                {"name": "Google", "ip": "8.8.8.8"},
            ],
        ), patch(
            "dns_benchmark.core.DomainManager.get_sample_domains",
            return_value=["example.com", "bad-domain.test"],
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
                    "--quiet",  # less noisy output
                ],
            )
            assert result.exit_code == 0, f"CLI failed: {result.output}"

    # Verify outputs
    files = list(outdir.glob("dns_benchmark_*.json"))
    assert files, "JSON export missing"
    json_path = files[0]

    csv_raw = list(outdir.glob("dns_benchmark_*_raw.csv"))
    csv_summary = list(outdir.glob("dns_benchmark_*_summary.csv"))
    csv_domains = list(outdir.glob("dns_benchmark_*_domains.csv"))
    csv_record_types = list(outdir.glob("dns_benchmark_*_record_types.csv"))
    csv_errors = list(outdir.glob("dns_benchmark_*_errors.csv"))

    assert csv_raw, "Raw CSV missing"
    assert csv_summary, "Summary CSV missing"
    assert csv_domains, "Domain stats CSV missing"
    assert csv_record_types, "Record type stats CSV missing"
    assert csv_errors, "Error stats CSV missing"

    excel = list(outdir.glob("dns_benchmark_*.xlsx"))
    pdf = list(outdir.glob("dns_benchmark_*.pdf"))
    assert excel, "Excel report missing"
    assert pdf, "PDF report missing"

    # Validate JSON structure
    data = json.loads(Path(json_path).read_text())
    assert "overall" in data
    assert "resolver_stats" in data and isinstance(data["resolver_stats"], list)
    assert "raw_results" in data and isinstance(data["raw_results"], list)
    assert "domain_stats" in data and isinstance(data["domain_stats"], list)
    assert "record_type_stats" in data and isinstance(data["record_type_stats"], list)
    assert "error_stats" in data and isinstance(data["error_stats"], dict)


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
        "dns_benchmark.cli.ResolverManager.load_resolvers_from_file",
        lambda path: [{"name": "Google", "ip": "8.8.8.8"}],
    )

    # Force domain loading to raise FileNotFoundError
    monkeypatch.setattr(
        "dns_benchmark.cli.DomainManager.load_domains_from_file",
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
        "dns_benchmark.cli.ResolverManager.load_resolvers_from_file",
        lambda path: [{"name": "Google", "ip": "8.8.8.8"}],
    )

    # Force domain loading to raise generic Exception
    monkeypatch.setattr(
        "dns_benchmark.cli.DomainManager.load_domains_from_file",
        lambda path: (_ for _ in ()).throw(Exception("boom")),
    )

    result = runner.invoke(
        cli, ["benchmark", "--resolvers", "resolvers.json", "--domains", "bad.txt"]
    )
    assert "Error loading domains" in result.output


def test_load_and_save_state(temp_config_dir):
    manager = FeedbackManager()
    state = manager._get_default_state()
    manager._save_state(state)

    loaded = manager._load_state()
    assert loaded == state


def test_should_show_prompt_threshold(temp_config_dir, monkeypatch):
    manager = FeedbackManager()
    state = manager._get_default_state()
    state["total_runs"] = 5
    state["last_shown"] = 0
    manager._save_state(state)

    # Force time to be > 24h later
    monkeypatch.setattr("time.time", lambda: 60 * 60 * 25)
    assert manager.should_show_prompt() is True


def test_mark_feedback_given(temp_config_dir):
    manager = FeedbackManager()
    manager.mark_feedback_given()
    state = manager._load_state()
    assert state["feedback_given"] is True


def test_mark_dismissed(temp_config_dir):
    manager = FeedbackManager()
    manager.mark_dismissed()
    state = manager._load_state()
    assert state["dismissed_count"] == 1


def test_show_feedback_prompt_yes(monkeypatch, temp_config_dir):
    manager = FeedbackManager()
    state = manager._get_default_state()
    state["total_runs"] = 5
    state["last_shown"] = 0
    manager._save_state(state)

    monkeypatch.setattr("time.time", lambda: 60 * 60 * 25)
    monkeypatch.setattr(click, "prompt", lambda *a, **k: "y")

    # Should not mark dismissed
    show_feedback_prompt()
    state = manager._load_state()
    assert state["dismissed_count"] == 0


def test_show_feedback_prompt_no(monkeypatch, temp_config_dir):
    manager = FeedbackManager()
    state = manager._get_default_state()
    state["total_runs"] = 5
    state["last_shown"] = 0
    manager._save_state(state)

    monkeypatch.setattr("time.time", lambda: 60 * 60 * 25)
    monkeypatch.setattr(click, "prompt", lambda *a, **k: "n")

    show_feedback_prompt()
    state = manager._load_state()
    assert state["dismissed_count"] == 1


def test_feedback_command(monkeypatch, temp_config_dir):
    runner = CliRunner()
    monkeypatch.setattr("webbrowser.open", lambda url: True)

    result = runner.invoke(feedback)
    assert result.exit_code == 0

    manager = FeedbackManager()
    state = manager._load_state()
    assert state["feedback_given"] is True


def test_reset_method_removes_file(temp_config_dir):
    manager = FeedbackManager()
    # Create a fake state file
    manager._save_state(manager._get_default_state())
    assert manager.config_file.exists()

    # Reset should remove it
    manager.reset()
    assert not manager.config_file.exists()


def test_reset_feedback_command(temp_config_dir):
    runner = CliRunner()
    manager = FeedbackManager()
    manager._save_state(manager._get_default_state())
    assert manager.config_file.exists()

    # Run CLI command
    result = runner.invoke(reset_feedback)
    assert result.exit_code == 0
    assert "✓ Feedback state reset" in result.output

    # File should be gone
    assert not manager.config_file.exists()
