import json
from pathlib import Path
from unittest.mock import patch

from click.testing import CliRunner

from dns_benchmark.cli import cli


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
