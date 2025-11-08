from unittest.mock import patch

from click.testing import CliRunner

from dns_benchmark.cli import cli


def test_list_defaults():
    runner = CliRunner()
    with patch(
        "dns_benchmark.core.ResolverManager.get_default_resolvers",
        return_value=[
            {"name": "Cloudflare", "ip": "1.1.1.1"},
        ],
    ), patch(
        "dns_benchmark.core.DomainManager.get_sample_domains",
        return_value=[
            "example.com",
        ],
    ):
        result = runner.invoke(cli, ["list-defaults"])
        assert result.exit_code == 0
        assert "Cloudflare" in result.output
        assert "example.com" in result.output


def test_list_resolvers_json():
    runner = CliRunner()
    with patch(
        "dns_benchmark.core.ResolverManager.get_all_resolvers",
        return_value=[
            {
                "name": "Cloudflare",
                "provider": "Cloudflare",
                "ip": "1.1.1.1",
                "type": "public",
                "category": "privacy",
                "description": "",
                "country": "Global",
            }
        ],
    ):
        result = runner.invoke(cli, ["list-resolvers", "--format", "json"])
        assert result.exit_code == 0
        assert '"Cloudflare"' in result.output


def test_list_domains_csv():
    runner = CliRunner()
    with patch(
        "dns_benchmark.core.DomainManager.get_all_domains",
        return_value=[
            {
                "domain": "example.com",
                "category": "test",
                "description": "desc",
                "country": "US",
            }
        ],
    ):
        result = runner.invoke(cli, ["list-domains", "--format", "csv"])
        assert result.exit_code == 0
        assert "example.com" in result.output
        assert "test" in result.output
