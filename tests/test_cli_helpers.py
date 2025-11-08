import json

import pytest
from click.testing import CliRunner

from dns_benchmark.cli import (
    generate_config,
    list_categories,
    list_domains,
    list_resolvers,
)


@pytest.fixture
def runner():
    return CliRunner()


# ----------------------------
# list_resolvers tests
# ----------------------------


def test_list_resolvers_json(runner):
    result = runner.invoke(list_resolvers, ["--format", "json"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert isinstance(data, list)
    if data:  # only check if non-empty
        assert "name" in data[0]


def test_list_resolvers_csv_simple(runner):
    result = runner.invoke(list_resolvers, ["--format", "csv"])
    assert result.exit_code == 0
    assert "Name,Provider,IPv4,IPv6,Category" in result.output


def test_list_resolvers_csv_detailed(runner):
    result = runner.invoke(list_resolvers, ["--format", "csv", "--details"])
    assert result.exit_code == 0
    assert (
        "Name,Provider,IPv4,IPv6,Type,Category,Features,Description,Country"
        in result.output
    )


def test_list_resolvers_table_default(runner):
    result = runner.invoke(list_resolvers, [])
    assert result.exit_code == 0
    out = result.output
    assert "DNS RESOLVERS" in out
    assert "Name" in out and "Provider" in out
    assert "Total resolvers:" in out  # summary box


def test_list_resolvers_table_detailed(runner):
    result = runner.invoke(list_resolvers, ["--details"])
    assert result.exit_code == 0
    out = result.output
    assert "DNS RESOLVERS - DETAILED LIST" in out
    assert "IPv4:" in out
    assert "Use '--category <name>'" in out  # summary box hint


# ----------------------------
# list_domains tests
# ----------------------------


def test_list_domains_json(runner):
    result = runner.invoke(list_domains, ["--format", "json"])
    assert result.exit_code == 0
    domains = json.loads(result.output)
    assert isinstance(domains, list)
    if domains:
        assert "domain" in domains[0]


def test_list_domains_csv(runner):
    result = runner.invoke(list_domains, ["--format", "csv"])
    assert result.exit_code == 0
    assert "Domain,Category,Description,Country" in result.output


def test_list_domains_table_default(runner):
    result = runner.invoke(list_domains, [])
    assert result.exit_code == 0
    out = result.output
    assert "TEST DOMAINS" in out
    assert "Domain" in out and "Category" in out
    assert "Total domains:" in out  # summary box


def test_list_domains_table_with_count(runner):
    result = runner.invoke(list_domains, ["--count", "1"])
    assert result.exit_code == 0
    out = result.output
    assert "TEST DOMAINS" in out
    assert "Total domains: 1" in out


# ----------------------------
# list_categories tests
# ----------------------------


def test_list_categories_output(runner):
    result = runner.invoke(list_categories)
    assert result.exit_code == 0
    out = result.output
    assert "AVAILABLE CATEGORIES" in out
    assert "RESOLVER CATEGORIES" in out
    assert "DOMAIN CATEGORIES" in out
    assert "Use 'list-resolvers --category" in out  # summary box hint


# ----------------------------
# generate_config tests
# ----------------------------


def test_generate_config_yaml_output(runner):
    result = runner.invoke(generate_config, [])
    assert result.exit_code == 0
    out = result.output
    assert "DNS Benchmark Configuration" in out
    assert "resolvers:" in out
    assert "domains:" in out
    assert "settings:" in out
    assert "Configuration name:" in out  # summary box
