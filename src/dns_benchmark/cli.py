import asyncio
import json
import os
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import click
import pyfiglet
from colorama import Fore, Style, init
from tqdm import tqdm

from dns_benchmark.analysis import BenchmarkAnalyzer
from dns_benchmark.core import DNSQueryEngine, DomainManager, ResolverManager
from dns_benchmark.exporters import (
    CSVExporter,
    ExcelExporter,
    ExportBundle,
    PDFExporter,
)
from dns_benchmark.utils.messages import (
    error,
    info,
    positive,
    success,
    summary_box,
    warning,
)

# Initialize colorama
init()


@click.group()
def cli() -> None:
    """
    Buildtools - DNS Benchmark Tool - Measure and compare DNS resolver performance
    CLI entry point.
    """
    # Allow suppression of banner for CI/CD
    if not os.environ.get("NO_BANNER"):
        ascii_art = pyfiglet.figlet_format("DNS Benchmarking Tool")
        print(Fore.GREEN + ascii_art + Style.RESET_ALL)
        print(Fore.CYAN + "[ GitHub : https://github.com/frankovo ]" + Style.RESET_ALL)


def create_progress_bar(total: int, desc: str) -> Any:
    return tqdm(
        total=total, desc=info(desc), bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt}"
    )


@cli.command()
@click.option("--resolvers", "-r", help="JSON file with resolver list")
@click.option("--domains", "-d", help="Text file with domain list")
@click.option(
    "--record-types",
    "-t",
    default="A",
    help="DNS record types to query (comma-separated)",
)
@click.option(
    "--output", "-o", default="./benchmark_results", help="Output directory for results"
)
@click.option(
    "--formats", "-f", default="csv,excel,pdf", help="Output formats (csv,excel,pdf)"
)
@click.option("--timeout", default=5.0, help="Query timeout in seconds")
@click.option("--max-concurrent", default=100, help="Maximum concurrent queries")
@click.option("--retries", default=2, help="Number of retries for failed queries")
@click.option(
    "--use-defaults", is_flag=True, help="Use default resolvers and sample domains"
)
@click.option("--quiet", is_flag=True, help="Suppress progress output")
@click.option("--domain-stats", is_flag=True, help="Include per-domain statistics")
@click.option(
    "--record-type-stats", is_flag=True, help="Include record-type statistics"
)
@click.option("--error-breakdown", is_flag=True, help="Include error breakdown")
@click.option("--json", "json_output", is_flag=True, help="Export results to JSON")
def benchmark(
    resolvers: Optional[str],
    domains: Optional[str],
    record_types: str,
    output: str,
    formats: str,
    timeout: float,
    max_concurrent: int,
    retries: int,
    use_defaults: bool,
    quiet: bool,
    domain_stats: bool,
    record_type_stats: bool,
    error_breakdown: bool,
    json_output: bool,
) -> None:
    """Run DNS benchmark test."""

    # Validate inputs
    if not use_defaults and (not resolvers or not domains):
        click.echo(
            error("Either provide --resolvers and --domains or use --use-defaults")
        )
        return

    # Parse record types
    record_type_list = [rt.strip().upper() for rt in record_types.split(",")]

    # Parse output formats
    output_formats = [fmt.strip().lower() for fmt in formats.split(",")]
    valid_formats = ["csv", "excel", "pdf"]
    for fmt in output_formats:
        if fmt not in valid_formats:
            click.echo(
                error(
                    f"Invalid format '{fmt}'. Must be one of: {', '.join(valid_formats)}"
                )
            )
            return

    output_path = Path(output)
    output_path.mkdir(parents=True, exist_ok=True)

    # Load resolvers
    if use_defaults:
        resolver_list = ResolverManager.get_default_resolvers()
        if not quiet:
            click.echo(
                success(f"Using default resolvers ({len(resolver_list)} resolvers)")
            )
    else:
        resolver_list = ResolverManager.load_resolvers_from_file(
            resolvers if resolvers else ""
        )

    # Load domains
    if use_defaults:
        domain_list = DomainManager.get_sample_domains()
        if not quiet:
            click.echo(success(f"Using sample domains ({len(domain_list)} domains)"))
    else:
        domain_list = DomainManager.load_domains_from_file(domains if domains else "")

    # Calculate total queries
    total_queries = len(resolver_list) * len(domain_list) * len(record_type_list)
    if not quiet:
        click.echo(info(f"Total queries to execute: {total_queries}"))
        click.echo(info(f"Record types: {', '.join(record_type_list)}"))

    # Run benchmark
    if not quiet:
        click.echo(warning("Starting DNS benchmark..."))
    start_time = time.time()

    try:
        engine = DNSQueryEngine(
            max_concurrent_queries=max_concurrent, timeout=timeout, max_retries=retries
        )

        progress_bar = None
        if not quiet:
            progress_bar = create_progress_bar(total_queries, "DNS Queries")
            
            # New callback signature: (completed, total)
            def _progress_cb(completed: int, total: int) -> None:
                """TQDM-friendly progress callback.

                Advances the bar by 1 per completed item and sets a postfix like '23/100'.
                Keep this callback fast and non-blocking.
                """
                try:
                    if progress_bar:
                        progress_bar.update(1)
                        progress_bar.set_postfix_str(f"{completed}/{total}")
                except Exception:
                    # Never allow progress callback errors to interrupt benchmarking
                    pass

            engine.set_progress_callback(_progress_cb)

        results = asyncio.run(
            engine.run_benchmark(
                resolvers=resolver_list,
                domains=domain_list,
                record_types=record_type_list,
            )
        )

        if progress_bar:
            progress_bar.close()

        duration = time.time() - start_time
        if not quiet:
            click.echo(success(f"Benchmark completed in {duration:.2f} seconds"))

        # Analyze results
        analyzer = BenchmarkAnalyzer(results)
        overall_stats = analyzer.get_overall_statistics()

        if not quiet:
            click.echo(info("=== BENCHMARK SUMMARY ==="))
            summary_lines = [
                f"Total queries: {overall_stats['total_queries']}",
                f"Successful: {overall_stats['successful_queries']} ({overall_stats['overall_success_rate']:.2f}%)",
                f"Average latency: {overall_stats['overall_avg_latency']:.2f} ms",
                f"Median latency: {overall_stats['overall_median_latency']:.2f} ms",
                f"Fastest resolver: {overall_stats['fastest_resolver']}",
                f"Slowest resolver: {overall_stats['slowest_resolver']}",
            ]
            click.echo(summary_box(summary_lines))

        # Optional analytics
        domain_stats_data = analyzer.get_domain_statistics() if domain_stats else None
        record_type_stats_data = (
            analyzer.get_record_type_statistics() if record_type_stats else None
        )
        error_stats_data = analyzer.get_error_statistics() if error_breakdown else None

        # Export results
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base_filename = f"dns_benchmark_{timestamp}"

        if not quiet:
            click.echo(warning("Exporting results..."))

        export_progress = (
            create_progress_bar(len(output_formats), "Exporting") if not quiet else None
        )

        try:
            if "csv" in output_formats:
                CSVExporter.export_raw_results(
                    results, str(output_path / f"{base_filename}_raw.csv")
                )
                CSVExporter.export_summary_statistics(
                    analyzer, str(output_path / f"{base_filename}_summary.csv")
                )
                if domain_stats_data:
                    CSVExporter.export_domain_statistics(
                        domain_stats_data,
                        str(output_path / f"{base_filename}_domains.csv"),
                    )
                if record_type_stats_data:
                    CSVExporter.export_record_type_statistics(
                        record_type_stats_data,
                        str(output_path / f"{base_filename}_record_types.csv"),
                    )
                if error_stats_data:
                    CSVExporter.export_error_statistics(
                        error_stats_data,
                        str(output_path / f"{base_filename}_errors.csv"),
                    )
                if export_progress:
                    export_progress.update(1)

            if "excel" in output_formats:
                ExcelExporter.export_results(
                    results,
                    analyzer,
                    str(output_path / f"{base_filename}.xlsx"),
                    domain_stats=domain_stats_data,
                    record_type_stats=record_type_stats_data,
                    error_stats=error_stats_data,
                )
                if export_progress:
                    export_progress.update(1)

            if "pdf" in output_formats:
                PDFExporter.export_results(
                    results,
                    analyzer,
                    str(output_path / f"{base_filename}.pdf"),
                    include_success_chart=True,
                )
                if export_progress:
                    export_progress.update(1)

            if not quiet:
                click.echo(success("All exports completed successfully!"))

        finally:
            if export_progress:
                export_progress.close()

        # JSON export
        if json_output:
            ExportBundle.export_json(
                results,
                analyzer,
                domain_stats=domain_stats_data,
                record_type_stats=record_type_stats_data,
                error_stats=error_stats_data,
                output_path=str(output_path / f"{base_filename}.json"),
            )

    except Exception as e:
        click.echo(error(f"Error during benchmark: {e}"))
        raise


@cli.command()
def list_defaults() -> None:
    """List default resolvers and sample domains."""
    click.echo(f"{Fore.CYAN}=== Default Resolvers ==={Style.RESET_ALL}")
    default_resolvers = ResolverManager.get_default_resolvers()
    for resolver in default_resolvers:
        click.echo(f"  {resolver['name']}: {resolver['ip']}")

    click.echo(f"\n{Fore.CYAN}=== Sample Domains ==={Style.RESET_ALL}")
    sample_domains = DomainManager.get_sample_domains()
    for domain in sample_domains:
        click.echo(f"  {domain}")
    return None


@cli.command()
@click.option("--category", "-c", help="Filter by category")
@click.option(
    "--format",
    "-f",
    type=click.Choice(["table", "json", "csv"]),
    default="table",
    help="Output format",
)
@click.option("--details", "-d", is_flag=True, help="Show detailed information")
def list_resolvers(category: Optional[str], format: str, details: bool) -> None:
    """Show all available DNS resolvers with provider information"""
    if category:
        resolvers: List[Dict[str, Any]] = ResolverManager.get_resolvers_by_category(
            category
        )
        status_msg = f"Showing resolvers in category: {category}"
    else:
        resolvers = ResolverManager.get_all_resolvers()
        status_msg = "Showing all resolvers"

    if format == "json":
        # Emit pure JSON only
        click.echo(json.dumps(resolvers, indent=2))
        return

    # For human‑friendly formats, show the status line
    click.echo(info(status_msg))

    if format == "csv":
        if details:
            click.echo(
                warning(
                    "Name,Provider,IPv4,IPv6,Type,Category,Features,Description,Country"
                )
            )
            for resolver in resolvers:
                features = ";".join(resolver.get("features", []))
                click.echo(
                    f"\"{resolver['name']}\",\"{resolver['provider']}\",\"{resolver['ip']}\","
                    f"\"{resolver.get('ipv6', '')}\",\"{resolver['type']}\",\"{resolver['category']}\","
                    f"\"{features}\",\"{resolver['description']}\",\"{resolver['country']}\""
                )
        else:
            click.echo(warning("Name,Provider,IPv4,IPv6,Category"))
            for resolver in resolvers:
                click.echo(
                    f"\"{resolver['name']}\",\"{resolver['provider']}\",\"{resolver['ip']}\","
                    f"\"{resolver.get('ipv6', '')}\",\"{resolver['category']}\""
                )
        return

    # Table format (default)
    if details:
        click.echo(info("=" * 100))
        click.echo(success(f"{'DNS RESOLVERS - DETAILED LIST':^100}"))
        click.echo(info("=" * 100))

        for i, resolver in enumerate(resolvers, 1):
            click.echo(
                positive(f"\n{i:2d}. {resolver['name']} ({resolver['provider']})")
            )
            click.echo(info(f"     IPv4: {resolver['ip']}"))
            if resolver.get("ipv6"):
                click.echo(info(f"     IPv6: {resolver['ipv6']}"))
            click.echo(
                info(
                    f"     Type: {resolver['type']} | Category: {resolver['category']} | Country: {resolver['country']}"
                )
            )
            click.echo(
                info(f"     Features: {', '.join(resolver.get('features', []))}")
            )
            click.echo(info(f"     Description: {resolver['description']}"))

            if i < len(resolvers):
                click.echo(info("     " + "-" * 100))
    else:
        click.echo(info("=" * 90))
        click.echo(success(f"{'DNS RESOLVERS':^90}"))
        click.echo(info("=" * 90))
        click.echo(
            warning(
                f"{'Name':<20} {'Provider':<25} {'IPv4':<15} {'IPv6':<25} {'Category':<10}"
            )
        )
        click.echo(info("-" * 90))

        for resolver in resolvers:
            ipv6_display = (
                resolver.get("ipv6", "")[:22] + "..."
                if len(resolver.get("ipv6", "")) > 25
                else resolver.get("ipv6", "")
            )
            click.echo(
                positive(
                    f"{resolver['name']:<20} {resolver['provider']:<25} {resolver['ip']:<15} {ipv6_display:<25} {resolver['category']:<10}"
                )
            )

    # Show summary in a framed box
    categories: List[str] = ResolverManager.get_categories()
    summary_lines: List[str] = [f"Total resolvers: {len(resolvers)}"]
    if not category:
        summary_lines.append(f"Available categories: {', '.join(categories)}")
    summary_lines.append(
        "Use '--category <name>' to filter or '--details' for more information"
    )

    click.echo(summary_box(summary_lines))


@cli.command()
@click.option("--category", "-c", help="Filter by category")
@click.option(
    "--format",
    "-f",
    type=click.Choice(["table", "json", "csv"]),
    default="table",
    help="Output format",
)
@click.option("--count", type=int, help="Limit number of domains shown")
def list_domains(category: Optional[str], format: str, count: Optional[int]) -> None:
    """Show all available test domains with categories"""
    if category:
        domains: List[Dict[str, Any]] = DomainManager.get_domains_by_category(category)
        status_msg = f"Showing domains in category: {category}"
    else:
        domains = DomainManager.get_all_domains()
        status_msg = "Showing all domains"

    if count:
        domains = domains[:count]

    if format == "json":
        # Emit pure JSON only
        click.echo(json.dumps(domains, indent=2))
        return

    # For human‑friendly formats, show the status line
    click.echo(info(status_msg))

    if format == "csv":
        click.echo(warning("Domain,Category,Description,Country"))
        for domain in domains:
            click.echo(
                f"\"{domain['domain']}\",\"{domain['category']}\","
                f"\"{domain['description']}\",\"{domain['country']}\""
            )
        return

    # Table format (default)
    click.echo(info("=" * 80))
    click.echo(success(f"{'TEST DOMAINS':^80}"))
    click.echo(info("=" * 80))
    click.echo(
        warning(f"{'Domain':<30} {'Category':<15} {'Country':<10} {'Description':<25}")
    )
    click.echo(info("-" * 80))

    for domain in domains:
        domain_display = (
            domain["domain"][:28] + "..."
            if len(domain["domain"]) > 30
            else domain["domain"]
        )
        desc_display = (
            domain["description"][:22] + "..."
            if len(domain["description"]) > 25
            else domain["description"]
        )
        click.echo(
            positive(
                f"{domain_display:<30} {domain['category']:<15} {domain['country']:<10} {desc_display:<25}"
            )
        )

    # Show summary in a framed box
    categories: List[str] = DomainManager.get_categories()
    summary_lines: List[str] = [f"Total domains: {len(domains)}"]
    if not category:
        summary_lines.append(f"Available categories: {', '.join(categories)}")
    summary_lines.append(
        "Use '--category <name>' to filter or '--count <number>' to limit results"
    )

    click.echo(summary_box(summary_lines))


@cli.command()
def list_categories() -> None:
    """Show all available resolver and domain categories"""
    resolver_categories: List[str] = ResolverManager.get_categories()
    domain_categories: List[str] = DomainManager.get_categories()

    # Header
    click.echo(info("=" * 50))
    click.echo(success(f"{'AVAILABLE CATEGORIES':^50}"))
    click.echo(info("=" * 50))

    # Resolver categories
    click.echo(success(f"\n{'RESOLVER CATEGORIES':^50}"))
    click.echo(info("-" * 50))
    for category in resolver_categories:
        count: int = len(ResolverManager.get_resolvers_by_category(category))
        click.echo(positive(f"  {category:<20} ({count} resolvers)"))

    # Domain categories
    click.echo(success(f"\n{'DOMAIN CATEGORIES':^50}"))
    click.echo(info("-" * 50))
    for category in domain_categories:
        count_domain: int = len(DomainManager.get_domains_by_category(category))
        click.echo(positive(f"  {category:<20} ({count_domain} domains)"))

    # Summary box
    summary_lines: List[str] = [
        "Use 'list-resolvers --category <name>' to filter resolvers",
        "Use 'list-domains --category <name>' to filter domains",
    ]
    click.echo(summary_box(summary_lines))


@cli.command()
@click.option("--category", "-c", help="Generate config for specific category")
@click.option("--output", "-o", help="Output file path")
def generate_config(category: Optional[str], output: Optional[str]) -> None:
    """Generate a sample configuration file"""
    config: Dict[str, Any] = {
        "name": f"DNS Benchmark Config - {category if category else 'All Categories'}",
        "resolvers": [],
        "domains": [],
        "settings": {
            "record_types": ["A", "AAAA"],
            "timeout": 5,
            "concurrent_queries": 50,
            "iterations": 1,
            "output_formats": ["csv", "excel", "pdf"],
        },
    }

    # Add resolvers
    if category:
        resolvers: List[Dict[str, Any]] = ResolverManager.get_resolvers_by_category(
            category
        )
        click.echo(info(f"Using resolvers from category: {category}"))
    else:
        resolvers = ResolverManager.get_all_resolvers()[:10]  # Limit to 10 for sample
        click.echo(info("Using first 10 resolvers for sample config"))

    for resolver in resolvers:
        config["resolvers"].append(
            {
                "name": resolver["name"],
                "ip": resolver["ip"],
                "ipv6": resolver.get("ipv6", ""),
            }
        )

    # Add domains
    if category:
        domains: List[Dict[str, Any]] = DomainManager.get_domains_by_category(category)
        click.echo(info(f"Using domains from category: {category}"))
    else:
        domains = DomainManager.get_all_domains()[:20]  # Limit to 20 for sample
        click.echo(info("Using first 20 domains for sample config"))

    for domain in domains:
        config["domains"].append(domain["domain"])

    # Build YAML string
    config_yaml: str = f"""# DNS Benchmark Configuration
# Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

name: "{config['name']}"

resolvers:
{chr(10).join(f'  - name: "{r["name"]}"{chr(10)}    ip: "{r["ip"]}"{chr(10)}    ipv6: "{r.get("ipv6", "")}"' for r in config["resolvers"])}

domains:
{chr(10).join(f'  - "{d}"' for d in config["domains"])}

settings:
  record_types: {config["settings"]["record_types"]}
  timeout: {config["settings"]["timeout"]}
  concurrent_queries: {config["settings"]["concurrent_queries"]}
  iterations: {config["settings"]["iterations"]}
  output_formats: {config["settings"]["output_formats"]}
"""

    if output:
        try:
            with open(output, "w") as f:
                f.write(config_yaml)
            click.echo(success(f"Configuration saved to: {output}"))
        except Exception as e:
            click.echo(error(f"Failed to save configuration: {e}"))
    else:
        click.echo(config_yaml)

    # Show summary box
    summary_lines: List[str] = [
        f"Configuration name: {config['name']}",
        f"Resolvers included: {len(config['resolvers'])}",
        f"Domains included: {len(config['domains'])}",
        f"Output formats: {', '.join(config['settings']['output_formats'])}",
    ]
    click.echo(summary_box(summary_lines))
