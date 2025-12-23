import asyncio
import json
import os
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, cast

import click
import pyfiglet
from colorama import Fore, Style, init
from tqdm import tqdm

from dns_benchmark import __version__
from dns_benchmark.analysis import BenchmarkAnalyzer
from dns_benchmark.core import (
    DNSQueryEngine,
    DomainManager,
    QueryStatus,
    ResolverManager,
)
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
@click.version_option(__version__, prog_name="DNS Benchmark Tool")
def cli() -> None:
    """
    Buildtools - DNS Benchmark Tool - Measure and compare DNS resolver performance
    CLI entry point.
    """
    # Allow suppression of banner for CI/CD
    if not os.environ.get("NO_BANNER"):
        ascii_art = pyfiglet.figlet_format("DNS Benchmark")
        print(Fore.GREEN + ascii_art + Style.RESET_ALL)
        print(
            Fore.CYAN
            + "Part of BuildTools - Network Performance Suite"
            + Style.RESET_ALL
        )
        print(Fore.YELLOW + "🌐 buildtools.net | 📦 1,400+ downloads" + Style.RESET_ALL)
        print(
            Fore.BLUE
            + "💡 Want multi-region testing? Join waitlist: buildtools.net"
            + Style.RESET_ALL
        )
        print()


def create_progress_bar(total: int, desc: str) -> Any:
    return tqdm(
        total=total, desc=info(desc), bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt}"
    )


class FeedbackManager:
    """Manages feedback prompt display logic with persistence."""

    def __init__(self) -> None:
        self.config_dir = Path.home() / ".dns-benchmark"
        self.config_file = self.config_dir / "feedback.json"
        self.config_dir.mkdir(exist_ok=True)

    def _get_default_state(self) -> Dict[str, Any]:
        """Get default state structure."""
        return {
            "total_runs": 0,
            "feedback_given": False,
            "dismissed_count": 0,
            "last_shown": 0,
            "last_threshold_shown": 0,
            "version": "1.0",
        }

    def _load_state(self) -> Dict[str, Any]:
        """Load feedback state from disk."""
        if not self.config_file.exists():
            return self._get_default_state()

        try:
            with open(self.config_file, "r") as f:
                state = json.load(f)
                # Ensure all required keys exist (for forward compatibility)
                default_state = self._get_default_state()
                for key, value in default_state.items():
                    state.setdefault(key, value)
                return cast(Dict[str, Any], state)
        except (json.JSONDecodeError, IOError) as e:
            # Log the error but continue with defaults
            import logging

            logging.warning(f"Failed to load feedback state: {e}")
            return self._get_default_state()

    def _save_state(self, state: Dict[str, Any]) -> None:
        """Save feedback state to disk."""
        try:
            with open(self.config_file, "w") as f:
                json.dump(state, f, indent=2)
        except IOError as e:
            # Log but fail silently for non-critical feature
            import logging

            logging.warning(f"Failed to save feedback state: {e}")

    def increment_run(self) -> None:
        """Increment the run counter without showing prompt."""
        state = self._load_state()
        state["total_runs"] = state.get("total_runs", 0) + 1
        self._save_state(state)

    def should_show_prompt(self) -> bool:
        """Determine if feedback prompt should be shown.

        Note: This method does NOT increment the run counter.
        Call increment_run() separately when a benchmark starts.
        """
        state = self._load_state()

        # Never show if already given feedback
        if state.get("feedback_given", False):
            return False

        # Don't show if dismissed 3+ times
        if state.get("dismissed_count", 0) >= 3:
            return False

        total_runs = state.get("total_runs", 0)
        last_shown = state.get("last_shown", 0)
        current_time = time.time()

        # Show after 5, 15, 30 runs (progressive nudging)
        thresholds = [5, 15, 30]

        # Ensure at least 24 hours between prompts
        hours_since_last = (current_time - last_shown) / 3600

        # Check if we've just crossed a threshold
        # (current run is at or past threshold, but previous check wasn't)
        should_show = False
        for threshold in thresholds:
            if total_runs >= threshold:
                # Check if this is the first time at this threshold
                # by verifying we haven't shown since crossing it
                last_threshold_shown = state.get("last_threshold_shown", 0)
                if threshold > last_threshold_shown and hours_since_last >= 24:
                    should_show = True
                    state["last_threshold_shown"] = threshold
                    break

        # Update last_shown timestamp if we're showing the prompt
        if should_show:
            state["last_shown"] = current_time
            self._save_state(state)

        return should_show

    def mark_feedback_given(self) -> None:
        """Mark that user has given feedback."""
        try:
            state = self._load_state()
            state["feedback_given"] = True
            self._save_state(state)
        except Exception as e:
            import logging

            logging.warning(f"Failed to mark feedback as given: {e}")

    def mark_dismissed(self) -> None:
        """Mark that user dismissed the prompt."""
        try:
            state = self._load_state()
            state["dismissed_count"] = state.get("dismissed_count", 0) + 1
            self._save_state(state)
        except Exception as e:
            import logging

            logging.warning(f"Failed to mark feedback as dismissed: {e}")

    def reset(self) -> None:
        """Reset feedback state (for testing or user request)."""
        try:
            if self.config_file.exists():
                self.config_file.unlink()
        except Exception as e:
            import logging

            logging.warning(f"Failed to reset feedback state: {e}")


def show_feedback_prompt() -> None:
    """Show feedback prompt with improved logic."""
    manager = FeedbackManager()

    if not manager.should_show_prompt():
        return

    click.echo("\n" + "─" * 60)
    click.echo(click.style("📢 Quick feedback request", fg="cyan", bold=True))
    click.echo(
        click.style(
            "Help shape dns-benchmark! Share your biggest DNS challenge.", fg="cyan"
        )
    )
    click.echo(
        click.style("→ https://forms.gle/BJBiyBFvRJHskyR57 (2 min survey)", fg="cyan")
    )
    click.echo(click.style("→ Or run: dns-benchmark feedback", fg="cyan"))
    click.echo("─" * 60)

    # Give user option to dismiss
    try:
        response = click.prompt(
            "\nShow this again? (y/n)",
            type=click.Choice(["y", "n"], case_sensitive=False),
            default="y",
            show_default=True,
        )

        if response.lower() == "n":
            manager.mark_dismissed()
            click.echo(
                click.style(
                    "✓ Got it! We won't ask again. Thanks for using dns-benchmark!",
                    fg="green",
                )
            )
    except (KeyboardInterrupt, click.Abort):
        # User skipped - don't mark as dismissed
        click.echo()


@cli.command()
def feedback() -> None:
    """Share feedback and mark as completed."""
    import webbrowser

    manager = FeedbackManager()
    feedback_url = "https://forms.gle/BJBiyBFvRJHskyR57"

    click.echo(click.style("📢 Help us make dns-benchmark better!", fg="cyan"))
    click.echo(click.style("\n👉 Opening feedback form...", fg="green"))
    click.echo(click.style(f"\nOr visit: {feedback_url}\n", fg="yellow"))

    try:
        webbrowser.open(feedback_url)
        click.echo(click.style("Form opened! Thank you! 🙏", fg="green"))

        # Mark as given after opening
        manager.mark_feedback_given()

    except Exception:
        click.echo(click.style(f"Please visit: {feedback_url}", fg="red"))


# Hidden command for testing/resetting
@cli.command(hidden=True)
def reset_feedback() -> None:
    """Reset feedback prompt state (for testing)."""
    manager = FeedbackManager()
    manager.reset()
    click.echo(click.style("✓ Feedback state reset", fg="green"))


# =================== Benchmark command
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
@click.option("--iterations", "-i", default=1, help="Number of iterations")
@click.option("--warmup", is_flag=True, help="Run warmup queries before benchmark")
@click.option("--use-cache", is_flag=True, help="Allow cache usage across iterations")
@click.option(
    "--warmup-fast",
    is_flag=True,
    help="Run lightweight warmup (one probe per resolver)",
)
@click.option(
    "--include-charts", is_flag=True, help="Include charts in Excel and PDF exports"
)
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
    iterations: int,
    warmup: bool,
    warmup_fast: bool,
    use_cache: bool,
    include_charts: bool,  # NEW
) -> None:
    """Run DNS benchmark test."""

    print(f"DEBUG benchmark(): resolvers = {repr(resolvers)}")

    feedback_manager = FeedbackManager()
    benchmark_started = False

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

    # Load resolvers with error handling
    try:
        if use_defaults:
            resolver_list = ResolverManager.get_default_resolvers()
            if not quiet:
                click.echo(
                    success(f"Using default resolvers ({len(resolver_list)} resolvers)")
                )
        else:
            resolver_list = ResolverManager.parse_resolvers_input(
                resolvers if resolvers else ""
            )
            if not quiet:
                click.echo(success(f"Loaded {len(resolver_list)} resolvers"))
    except FileNotFoundError as e:
        click.echo(error(f"Resolver file not found: {e}"))
        return
    except Exception as e:
        click.echo(error(f"Error loading resolvers: {e}"))
        return

    # Load domains with error handling
    try:
        if use_defaults:
            domain_list = DomainManager.get_sample_domains()
            if not quiet:
                click.echo(
                    success(f"Using sample domains ({len(domain_list)} domains)")
                )
        else:
            domain_list = DomainManager.parse_domains_input(domains if domains else "")
            if not quiet:
                click.echo(success(f"Loaded {len(domain_list)} domains"))
    except FileNotFoundError as e:
        click.echo(error(f"Domain file not found: {e}"))
        return
    except Exception as e:
        click.echo(error(f"Error loading domains: {e}"))
        return

    # Calculate total queries
    total_queries = (
        len(resolver_list) * len(domain_list) * len(record_type_list) * iterations
    )
    if not quiet:
        click.echo(info("Configuration:"))
        click.echo(info(f"- Resolvers: {len(resolver_list)}"))
        click.echo(info(f"- Domains: {len(domain_list)}"))
        click.echo(info(f"- Record types: {', '.join(record_type_list)}"))
        click.echo(info(f"- Iterations: {iterations}"))
        click.echo(info(f"- Total queries: {total_queries}"))
        if use_cache:
            click.echo(info("- Cache enabled: queries may be reused across iterations"))

    # Show warmup message
    if (warmup or warmup_fast) and not quiet:
        warmup_type = "fast" if warmup_fast else "full"
        click.echo(info(f"Running {warmup_type} warmup queries..."))

    # Run benchmark
    if not quiet:
        click.echo(warning("Starting DNS benchmark..."))

    # Mark that benchmark is actually starting and increment run counter
    benchmark_started = True
    feedback_manager.increment_run()

    start_time = time.time()

    try:
        engine = DNSQueryEngine(
            max_concurrent_queries=max_concurrent,
            timeout=timeout,
            max_retries=retries,
            enable_cache=use_cache,
        )

        progress_bar = None
        if not quiet:
            progress_bar = create_progress_bar(total_queries, "DNS Queries")

            def _progress_cb(completed: int, total: int) -> None:
                """TQDM-friendly progress callback.

                Sets the absolute position of the progress bar.
                Keep this callback fast and non-blocking.
                """
                try:
                    if progress_bar:
                        progress_bar.n = completed  # Absolute position
                        progress_bar.refresh()
                except Exception:
                    # Never allow progress callback errors to interrupt benchmarking
                    pass

            engine.set_progress_callback(_progress_cb)

        results = asyncio.run(
            engine.run_benchmark(
                resolvers=resolver_list,
                domains=domain_list,
                record_types=record_type_list,
                iterations=iterations,
                warmup=warmup,
                warmup_fast=warmup_fast,
                use_cache=use_cache,
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
            # Add iteration info if multiple iterations
            if iterations > 1:
                cache_hits = sum(1 for r in results if r.cache_hit)
                summary_lines.append(f"Iterations: {iterations}")
                if use_cache and cache_hits > 0:
                    summary_lines.append(
                        f"Cache hits: {cache_hits} ({cache_hits / len(results) * 100:.1f}%)"
                    )

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

        export_count = len(output_formats) + (1 if json_output else 0)
        export_progress = (
            create_progress_bar(export_count, "Exporting") if not quiet else None
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
                    include_charts=include_charts,
                )
                if export_progress:
                    export_progress.update(1)

            if "pdf" in output_formats:
                try:
                    PDFExporter.export_results(
                        results,
                        analyzer,
                        str(output_path / f"{base_filename}.pdf"),
                        include_success_chart=include_charts,
                    )
                    if export_progress:
                        export_progress.update(1)
                except RuntimeError as e:
                    click.echo(error(f"Error during benchmark: {e}"))

            # JSON export now tracked in progress
            if json_output:
                ExportBundle.export_json(
                    results,
                    analyzer,
                    domain_stats=domain_stats_data,
                    record_type_stats=record_type_stats_data,
                    error_stats=error_stats_data,
                    output_path=str(output_path / f"{base_filename}.json"),
                )
                if export_progress:
                    export_progress.update(1)

            if not quiet:
                click.echo(success("All exports completed successfully!"))
                click.echo(info(f"Results saved to: {output_path}"))
                show_feedback_prompt()

        finally:
            if export_progress:
                export_progress.close()

    except KeyboardInterrupt:
        click.echo(warning("\nBenchmark interrupted by user"))
        # Still show feedback prompt since benchmark was started
        if benchmark_started and not quiet:
            show_feedback_prompt()
        return
    except Exception as e:
        click.echo(error(f"Error during benchmark: {e}"))
        # Still show feedback prompt since benchmark was attempted
        if benchmark_started and not quiet:
            show_feedback_prompt()
        raise

    # Show feedback prompt after successful completion
    # This runs only if no exceptions occurred
    if benchmark_started and not quiet:
        show_feedback_prompt()


# ====================== Top Resolvers Command
@cli.command()
@click.option("--limit", "-n", default=10, help="Number of top resolvers to display")
@click.option(
    "--metric",
    "-m",
    type=click.Choice(["latency", "success", "reliability"], case_sensitive=False),
    default="latency",
    help="Metric to rank by (latency=fastest, success=highest success rate, reliability=combined score)",
)
@click.option("--domains", "-d", help="Text file with domain list")
@click.option(
    "--record-types",
    "-t",
    default="A",
    help="DNS record types to query (comma-separated)",
)
@click.option("--timeout", default=5.0, help="Query timeout in seconds")
@click.option("--max-concurrent", default=100, help="Maximum concurrent queries")
@click.option(
    "--category",
    "-c",
    help="Filter resolvers by category (privacy, security, family, performance, etc.)",
)
@click.option(
    "--output", "-o", help="Optional: save results to file (supports .txt, .json, .csv)"
)
@click.option("--quiet", is_flag=True, help="Suppress progress output")
def top(
    limit: int,
    metric: str,
    domains: Optional[str],
    record_types: str,
    timeout: float,
    max_concurrent: int,
    category: Optional[str],
    output: Optional[str],
    quiet: bool,
) -> None:
    """Find and rank the top performing DNS resolvers.

    Examples:
        dns-benchmark top --limit 5
        dns-benchmark top --metric success --category privacy
        dns-benchmark top --limit 10 --output top_resolvers.json
    """
    start_time = time.time()
    if not quiet:
        click.echo(info("🔍 Finding top DNS resolvers..."))

    # Get resolvers
    if category:
        all_resolvers = ResolverManager.get_resolvers_by_category(category)
        if not all_resolvers:
            available = ", ".join(ResolverManager.get_categories())
            click.echo(error(f"No resolvers found for category '{category}'."))
            click.echo(info(f"Available categories: {available}"))
            return
        resolver_list = [{"name": r["name"], "ip": r["ip"]} for r in all_resolvers]
        if not quiet:
            click.echo(
                success(
                    f"Testing {len(resolver_list)} resolvers in category '{category}'"
                )
            )
    else:
        # Use all available resolvers for comprehensive ranking
        all_resolvers = ResolverManager.get_all_resolvers()
        resolver_list = [{"name": r["name"], "ip": r["ip"]} for r in all_resolvers]
        if not quiet:
            click.echo(success(f"Testing {len(resolver_list)} resolvers"))

    # Get domains
    if domains:
        try:
            domain_list = DomainManager.load_domains_from_file(domains)
        except Exception as e:
            click.echo(error(f"Error loading domains: {e}"))
            return
    else:
        domain_list = DomainManager.get_sample_domains()

    # Parse record types
    record_type_list = [rt.strip().upper() for rt in record_types.split(",")]

    # Run benchmark
    total_queries = len(resolver_list) * len(domain_list) * len(record_type_list)
    if not quiet:
        click.echo(info(f"Running {total_queries} queries..."))

    progress_bar = None
    if not quiet:
        progress_bar = create_progress_bar(total_queries, "Testing resolvers")

    try:
        engine = DNSQueryEngine(
            max_concurrent_queries=max_concurrent,
            timeout=timeout,
            enable_cache=False,
        )

        if progress_bar:

            def _progress_cb(completed: int, total: int) -> None:
                try:
                    if progress_bar:
                        progress_bar.n = completed
                        progress_bar.refresh()
                except Exception:
                    pass

            engine.set_progress_callback(_progress_cb)

        results = asyncio.run(
            engine.run_benchmark(
                resolvers=resolver_list,
                domains=domain_list,
                record_types=record_type_list,
                warmup_fast=True,
            )
        )

        if progress_bar:
            progress_bar.close()

        duration = time.time() - start_time

        if not quiet:
            click.echo(success(f"Benchmark completed in {duration:.2f} seconds"))

        # Analyze and rank
        analyzer = BenchmarkAnalyzer(results)
        resolver_stats_list = analyzer.get_resolver_statistics()

        # Convert list of ResolverStats objects to dict for easier lookup
        resolver_stats = {stats.resolver_name: stats for stats in resolver_stats_list}

        # Calculate ranking score based on metric
        scored_resolvers = []
        for name, stats in resolver_stats.items():
            if metric == "latency":
                if stats.successful_queries > 0 and stats.avg_latency is not None:
                    score = -stats.avg_latency
                else:
                    score = float("-inf")  # push failed resolvers to bottom

            elif metric == "success":
                # Higher is better
                score = stats.success_rate
            else:  # reliability (combined)
                # Weighted score: 60% success rate, 40% speed (normalized)
                if stats.successful_queries > 0 and stats.avg_latency not in (None, 0):
                    latency_score = max(0, 100 - (stats.avg_latency / 5))
                    score = (stats.success_rate * 0.6) + (latency_score * 0.4)
                else:
                    score = stats.success_rate * 0.6

            scored_resolvers.append((name, stats, score))

        # Sort by score (descending)
        scored_resolvers.sort(key=lambda x: x[2], reverse=True)

        # Display top N
        top_resolvers = scored_resolvers[:limit]

        if not quiet:
            click.echo(
                success(f"\n🏆 Top {len(top_resolvers)} DNS Resolvers (by {metric}):\n")
            )

            for rank, (name, stats, score) in enumerate(top_resolvers, 1):
                medal = (
                    "🥇"
                    if rank == 1
                    else "🥈" if rank == 2 else "🥉" if rank == 3 else f"{rank}."
                )

                click.echo(Fore.CYAN + f"{medal} {name}" + Style.RESET_ALL)
                latency_str = (
                    f"{stats.avg_latency:.2f} ms"
                    if stats.avg_latency is not None
                    else "N/A"
                )
                click.echo(
                    f"   Avg Latency: {Fore.GREEN}{latency_str}{Style.RESET_ALL}"
                )
                click.echo(
                    f"   Success Rate: {Fore.GREEN}{stats.success_rate:.1f}%{Style.RESET_ALL}"
                )
                click.echo(
                    f"   Queries: {stats.successful_queries}/{stats.total_queries}"
                )

                if metric == "reliability":
                    click.echo(
                        f"   Reliability Score: {Fore.YELLOW}{score:.2f}/100{Style.RESET_ALL}"
                    )
                click.echo()

        # Export if requested
        if output:
            output_path = Path(output)
            ext = output_path.suffix.lower()

            if ext == ".json":
                export_data = {
                    "timestamp": datetime.now().isoformat(),
                    "metric": metric,
                    "category": category,
                    "top_resolvers": [
                        {
                            "rank": i + 1,
                            "name": name,
                            "avg_latency_ms": stats.avg_latency,
                            "success_rate": stats.success_rate,
                            "successful_queries": stats.successful_queries,
                            "total_queries": stats.total_queries,
                            # "score": score,
                        }
                        for i, (name, stats, score) in enumerate(top_resolvers)
                    ],
                }
                with open(output_path, "w") as f:
                    json.dump(export_data, f, indent=2)

            elif ext == ".csv":
                import csv

                with open(output_path, "w", newline="") as f:
                    writer = csv.writer(f)
                    writer.writerow(
                        [
                            "Rank",
                            "Resolver",
                            "Avg Latency (ms)",
                            "Success Rate (%)",
                            "Successful",
                            "Total",
                            # "Score"
                        ]
                    )
                    for i, (name, stats, score) in enumerate(top_resolvers, 1):
                        writer.writerow(
                            [
                                i,
                                name,
                                (
                                    f"{stats.avg_latency:.2f}"
                                    if stats.avg_latency is not None
                                    else "N/A"
                                ),
                                f"{stats.success_rate:.1f}",
                                stats.successful_queries,
                                stats.total_queries,
                                # f"{score:.2f}"
                            ]
                        )

            else:  # .txt or default
                with open(output_path, "w") as f:
                    f.write(f"Top {len(top_resolvers)} DNS Resolvers (by {metric})\n")
                    f.write(
                        f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
                    )
                    if category:
                        f.write(f"Category: {category}\n")
                    f.write("\n" + "=" * 60 + "\n\n")

                    for rank, (name, stats, score) in enumerate(top_resolvers, 1):
                        f.write(f"{rank}. {name}\n")
                        f.write(
                            f"   Avg Latency: {stats.avg_latency:.2f} ms\n"
                            if stats.avg_latency is not None
                            else "   Avg Latency: N/A\n"
                        )
                        f.write(f"   Success Rate: {stats.success_rate:.1f}%\n")
                        f.write(
                            f"   Queries: {stats.successful_queries}/{stats.total_queries}\n"
                        )
                        # if metric == "reliability":
                        #     f.write(f"   Score: {score:.2f}/100\n")
                        f.write("\n")
            # Add summary note if any resolvers had no successful queries
            failed_resolvers = [
                s for s in resolver_stats.values() if s.successful_queries == 0
            ]
            if failed_resolvers and not quiet:
                click.echo(
                    warning(
                        "⚠️ Some resolvers returned no successful queries and were excluded from ranking"
                    )
                )

            if not quiet:
                click.echo(success(f"Results saved to: {output_path}"))

    except KeyboardInterrupt:
        if progress_bar:
            progress_bar.close()
        click.echo(warning("\nTest interrupted by user"))
    except Exception as e:
        if progress_bar:
            progress_bar.close()
        click.echo(error(f"Error during test: {e}"))
        raise


# ======================= Compare
@cli.command()
@click.argument("resolvers", nargs=-1, required=True)
@click.option("--domains", "-d", help="Text file with domain list")
@click.option(
    "--record-types",
    "-t",
    default="A",
    help="DNS record types to query (comma-separated)",
)
@click.option("--timeout", default=5.0, help="Query timeout in seconds")
@click.option("--max-concurrent", default=100, help="Maximum concurrent queries")
@click.option("--iterations", "-i", default=3, help="Number of test iterations")
@click.option("--output", "-o", help="Optional: save comparison to file")
@click.option("--quiet", is_flag=True, help="Suppress progress output")
@click.option("--show-details", is_flag=True, help="Show detailed per-domain breakdown")
def compare(
    resolvers: Tuple[str],
    domains: Optional[str],
    record_types: str,
    timeout: float,
    max_concurrent: int,
    iterations: int,
    output: Optional[str],
    quiet: bool,
    show_details: bool,
) -> None:
    """Compare specific DNS resolvers side-by-side.

    You can specify resolvers by name or IP address.

    Examples:
        dns-benchmark compare Cloudflare Google Quad9
        dns-benchmark compare 1.1.1.1 8.8.8.8 9.9.9.9
        dns-benchmark compare "Cloudflare" "Google" --iterations 5
    """
    if not quiet:
        click.echo(info(f"🔬 Comparing {len(resolvers)} DNS resolvers..."))

    # Resolve resolver names to IPs
    all_resolvers = ResolverManager.get_all_resolvers()
    resolver_list = []

    for resolver_input in resolvers:
        # Try to match by name first
        matched = False
        for r in all_resolvers:
            if r["name"].lower() == resolver_input.lower():
                resolver_list.append({"name": r["name"], "ip": r["ip"]})
                matched = True
                break

        # If no name match, assume it's an IP
        if not matched:
            # Validate IP format (basic check)
            if "." in resolver_input or ":" in resolver_input:
                resolver_list.append({"name": resolver_input, "ip": resolver_input})
            else:
                click.echo(warning(f"Could not resolve '{resolver_input}' - skipping"))

    if len(resolver_list) < 2:
        click.echo(error("Need at least 2 valid resolvers to compare"))
        return

    if not quiet:
        click.echo(
            success(f"Comparing: {', '.join([r['name'] for r in resolver_list])}")
        )

    # Get domains
    if domains:
        try:
            domain_list = DomainManager.load_domains_from_file(domains)
        except Exception as e:
            click.echo(error(f"Error loading domains: {e}"))
            return
    else:
        domain_list = DomainManager.get_sample_domains()

    # Parse record types
    record_type_list = [rt.strip().upper() for rt in record_types.split(",")]

    # Run benchmark
    total_queries = (
        len(resolver_list) * len(domain_list) * len(record_type_list) * iterations
    )
    if not quiet:
        click.echo(
            info(f"Running {total_queries} queries across {iterations} iterations...")
        )

    progress_bar = None
    if not quiet:
        progress_bar = create_progress_bar(total_queries, "Comparing")

    try:
        engine = DNSQueryEngine(
            max_concurrent_queries=max_concurrent,
            timeout=timeout,
            enable_cache=False,
        )

        if progress_bar:

            def _progress_cb(completed: int, total: int) -> None:
                try:
                    if progress_bar:
                        progress_bar.n = completed
                        progress_bar.refresh()
                except Exception:
                    pass

            engine.set_progress_callback(_progress_cb)

        results = asyncio.run(
            engine.run_benchmark(
                resolvers=resolver_list,
                domains=domain_list,
                record_types=record_type_list,
                iterations=iterations,
                warmup_fast=True,
            )
        )

        if progress_bar:
            progress_bar.close()

        # Analyze
        analyzer = BenchmarkAnalyzer(results)
        resolver_stats_list = analyzer.get_resolver_statistics()

        # Convert list of ResolverStats objects to dict for easier lookup
        resolver_stats = {stats.resolver_name: stats for stats in resolver_stats_list}

        # Display comparison
        if not quiet:
            click.echo(success("📊 Comparison Results:\n"))

            # Header
            click.echo(
                Fore.CYAN
                + f"{'Resolver':<20} {'Avg Latency':<15} {'Success Rate':<15} {'Queries':<10}"
                + Style.RESET_ALL
            )
            click.echo("-" * 65)

            # Sort by latency for display
            sorted_stats = sorted(
                resolver_stats.items(), key=lambda x: x[1].avg_latency
            )

            for name, stats in sorted_stats:
                latency_color = (
                    Fore.GREEN
                    if stats.avg_latency < 50
                    else Fore.YELLOW if stats.avg_latency < 100 else Fore.RED
                )
                success_color = (
                    Fore.GREEN
                    if stats.success_rate >= 95
                    else Fore.YELLOW if stats.success_rate >= 80 else Fore.RED
                )

                click.echo(
                    f"{name:<20} "
                    f"{latency_color}{stats.avg_latency:>6.2f} ms{Style.RESET_ALL}{'':>4} "
                    f"{success_color}{stats.success_rate:>6.1f}%{Style.RESET_ALL}{'':>6} "
                    f"{stats.successful_queries}/{stats.total_queries}"
                )

            # Winner
            click.echo()
            fastest = min(sorted_stats, key=lambda x: x[1].avg_latency)
            most_reliable = max(sorted_stats, key=lambda x: x[1].success_rate)

            click.echo(
                Fore.GREEN
                + "🏆 Fastest: "
                + Style.RESET_ALL
                + f"{fastest[0]} ({fastest[1].avg_latency:.2f} ms)"
            )
            click.echo(
                Fore.GREEN
                + "🛡️  Most Reliable: "
                + Style.RESET_ALL
                + f"{most_reliable[0]} ({most_reliable[1].success_rate:.1f}%)"
            )

            # Per-domain details if requested
            if show_details:
                click.echo(success("📋 Per-Domain Breakdown:\n"))
                domain_stats = analyzer.get_domain_statistics()

                for dom_stat in domain_stats[:10]:  # Limit to first 10
                    domain = dom_stat["domain"]
                    click.echo(Fore.CYAN + f"\n{domain}:" + Style.RESET_ALL)

                    for name in [r["name"] for r in resolver_list]:
                        # Find results for this resolver+domain
                        domain_results = [
                            r
                            for r in results
                            if r.resolver_name == name and r.domain == domain
                        ]
                        if domain_results:
                            avg_lat = sum(r.latency_ms for r in domain_results) / len(
                                domain_results
                            )
                            successes = sum(
                                1
                                for r in domain_results
                                if r.status == QueryStatus.SUCCESS
                            )
                            click.echo(
                                f"  {name:<20} {avg_lat:>6.2f} ms  ({successes}/{len(domain_results)} success)"
                            )

        # Export if requested
        if output:
            output_path = Path(output)
            ext = output_path.suffix.lower()

            if ext == ".json":
                import json

                export_data = {
                    "timestamp": datetime.now().isoformat(),
                    "iterations": iterations,
                    "comparison": [
                        {
                            "resolver": name,
                            "avg_latency_ms": stats.avg_latency,
                            "median_latency_ms": stats.median_latency,
                            "success_rate": stats.success_rate,
                            "successful_queries": stats.successful_queries,
                            "total_queries": stats.total_queries,
                        }
                        for name, stats in resolver_stats.items()
                    ],
                }
                with open(output_path, "w") as f:
                    json.dump(export_data, f, indent=2)

            else:  # csv
                CSVExporter.export_summary_statistics(analyzer, str(output_path))

            if not quiet:
                click.echo(success(f"Comparison saved to: {output_path}"))

    except KeyboardInterrupt:
        if progress_bar:
            progress_bar.close()
        click.echo(warning("Comparison interrupted by user"))
    except Exception as e:
        if progress_bar:
            progress_bar.close()
        click.echo(error(f"Error during comparison: {e}"))
        raise


# ==================== Monitoring Command
@cli.command()
@click.option("--resolvers", "-r", help="JSON file with resolver list")
@click.option("--domains", "-d", help="Text file with domain list")
@click.option(
    "--interval",
    "-i",
    default=60,
    help="Monitoring interval in seconds (default: 60)",
)
@click.option(
    "--duration",
    default=0,
    help="Total monitoring duration in seconds (0 = indefinite)",
)
@click.option(
    "--alert-latency",
    default=200.0,
    help="Alert if latency exceeds this threshold (ms)",
)
@click.option(
    "--alert-failure-rate",
    default=10.0,
    help="Alert if failure rate exceeds this threshold (%)",
)
@click.option("--output", "-o", help="Log file for monitoring results")
@click.option(
    "--use-defaults", is_flag=True, help="Use default resolvers and sample domains"
)
def monitoring(
    resolvers: Optional[str],
    domains: Optional[str],
    interval: int,
    duration: int,
    alert_latency: float,
    alert_failure_rate: float,
    output: Optional[str],
    use_defaults: bool,
) -> None:
    """Continuously monitor DNS resolver performance.

    Monitor DNS resolvers in real-time and alert on issues.

    Examples:
        dns-benchmark monitoring --use-defaults
        dns-benchmark monitoring --interval 30 --duration 3600
        dns-benchmark monitoring --alert-latency 150 --output monitor.log
    """
    click.echo(info("🔄 Starting DNS monitoring..."))
    click.echo(warning("Press Ctrl+C to stop monitoring\n"))

    # Load resolvers
    if use_defaults:
        resolver_list = ResolverManager.get_default_resolvers()
        click.echo(success(f"Monitoring {len(resolver_list)} default resolvers"))
    elif resolvers:
        try:
            resolver_list = ResolverManager.load_resolvers_from_file(resolvers)
            click.echo(success(f"Monitoring {len(resolver_list)} resolvers"))
        except Exception as e:
            click.echo(error(f"Error loading resolvers: {e}"))
            return
    else:
        click.echo(error("Either provide --resolvers or use --use-defaults"))
        return

    # Load domains
    if use_defaults:
        # Use a smaller set for monitoring
        domain_list = DomainManager.get_sample_domains()[:5]
    elif domains:
        try:
            domain_list = DomainManager.load_domains_from_file(domains)
        except Exception as e:
            click.echo(error(f"Error loading domains: {e}"))
            return
    else:
        domain_list = DomainManager.get_sample_domains()[:5]

    click.echo(info(f"Testing against {len(domain_list)} domains"))
    click.echo(info(f"Check interval: {interval}s"))
    if duration > 0:
        click.echo(info(f"Duration: {duration}s"))
    click.echo(info(f"Latency alert threshold: {alert_latency} ms"))
    click.echo(info(f"Failure rate alert threshold: {alert_failure_rate}%\n"))

    # Setup output log
    log_file = None
    if output:
        log_file = open(output, "a")
        log_file.write(f"\n{'=' * 60}\n")
        log_file.write(
            f"Monitoring started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        )
        log_file.write(f"{'=' * 60}\n\n")

    start_time = time.time()
    iteration = 0

    try:
        while True:
            iteration += 1
            check_time = datetime.now().strftime("%H:%M:%S")

            click.echo(
                Fore.CYAN + f"[{check_time}] Check #{iteration}" + Style.RESET_ALL
            )

            # Run quick benchmark
            engine = DNSQueryEngine(
                max_concurrent_queries=50,
                timeout=5.0,
                enable_cache=False,
            )

            results = asyncio.run(
                engine.run_benchmark(
                    resolvers=resolver_list,
                    domains=domain_list,
                    record_types=["A"],
                    warmup=False,
                )
            )

            # Analyze
            analyzer = BenchmarkAnalyzer(results)
            resolver_stats_list = analyzer.get_resolver_statistics()

            # Check for alerts
            alerts = []
            for stats in resolver_stats_list:
                if stats.avg_latency > alert_latency:
                    alerts.append(
                        f"⚠️  {stats.resolver_name}: High latency ({stats.avg_latency:.2f} ms)"
                    )

                failure_rate = 100 - stats.success_rate
                if failure_rate > alert_failure_rate:
                    alerts.append(
                        f"⚠️  {stats.resolver_name}: High failure rate ({failure_rate:.1f}%)"
                    )

            # Display results
            for stats in resolver_stats_list:
                latency_indicator = (
                    "🟢"
                    if stats.avg_latency < 50
                    else "🟡" if stats.avg_latency < 100 else "🔴"
                )
                success_indicator = (
                    "🟢"
                    if stats.success_rate >= 95
                    else "🟡" if stats.success_rate >= 80 else "🔴"
                )

                status_line = f"  {stats.resolver_name:<20} {latency_indicator} {stats.avg_latency:>6.2f} ms  {success_indicator} {stats.success_rate:>5.1f}%"
                click.echo(status_line)

                if log_file:
                    log_file.write(
                        f"[{check_time}] {stats.resolver_name}: {stats.avg_latency:.2f} ms, {stats.success_rate:.1f}% success\n"
                    )

            # Display alerts
            if alerts:
                click.echo()
                for alert in alerts:
                    click.echo(Fore.RED + alert + Style.RESET_ALL)
                    if log_file:
                        log_file.write(f"[{check_time}] ALERT: {alert}\n")

            click.echo()

            if log_file:
                log_file.flush()

            # Check duration
            if duration > 0 and (time.time() - start_time) >= duration:
                click.echo(success("Monitoring duration completed"))
                break

            # Wait for next interval
            time.sleep(interval)

    except KeyboardInterrupt:
        click.echo(warning("Monitoring stopped by user"))
    except Exception as e:
        click.echo(error(f"Error during monitoring: {e}"))
        raise
    finally:
        if log_file:
            log_file.write(
                f"Monitoring ended: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            )
            log_file.close()
            click.echo(success(f"Monitoring log saved to: {output}"))


# ===================== List Defaults Command
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


# ===================== List Resolvers Command
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


# ====================== List Domains Command
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


# ======================= List Categories Command
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


#  ====================== Generate Config Command
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
