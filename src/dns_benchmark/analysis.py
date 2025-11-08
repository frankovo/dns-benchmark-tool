"""Statistical analysis of DNS benchmark results."""

from dataclasses import dataclass
from typing import Any, Dict, List, cast

import pandas as pd

from dns_benchmark.core import DNSQueryResult, QueryStatus


@dataclass
class ResolverStats:
    """Statistics for a single resolver."""

    resolver_name: str
    resolver_ip: str
    total_queries: int
    successful_queries: int
    success_rate: float
    min_latency: float
    max_latency: float
    avg_latency: float
    median_latency: float
    std_latency: float
    p95_latency: float
    p99_latency: float


class BenchmarkAnalyzer:
    """Analyze DNS benchmark results and compute statistics."""

    def __init__(self, results: List[DNSQueryResult]):
        self.results = results
        self.df = self._create_dataframe()

    def _create_dataframe(self) -> pd.DataFrame:
        """Convert results to pandas DataFrame."""
        data = []
        for result in self.results:
            data.append(
                {
                    "resolver_name": result.resolver_name,
                    "resolver_ip": result.resolver_ip,
                    "domain": result.domain,
                    "record_type": result.record_type,
                    "latency_ms": result.latency_ms,
                    "status": result.status.value,
                    "success": result.status == QueryStatus.SUCCESS,
                    "answers_count": len(result.answers),
                    "ttl": result.ttl or 0,
                    "error_message": result.error_message or "",
                }
            )

        return pd.DataFrame(data)

    def get_resolver_statistics(self) -> List[ResolverStats]:
        """Compute statistics per resolver."""
        resolver_stats = []

        for resolver_name in self.df["resolver_name"].unique():
            resolver_data = self.df[self.df["resolver_name"] == resolver_name]
            resolver_ip = resolver_data["resolver_ip"].iloc[0]

            # Basic counts
            total_queries = len(resolver_data)
            successful_queries = len(resolver_data[resolver_data["success"] == True])
            success_rate = (
                (successful_queries / total_queries) * 100 if total_queries > 0 else 0
            )

            # Latency statistics (only for successful queries)
            successful_latencies = resolver_data[resolver_data["success"] == True][
                "latency_ms"
            ]

            if len(successful_latencies) > 0:
                min_latency = float(successful_latencies.min())
                max_latency = float(successful_latencies.max())
                avg_latency = float(successful_latencies.mean())
                median_latency = float(successful_latencies.median())
                std_latency = float(successful_latencies.std())
                p95_latency = float(successful_latencies.quantile(0.95))
                p99_latency = float(successful_latencies.quantile(0.99))
            else:
                min_latency = max_latency = avg_latency = median_latency = (
                    std_latency
                ) = 0.0
                p95_latency = p99_latency = 0.0

            stats = ResolverStats(
                resolver_name=resolver_name,
                resolver_ip=resolver_ip,
                total_queries=total_queries,
                successful_queries=successful_queries,
                success_rate=success_rate,
                min_latency=min_latency,
                max_latency=max_latency,
                avg_latency=avg_latency,
                median_latency=median_latency,
                std_latency=std_latency,
                p95_latency=p95_latency,
                p99_latency=p99_latency,
            )

            resolver_stats.append(stats)

        return resolver_stats

    def get_overall_statistics(self) -> Dict[str, Any]:
        """Get overall benchmark statistics."""
        total_queries = len(self.df)
        successful_queries = len(self.df[self.df["success"] == True])
        overall_success_rate = (
            (successful_queries / total_queries) * 100 if total_queries > 0 else 0
        )

        successful_latencies = self.df[self.df["success"] == True]["latency_ms"]

        if len(successful_latencies) > 0:
            overall_avg_latency = float(successful_latencies.mean())
            overall_median_latency = float(successful_latencies.median())
        else:
            overall_avg_latency = overall_median_latency = 0.0

        # Rank resolvers by average latency
        resolver_stats = self.get_resolver_statistics()
        ranked_resolvers = sorted(
            [r for r in resolver_stats if r.successful_queries > 0],
            key=lambda x: x.avg_latency,
        )

        return {
            "total_queries": total_queries,
            "successful_queries": successful_queries,
            "overall_success_rate": overall_success_rate,
            "overall_avg_latency": overall_avg_latency,
            "overall_median_latency": overall_median_latency,
            "fastest_resolver": (
                ranked_resolvers[0].resolver_name if ranked_resolvers else "N/A"
            ),
            "slowest_resolver": (
                ranked_resolvers[-1].resolver_name if ranked_resolvers else "N/A"
            ),
            "resolver_count": len(resolver_stats),
            "domain_count": len(self.df["domain"].unique()),
        }

    def get_domain_statistics(self) -> List[Dict[str, Any]]:
        """Compute statistics per domain across all resolvers."""
        domain_stats: List[Dict[str, Any]] = []
        for domain in self.df["domain"].unique():
            dd = self.df[self.df["domain"] == domain]
            total = len(dd)
            success = len(dd[dd["success"] == True])
            rate = (success / total) * 100 if total > 0 else 0.0

            latencies = dd[dd["success"] == True]["latency_ms"]
            stats = {
                "domain": domain,
                "total_queries": total,
                "successful_queries": success,
                "success_rate": rate,
                "min_latency": float(latencies.min()) if len(latencies) else 0.0,
                "avg_latency": float(latencies.mean()) if len(latencies) else 0.0,
                "median_latency": float(latencies.median()) if len(latencies) else 0.0,
                "max_latency": float(latencies.max()) if len(latencies) else 0.0,
                "p95_latency": (
                    float(latencies.quantile(0.95)) if len(latencies) else 0.0
                ),
            }
            domain_stats.append(stats)
        return domain_stats

    def get_record_type_statistics(self) -> List[Dict[str, Any]]:
        """Compute statistics per DNS record type across all resolvers/domains."""
        rt_stats: List[Dict[str, Any]] = []
        for rt in self.df["record_type"].unique():
            rt_df = self.df[self.df["record_type"] == rt]
            total = len(rt_df)
            success = len(rt_df[rt_df["success"] == True])
            rate = (success / total) * 100 if total > 0 else 0.0
            latencies = rt_df[rt_df["success"] == True]["latency_ms"]
            rt_stats.append(
                {
                    "record_type": rt,
                    "total_queries": total,
                    "successful_queries": success,
                    "success_rate": rate,
                    "avg_latency": float(latencies.mean()) if len(latencies) else 0.0,
                    "p95_latency": (
                        float(latencies.quantile(0.95)) if len(latencies) else 0.0
                    ),
                }
            )
        return rt_stats

    def get_error_statistics(self) -> Dict[str, int]:
        """Count errors by message across all failed queries."""
        errors = self.df[self.df["success"] == False]["error_message"]
        return cast(Dict[str, int], errors.value_counts().to_dict())
