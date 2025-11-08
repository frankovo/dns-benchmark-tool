from dns_benchmark.analysis import BenchmarkAnalyzer


def test_analyzer_domain_record_error_stats(sample_results):
    analyzer = BenchmarkAnalyzer(sample_results)

    domains = analyzer.get_domain_statistics()
    assert domains and any(d["domain"] == "example.com" for d in domains)
    assert any("avg_latency" in d for d in domains)

    record_types = analyzer.get_record_type_statistics()
    assert record_types and any(rt["record_type"] == "A" for rt in record_types)

    errors = analyzer.get_error_statistics()
    assert isinstance(errors, dict)
    assert errors.get("Non-existent domain", 0) >= 1

    overall = analyzer.get_overall_statistics()
    assert overall["total_queries"] == len(sample_results)
    assert "fastest_resolver" in overall
    assert "slowest_resolver" in overall
