<div align="center">

# DNS Benchmark Tool

**Fast, comprehensive DNS performance testing**

Part of [BuildTools](https://buildtools.net) - Network Performance Suite

```bash
pip install dns-benchmark-tool
dns-benchmark benchmark --use-defaults
```

---

> 🎉 **1,400+ downloads this week!** Thank you to our growing community.  

</div>

## 🎉 Today’s Release Highlights ![new](https://img.shields.io/pypi/v/dns-benchmark-tool.svg?color=brightgreen&label=new)

We’ve added **three powerful CLI commands** to make DNS benchmarking even more versatile:

- 🚀 **top** — quick ranking of resolvers by speed and reliability  
- 📊 **compare** — side‑by‑side benchmarking with detailed statistics and export options  
- 🔄 **monitoring** — continuous performance tracking with alerts and logging  

```bash
# Quick resolver ranking
dns-benchmark top --use-defaults

# Compare resolvers side-by-side
dns-benchmark compare Cloudflare Google Quad9 --show-details

# Run monitoring for 1 hour with alerts
dns-benchmark monitoring --use-defaults --interval 30 --duration 3600 \
  --alert-latency 150 --alert-failure-rate 5 --output monitor.log
```

---

[![CI Tests](https://github.com/frankovo/dns-benchmark-tool/actions/workflows/test.yml/badge.svg)](https://github.com/frankovo/dns-benchmark-tool/actions/workflows/test.yml)
[![Publish to TestPyPI](https://github.com/frankovo/dns-benchmark-tool/actions/workflows/testpypi.yml/badge.svg)](https://github.com/frankovo/dns-benchmark-tool/actions/workflows/testpypi.yml)
[![Publish to PyPI](https://github.com/frankovo/dns-benchmark-tool/actions/workflows/pypi.yml/badge.svg)](https://github.com/frankovo/dns-benchmark-tool/actions/workflows/pypi.yml)
[![PyPI version](https://img.shields.io/pypi/v/dns-benchmark-tool.svg?color=brightgreen)](https://pypi.org/project/dns-benchmark-tool/)

![Python Version](https://img.shields.io/badge/python-3.9%2B-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Coverage](https://img.shields.io/badge/coverage-91%25-brightgreen.svg)

[![Downloads](https://img.shields.io/pypi/dm/dns-benchmark-tool.svg?color=blueviolet)](https://pypi.org/project/dns-benchmark-tool/)
[![GitHub stars](https://img.shields.io/github/stars/frankovo/dns-benchmark-tool.svg?style=social&label=Star)](https://github.com/frankovo/dns-benchmark-tool/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/frankovo/dns-benchmark-tool.svg?style=social&label=Fork)](https://github.com/frankovo/dns-benchmark-tool/network/members)
[![Issues](https://img.shields.io/github/issues/frankovo/dns-benchmark-tool.svg?color=orange)](https://github.com/frankovo/dns-benchmark-tool/issues)
[![Last commit](https://img.shields.io/github/last-commit/frankovo/dns-benchmark-tool.svg?color=blue)](https://github.com/frankovo/dns-benchmark-tool/commits/main)
[![Main branch protected](https://img.shields.io/badge/branch%20protection-main%20✅-brightgreen)](https://github.com/frankovo/dns-benchmark-tool/blob/main/RELEASE.md)

## Why DNS Benchmarking?

DNS resolution can add 300ms+ to every request. This tool helps you find the fastest resolver for YOUR location.

**The Problem:**

- DNS adds hidden latency to every request
- Fastest resolver depends on your location
- Security varies wildly (DNSSEC, DoH, DoT)
- Most developers never test their DNS

**The Solution:**

- Test multiple DNS resolvers side-by-side
- Get statistical analysis (P95, P99, jitter, consistency)
- Validate DNSSEC security
- Compare privacy options (DoH, DoT, DoQ)

---

## Key Features

### 🚀 Performance

✅ Async queries let you test 100+ resolvers simultaneously.  
✅ Multi‑iteration runs (`--iterations 3`) provide more accurate results.  
✅ Statistical analysis includes P95, P99, jitter, and consistency scores.  
✅ Smart caching reuses results with `--use-cache`.  
✅ Warmup options (`--warmup` or `--warmup-fast`) ensure accurate tests.  

### 🔒 Security & Privacy

✅ DNSSEC validation verifies cryptographic trust chains.  
✅ DNS-over-HTTPS (DoH) enables encrypted DNS benchmarking.  
✅ DNS-over-TLS (DoT) secures transport testing.  
✅ DNS-over-QUIC (DoQ) adds experimental QUIC support.  
✅ TSIG authentication provides enterprise-grade secure queries.  

### 📊 Analysis & Export

✅ Multiple formats supported: CSV, Excel, PDF, JSON.  
✅ Visual reports with charts and graphs in PDF/Excel.  
✅ Domain statistics via `--domain-stats` for per-domain analysis.  
✅ Record type statistics (`--record-type-stats`) compare A, AAAA, MX, etc.  
✅ Error breakdown (`--error-breakdown`) highlights problematic resolvers.  

### 🏢 Enterprise Features

✅ Zone transfers (AXFR/IXFR) validate DNS migrations.  
✅ Dynamic updates allow DNS write operation testing.  
✅ EDNS0 support extends DNS features.  
✅ Windows WMI integration auto-detects system DNS.  
✅ Compliance reports generate audit-ready PDF/Excel documentation.  

### 🌐 Cross-Platform

✅ Native support for Linux, macOS, and Windows.  
✅ CI/CD friendly with JSON output, exit codes, and `--quiet` mode.  
✅ IDNA support for internationalized domain names.  
✅ Custom configurations using JSON resolvers and text domain lists.  

## Installation

```bash
pip install dns-benchmark-tool
```

## Quick usage

```bash
# Run first benchmark
dns-benchmark benchmark --use-defaults

# Custom resolvers and domains
dns-benchmark benchmark --resolvers data/resolvers.json --domains data/domains.txt

# Results saved to ./benchmark_results/
```

---

## 📖 Usage Examples

### Basic Usage

```bash
# Basic test with progress bars
dns-benchmark benchmark --use-defaults

# Basic test without progress bars
dns-benchmark benchmark --use-defaults --quiet

# Test with custom resolvers and domains
dns-benchmark benchmark --resolvers data/resolvers.json --domains data/domains.txt

# Quick test with only CSV output
dns-benchmark benchmark --use-defaults --formats csv
```

### Advanced Usage

```bash
# Export a machine-readable bundle
dns-benchmark benchmark --use-defaults --json --output ./results

# Test specific record types
dns-benchmark benchmark --use-defaults --record-types A,AAAA,MX

# Custom output location and formats
dns-benchmark benchmark \
  --use-defaults \
  --output ./my-results \
  --formats csv,excel,pdf,json

# Include detailed statistics
dns-benchmark benchmark \
  --use-defaults \
  --record-type-stats \
  --error-breakdown

# High concurrency with retries
dns-benchmark benchmark \
  --use-defaults \
  --max-concurrent 200 \
  --timeout 3.0 \
  --retries 3

# Website migration planning
dns-benchmark benchmark \
  --resolvers data/global_resolvers.json \
  --domains data/migration_domains.txt \
  --formats excel,pdf \
  --output ./migration_analysis

# DNS provider selection
dns-benchmark benchmark \
  --resolvers data/provider_candidates.json \
  --domains data/business_domains.txt \
  --formats csv,excel \
  --output ./provider_selection

# Network troubleshooting
dns-benchmark benchmark \
  --resolvers "192.168.1.1,1.1.1.1,8.8.8.8" \
  --domains "problematic-domain.com,working-domain.com" \
  --timeout 10 \
  --retries 3 \
  --formats csv \
  --output ./troubleshooting

# Security assessment
dns-benchmark benchmark \
  --resolvers data/security_resolvers.json \
  --domains data/security_test_domains.txt \
  --formats pdf \
  --output ./security_assessment

# Performance monitoring
dns-benchmark benchmark \
  --use-defaults \
  --formats csv \
  --quiet \
  --output /var/log/dns_benchmark/$(date +%Y%m%d_%H%M%S)
```

### Utilities

```bash
# List default resolvers and domains
dns-benchmark list-defaults

# Browse available resolvers
dns-benchmark list-resolvers
dns-benchmark list-resolvers --category privacy
dns-benchmark list-resolvers --format csv

# Browse test domains
dns-benchmark list-domains
dns-benchmark list-domains --category tech

# Generate sample config
dns-benchmark generate-config --output my-config.yaml
dns-benchmark generate-config --category security --output security.yaml
```

---

## Real-World Use Cases

**For Developers & DevOps/SRE:**

```bash
# Optimize API performance
dns-benchmark benchmark \
  --domains api.myapp.com,cdn.myapp.com \
  --record-types A,AAAA \
  --iterations 10

# CI/CD integration test
dns-benchmark benchmark \
  --resolvers data/ci_resolvers.json \
  --domains data/ci_domains.txt \
  --timeout 2 \
  --formats csv \
  --quiet
```

**For Enterprise IT:**

```bash
# Corporate network assessment
dns-benchmark benchmark \
  --resolvers data/enterprise_resolvers.json \
  --domains data/corporate_domains.txt \
  --record-types A,AAAA,MX,TXT,SRV \
  --timeout 10 \
  --max-concurrent 25 \
  --retries 2 \
  --formats csv,excel,pdf \
  --output ./enterprise_dns_audit

# Multi-location testing
dns-benchmark benchmark \
  --resolvers data/global_resolvers.json \
  --domains data/international_domains.txt \
  --formats excel \
  --output ./global_performance
```

**For Network Admins:**

```bash
# Monthly health check (crontab)
0 0 1 * * dns-benchmark benchmark \
  --use-defaults \
  --formats pdf,csv \
  --output /var/reports/dns/
```

## Performance Tips

| Mode | Flags | Purpose |
|------|-------|---------|
| **Quick** | `--iterations 1 --warmup-fast --timeout 1` | Fast feedback |
| **Thorough** | `--iterations 3 --use-cache --warmup` | Accurate results |
| **CI/CD** | `--quiet --formats csv --timeout 2` | Automated testing |
| **Large Scale** | `--max-concurrent 200 --quiet` | 100+ resolvers |

---

## ⚡ CLI Commands

The DNS Benchmark Tool now includes three specialized commands for different workflows:

### 🚀 Top

Quickly rank resolvers by speed and reliability.

```bash
# Rank resolvers quickly
dns-benchmark top --use-defaults

# Use custom domain list
dns-benchmark top -d domains.txt

# Export results to JSON
dns-benchmark top -o results.json
```

---

### 📊 Compare

Benchmark resolvers side‑by‑side with detailed statistics.

```bash
# Compare Cloudflare, Google, and Quad9
dns-benchmark compare Cloudflare Google Quad9

# Compare by IP addresses
dns-benchmark compare 1.1.1.1 8.8.8.8 9.9.9.9

# Show detailed per-domain breakdown
dns-benchmark compare Cloudflare Google --show-details

# Export results to CSV
dns-benchmark compare Cloudflare Google -o results.csv
```

---

### 🔄 Monitoring

Continuously monitor resolver performance with alerts.

```bash
# Monitor default resolvers continuously (every 60s)
dns-benchmark monitoring --use-defaults

# Monitor with custom resolvers and domains
dns-benchmark monitoring -r resolvers.json -d domains.txt

# Run monitoring for 1 hour with alerts
dns-benchmark monitoring --use-defaults --interval 30 --duration 3600 \
  --alert-latency 150 --alert-failure-rate 5 --output monitor.log
```

---

### 🌟 Command Showcase

| Command      | Purpose | Typical Use Case | Key Options | Output |
|--------------|---------|------------------|-------------|--------|
| **top**      | Quick ranking of resolvers by speed and reliability | Fast check to see which resolver is best right now | `--domains`, `--record-types`, `--iterations`, `--output` | Sorted list of resolvers with latency & success rate |
| **compare**  | Side‑by‑side comparison of specific resolvers | Detailed benchmarking across chosen resolvers/domains | `--domains`, `--record-types`, `--iterations`, `--output`, `--show-details` | Table of resolvers with latency, success rate, per‑domain breakdown |
| **monitoring** | Continuous monitoring with alerts | Real‑time tracking of resolver performance over time | `--interval`, `--duration`, `--alert-latency`, `--alert-failure-rate`, `--output`, `--use-defaults` | Live status indicators, alerts, optional log file |

---

## Feedback & Community

### Share Your Input

Help us improve dns-benchmark! Share your DNS challenges and feature requests:

```bash
dns-benchmark feedback
```

Opens a 2-minute survey that directly shapes our roadmap: https://forms.gle/BJBiyBFvRJHskyR57

### Smart Prompts (Non-Intrusive)

The tool occasionally shows a feedback prompt:

- Only after runs **5, 15, and 30** (not random)
- With **24-hour cooldown** between prompts
- Stops after you submit feedback or dismiss 3 times

### Privacy First

**Local storage only:** State stored in `~/.dns-benchmark/feedback.json`  
**No telemetry:** Zero automatic data collection  
**Full control:** Multiple opt-out options available

### Opt Out

**Dismiss when prompted:**

```bash
Show this again? (y/n) [y]: n
```

**Environment variable (permanent):**

```bash
export DNS_BENCHMARK_NO_FEEDBACK=1
```

**Auto-disabled in CI/CD:** Respects `CI=true` and `--quiet` flag

---

## 🌐 Hosted Version (Coming Soon)

**CLI stays free forever.** The hosted version adds features impossible to achieve locally:

### 🌍 Multi-Region Testing

Test from US-East, US-West, EU, Asia simultaneously. See how your DNS performs for users worldwide.

### 📊 Historical Tracking

Monitor DNS performance over time. Identify trends, degradation, and optimize continuously.

### 🚨 Smart Alerts

Get notified via Email, Slack, PagerDuty when DNS performance degrades or SLA thresholds are breached.

### 👥 Team Collaboration

Share results, dashboards, and reports across your team. Role-based access control.

### 📈 SLA Compliance

Automated monthly reports proving DNS provider meets SLA guarantees. Audit-ready documentation.

### 🔌 API Access

Integrate DNS monitoring into your existing observability stack. Prometheus, Datadog, Grafana.

---

**[Join the Waitlist →](https://buildtools.net)** | Early access gets 50% off for 3 months

---

## 🛣️ Roadmap

### ✅ Current Release (CLI Edition)

- Benchmark DNS resolvers across domains and record types
- Export to CSV, Excel, PDF, JSON
- Statistical analysis (P95, P99, jitter, consistency)
- Automation support (CI/CD, cron)

### 🚧 Hosted Version (Q1 2026)

**CLI stays free forever.** Hosted adds:

- 🌍 Multi-region testing (US, EU, Asia, custom)
- 📊 Historical tracking with charts and trends
- 🚨 Alerts (Email, Slack, PagerDuty, webhooks)
- 👥 Team collaboration and sharing
- 📈 SLA compliance reporting
- 🔌 API access and integrations

**[Join Waitlist](https://buildtools.net)** for early access

### 🔜 More Network Tools (Q1-Q2 2026)

Part of BuildTools - Network Performance Suite:

- 🔍 **HTTP/HTTPS Benchmark** - Test API endpoints and CDNs
- 🔒 **SSL Certificate Monitor** - Never miss renewals
- 📡 **Uptime Monitor** - 24/7 availability tracking
- 🌐 **API Health Dashboard** - Complete network observability

### 💡 Your Input Matters

**Help shape our roadmap:**

- [📝 2-minute feedback survey](https://forms.gle/BJBiyBFvRJHskyR57)
- [💬 GitHub Discussions](https://github.com/frankovo/dns-benchmark-tool/discussions)
- [⭐ Star us](https://github.com/frankovo/dns-benchmark-tool) if this helps you!

---

## 🤝 Contributing

We love contributions! Here's how you can help:

### Ways to Contribute

- 🐛 **Report bugs** - [Open an issue](https://github.com/frankovo/dns-benchmark-tool/issues)
- 💡 **Suggest features** - [Start a discussion](https://github.com/frankovo/dns-benchmark-tool/discussions)
- 📝 **Improve docs** - README, examples, tutorials
- 🔧 **Submit PRs** - Bug fixes, features, tests
- ⭐ **Star the repo** - Help others discover the tool
- 📢 **Spread the word** - Tweet, blog, share

### Code Guidelines

- Follow PEP 8 style guide
- Add tests for new features
- Update documentation
- Keep PRs focused and atomic

---

## 🔗 Links & Support

### Official

- **Website**: [buildtools.net](https://buildtools.net)
- **PyPI**: [dns-benchmark-tool](https://pypi.org/project/dns-benchmark-tool/)
- **GitHub**: [frankovo/dns-benchmark-tool](https://github.com/frankovo/dns-benchmark-tool)

### Community

- **Documentation:** Full usage guide, advanced examples, and screenshots are available on [GitHub](https://github.com/frankovo/dns-benchmark-tool)
- **Feedback**: [2-minute survey](https://forms.gle/BJBiyBFvRJHskyR57)
- **Discussions**: [GitHub Discussions](https://github.com/frankovo/dns-benchmark-tool/discussions)
- **Issues**: [Bug Reports](https://github.com/frankovo/dns-benchmark-tool/issues)

### Stats

- **Downloads**: 1,400+ (this week)
- **Active Users**: 600+

---

## License

MIT License - see [LICENSE](https://github.com/frankovo/dns-benchmark-tool/blob/main/LICENSE) file for details.

---

<div align="center">

**Built with ❤️ by [@frankovo](https://github.com/frankovo)**

Part of [BuildTools](https://buildtools.net) - Network Performance Suite

[⭐ Star on GitHub](https://github.com/frankovo/dns-benchmark-tool) • [📦 Install from PyPI](https://pypi.org/project/dns-benchmark-tool/) • [🌐 Join Waitlist](https://buildtools.net)

</div>
