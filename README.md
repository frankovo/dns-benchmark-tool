# DNS Benchmark Tool

[![CI Tests](https://github.com/frankovo/dns-benchmark-tool/actions/workflows/test.yml/badge.svg)](https://github.com/frankovo/dns-benchmark-tool/actions/workflows/test.yml)
[![Publish to TestPyPI](https://github.com/frankovo/dns-benchmark-tool/actions/workflows/testpypi.yml/badge.svg)](https://github.com/frankovo/dns-benchmark-tool/actions/workflows/testpypi.yml)
[![Publish to PyPI](https://github.com/frankovo/dns-benchmark-tool/actions/workflows/pypi.yml/badge.svg)](https://github.com/frankovo/dns-benchmark-tool/actions/workflows/pypi.yml)
[![PyPI version](https://img.shields.io/pypi/v/dns-benchmark-tool.svg)](https://pypi.org/project/dns-benchmark-tool/)

![Python Version](https://img.shields.io/badge/python-3.9%2B-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Coverage](https://img.shields.io/badge/coverage-91%25-brightgreen.svg)

[![Downloads](https://img.shields.io/pypi/dm/dns-benchmark-tool.svg)](https://pypi.org/project/dns-benchmark-tool/)
[![GitHub stars](https://img.shields.io/github/stars/frankovo/dns-benchmark-tool.svg?style=social&label=Star)](https://github.com/frankovo/dns-benchmark-tool/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/frankovo/dns-benchmark-tool.svg?style=social&label=Fork)](https://github.com/frankovo/dns-benchmark-tool/network/members)
[![Issues](https://img.shields.io/github/issues/frankovo/dns-benchmark-tool.svg)](https://github.com/frankovo/dns-benchmark-tool/issues)
[![Last commit](https://img.shields.io/github/last-commit/frankovo/dns-benchmark-tool.svg)](https://github.com/frankovo/dns-benchmark-tool/commits/main)
[![Main branch protected](https://img.shields.io/badge/branch%20protection-main%20✅-brightgreen)](./RELEASE.md)

A powerful open-source CLI tool to benchmark DNS resolvers across domains and record types.  
Generates detailed analytics, exports to CSV/Excel/PDF/JSON, and supports automation in CI/CD.

## Table of Contents

- [DNS Benchmark Tool](#dns-benchmark-tool)
  - [Table of Contents](#table-of-contents)
  - [Quick start](#quick-start)
    - [Installation](#installation)
    - [Basic usage](#basic-usage)
  - [🛠 Development \& Makefile Commands](#-development--makefile-commands)
    - [Common usage](#common-usage)
  - [Complete usage guide](#complete-usage-guide)
    - [1) Benchmark commands](#1-benchmark-commands)
      - [Quick performance test](#quick-performance-test)
      - [Network administrator](#network-administrator)
      - [ISP \& network operator](#isp--network-operator)
      - [Developer \& DevOps](#developer--devops)
      - [Security auditor](#security-auditor)
      - [Enterprise IT](#enterprise-it)
    - [2) Information \& discovery](#2-information--discovery)
      - [Domain management](#domain-management)
      - [Category overview](#category-overview)
    - [3) Configuration management](#3-configuration-management)
  - [Data files structure](#data-files-structure)
    - [Resolvers JSON format](#resolvers-json-format)
    - [Domains text file format](#domains-text-file-format)
  - [Output formats](#output-formats)
    - [CSV outputs](#csv-outputs)
    - [Excel report](#excel-report)
    - [PDF report](#pdf-report)
    - [JSON export](#json-export)
  - [Performance optimization](#performance-optimization)
  - [Troubleshooting](#troubleshooting)
    - [Debug mode](#debug-mode)
  - [Automation \& CI](#automation--ci)
    - [Cron jobs](#cron-jobs)
    - [GitHub Actions example](#github-actions-example)
  - [Use case examples](#use-case-examples)
  - [Screenshots](#screenshots)
  - [Getting help](#getting-help)
  - [License](#license)
  - [🛣️ Roadmap](#️-roadmap)
    - [✅ Current Release (CLI Edition)](#-current-release-cli-edition)
    - [🚧 Upcoming Features](#-upcoming-features)
    - [🔜 Future Enhancements](#-future-enhancements)

## Quick start

### Installation

```bash
# Install from source
git clone <repository-url>
cd dns-benchmark-tool
pip install -e .

# Or install dependencies directly
pip install dnspython pandas openpyxl weasyprint click colorama tqdm matplotlib Jinja2
```

### Basic usage

```bash
# Quick test with defaults
dns-benchmark benchmark --use-defaults

# Test with custom resolvers and domains
dns-benchmark benchmark --resolvers data/resolvers.json --domains data/domains.txt

# Generate comprehensive report with analytics
dns-benchmark benchmark --use-defaults --formats csv,excel,pdf \
  --domain-stats --record-type-stats --error-breakdown --json \
  --output ./results
```

---

## 🛠 Development & Makefile Commands

This project includes a `Makefile` to simplify installation, testing, and code quality checks.

```makefile
.PHONY: install install-dev uninstall mypy black isort flake8 cov test clean cli-test

# 🔧 Install package (runtime only)
install:
  pip install .

# 🔧 Install package with dev extras (pytest, mypy, flake8, black, isort, etc.)
install-dev:
  pip install .[dev]

# 🔧 Uninstall package
uninstall:
  pip uninstall -y dns-benchmark-tool \
  dnspython pandas aiohttp click pyfiglet colorama Jinja2 weasyprint openpyxl pyyaml tqdm matplotlib \
  mypy black flake8 autopep8 pytest coverage isort

mypy:
  mypy .

isort:
  isort .

black:
  black .

flake8:
  flake8 src tests --ignore=E126,E501,E712,F405,F403,E266,W503 --max-line-length=88 --extend-ignore=E203

cov:
  coverage erase
  coverage run --source=src -m pytest -vv -s
  coverage html

test: mypy black isort flake8 cov

clean:
  rm -rf __pycache__ .pytest_cache htmlcov .coverage coverage.xml \
  build dist *.egg-info .eggs benchmark_results
cli-test:
  # Run only the CLI smoke tests marked with @pytest.mark.cli
  pytest -vv -s -m cli tests/test_cli_commands.py
```

### Common usage

- **Install runtime only**
  
  ```bash
  make install
  ```

- **Install with dev dependencies**

  ```bash
  make install-dev
  ```

- **Run type checks, linting, formatting, and tests**
  
  ```bash
  make test
  ```

- **Run CLI smoke tests only**  

  ```bash
  make cli-test
  ```

- **Clean build/test artifacts**  

  ```bash
  make clean
  ```
  
---

## Complete usage guide

### 1) Benchmark commands

#### Quick performance test

```bash
# Basic test with progress bars
dns-benchmark benchmark --use-defaults

# Quick test with only CSV output
dns-benchmark benchmark --use-defaults --formats csv --quiet

# Test specific record types
dns-benchmark benchmark --use-defaults --record-types A,AAAA,MX
```

Add-on analytics flags:

```bash
# Include domain and record-type analytics and error breakdown
dns-benchmark benchmark --use-defaults \
  --domain-stats --record-type-stats --error-breakdown
```

JSON export:

```bash
# Export a machine-readable bundle
dns-benchmark benchmark --use-defaults --json --output ./results
```

#### Network administrator

```bash
# Compare internal vs external DNS
dns-benchmark benchmark \
  --resolvers "192.168.1.1,1.1.1.1,8.8.8.8,9.9.9.9" \
  --domains "internal.company.com,google.com,github.com,api.service.com" \
  --formats excel,pdf \
  --timeout 3 \
  --max-concurrent 50 \
  --output ./network_audit

# Test DNS failover scenarios
dns-benchmark benchmark \
  --resolvers data/primary_resolvers.json \
  --domains data/business_critical_domains.txt \
  --record-types A,AAAA \
  --retries 3 \
  --formats csv,excel \
  --output ./failover_test
```

#### ISP & network operator

```bash
# Comprehensive ISP resolver comparison
dns-benchmark benchmark \
  --resolvers data/isp_resolvers.json \
  --domains data/popular_domains.txt \
  --timeout 5 \
  --max-concurrent 100 \
  --formats csv,excel,pdf \
  --output ./isp_performance_analysis

# Regional performance testing
dns-benchmark benchmark \
  --resolvers data/regional_resolvers.json \
  --domains data/regional_domains.txt \
  --formats excel \
  --quiet \
  --output ./regional_analysis
```

#### Developer & DevOps

```bash
# Test application dependencies
dns-benchmark benchmark \
  --resolvers "1.1.1.1,8.8.8.8" \
  --domains "api.github.com,registry.npmjs.org,pypi.org,docker.io,aws.amazon.com" \
  --formats csv \
  --quiet \
  --output ./app_dependencies

# CI/CD integration test
dns-benchmark benchmark \
  --resolvers data/ci_resolvers.json \
  --domains data/ci_domains.txt \
  --timeout 2 \
  --formats csv \
  --quiet
```

#### Security auditor

```bash
# Security-focused resolver testing
dns-benchmark benchmark \
  --resolvers data/security_resolvers.json \
  --domains data/malware_test_domains.txt \
  --formats csv,pdf \
  --output ./security_audit

# Privacy-focused testing
dns-benchmark benchmark \
  --resolvers data/privacy_resolvers.json \
  --domains data/tracking_domains.txt \
  --formats excel \
  --output ./privacy_analysis
```

#### Enterprise IT

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

### 2) Information & discovery

```bash
# Show default resolvers and domains
dns-benchmark list-defaults

# Browse all available resolvers
dns-benchmark list-resolvers

# Browse with detailed information
dns-benchmark list-resolvers --details

# Filter by category
dns-benchmark list-resolvers --category security
dns-benchmark list-resolvers --category privacy
dns-benchmark list-resolvers --category family

# Export resolvers to different formats
dns-benchmark list-resolvers --format csv
dns-benchmark list-resolvers --format json
```

#### Domain management

```bash
# List all test domains
dns-benchmark list-domains

# Show domains by category
dns-benchmark list-domains --category tech
dns-benchmark list-domains --category ecommerce
dns-benchmark list-domains --category social

# Limit results
dns-benchmark list-domains --count 10
dns-benchmark list-domains --category news --count 5

# Export domain list
dns-benchmark list-domains --format csv
dns-benchmark list-domains --format json
```

#### Category overview

```bash
# View all available categories
dns-benchmark list-categories
```

### 3) Configuration management

```bash
# Generate sample configuration
dns-benchmark generate-config --output sample_config.yaml

# Category-specific configurations
dns-benchmark generate-config --category security --output security_test.yaml
dns-benchmark generate-config --category family --output family_protection.yaml
dns-benchmark generate-config --category performance --output performance_test.yaml

# Custom configuration for specific use case
dns-benchmark generate-config --category privacy --output privacy_audit.yaml
```

---

## Data files structure

### Resolvers JSON format

```json
{
  "resolvers": [
    {
      "name": "Cloudflare",
      "ip": "1.1.1.1",
      "ipv6": "2606:4700:4700::1111"
    },
    {
      "name": "Google DNS",
      "ip": "8.8.8.8",
      "ipv6": "2001:4860:4860::8888"
    }
  ]
}
```

### Domains text file format

```txt
# Popular websites
google.com
github.com
stackoverflow.com

# Corporate domains
microsoft.com
apple.com
amazon.com

# CDN and cloud
cloudflare.com
aws.amazon.com
```

---

## Output formats

### CSV outputs

- Raw data: individual query results with timestamps and metadata
- Summary statistics: aggregated metrics per resolver
- Domain statistics: per-domain metrics (when --domain-stats)
- Record type statistics: per-record-type metrics (when --record-type-stats)
- Error breakdown: counts by error type (when --error-breakdown)

### Excel report

- Raw data sheet: all query results with formatting
- Resolver summary: comprehensive statistics with conditional formatting
- Domain stats: per-domain performance (optional)
- Record type stats: per-record-type performance (optional)
- Error breakdown: aggregated error counts (optional)
- Performance analysis: charts and comparative analysis

### PDF report

- Executive summary: key findings and recommendations
- Performance charts: latency comparison; optional success rate chart
- Resolver rankings: ordered by average latency
- Detailed analysis: technical deep‑dive with percentiles

### JSON export

- Machine‑readable bundle including:
  - Overall statistics
  - Resolver statistics
  - Raw query results
  - Domain statistics
  - Record type statistics
  - Error breakdown

---

## Performance optimization

```bash
# Large-scale testing (1000+ queries)
dns-benchmark benchmark \
  --resolvers data/many_resolvers.json \
  --domains data/many_domains.txt \
  --max-concurrent 50 \
  --timeout 3 \
  --quiet \
  --formats csv

# Unstable networks
dns-benchmark benchmark \
  --resolvers data/backup_resolvers.json \
  --domains data/critical_domains.txt \
  --timeout 10 \
  --retries 3 \
  --max-concurrent 10

# Quick diagnostics
dns-benchmark benchmark \
  --resolvers "1.1.1.1,8.8.8.8" \
  --domains "google.com,cloudflare.com" \
  --formats csv \
  --quiet \
  --timeout 2
```

---

## Troubleshooting

```bash
# Command not found
pip install -e .
python -m dns_benchmark.cli --help

# PDF generation fails (Ubuntu/Debian)
sudo apt-get install libcairo2 libpango-1.0-0 libpangocairo-1.0-0 \
  libgdk-pixbuf2.0-0 libffi-dev shared-mime-info
# Or skip PDF
dns-benchmark benchmark --use-defaults --formats csv,excel

# Network timeouts
dns-benchmark benchmark --use-defaults --timeout 10 --retries 3
dns-benchmark benchmark --use-defaults --max-concurrent 25
```

### Debug mode

```bash
# Verbose run
python -m dns_benchmark.cli benchmark --use-defaults --formats csv

# Minimal configuration
dns-benchmark benchmark --resolvers "1.1.1.1" --domains "google.com" --formats csv
```

---

## Automation & CI

### Cron jobs

```bash
# Daily monitoring
0 2 * * * /usr/local/bin/dns-benchmark benchmark --use-defaults --formats csv --quiet --output /var/log/dns_benchmark/daily_$(date +\%Y\%m\%d)

# Time-based variability (every 6 hours)
0 */6 * * * /usr/local/bin/dns-benchmark benchmark --use-defaults --formats csv --quiet --output /var/log/dns_benchmark/$(date +\%Y\%m\%d_\%H)
```

### GitHub Actions example

```yaml
- name: DNS Performance Test
  run: |
    pip install dnspython pandas click tqdm colorama
    dns-benchmark benchmark \
      --resolvers "1.1.1.1,8.8.8.8" \
      --domains "api.service.com,database.service.com" \
      --formats csv \
      --quiet
```

---

## Use case examples

```bash
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

---

## Screenshots

Place images in `docs/screenshots/`:

- `docs/screenshots/cli_run.png`
- `docs/screenshots/excel_report.png`
- `docs/screenshots/pdf_summary.png`

```markdown
### 1. CLI Benchmark Run
![CLI Benchmark Run](docs/screenshots/cli_run.png)

### 2. Excel Report Output
![Excel Report Output](docs/screenshots/excel_report.png)

### 3. PDF Executive Summary
![PDF Executive Summary](docs/screenshots/pdf_summary.png)
```

---

## Getting help

```bash
dns-benchmark --help
dns-benchmark benchmark --help
dns-benchmark list-resolvers --help
dns-benchmark list-domains --help
dns-benchmark list-categories --help
dns-benchmark generate-config --help
```

Common scenarios:

```bash
# I'm new — where to start?
dns-benchmark list-defaults
dns-benchmark benchmark --use-defaults

# Test specific resolvers
dns-benchmark list-resolvers --category security
dns-benchmark benchmark --resolvers data/security_resolvers.json --use-defaults

# Generate a management report
dns-benchmark benchmark --use-defaults --formats excel,pdf \
  --domain-stats --record-type-stats --error-breakdown --json \
  --output ./management_report
```

---

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

---

## 🛣️ Roadmap

### ✅ Current Release (CLI Edition)

- Benchmark DNS resolvers across domains and record types  
- Export results to CSV, Excel, PDF, and JSON  
- Generate detailed analytics (domain stats, record-type stats, error breakdown)  
- Automation support (cron jobs, CI/CD)  

### 🚧 Upcoming Features

- Web UI (Django + HTMX + FastAPI) for interactive dashboards  
- Real-time monitoring with WebSocket updates  
- Public status pages for sharing resolver/domain performance  
- Multi-channel notifications (email, Slack, etc.)  
- Advanced scheduling and historical tracking  

### 🔜 Future Enhancements

- SaaS platform integration with Stripe-powered subscriptions  
- Team collaboration features  
- Enterprise-grade reporting and centralized management  
