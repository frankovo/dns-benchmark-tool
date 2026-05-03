<div align="center">

# DNS Benchmark Tool

## Part of [BuildTools](https://buildtools.net) - Network Performance Suite

**Fast, comprehensive DNS performance testing with DNSSEC validation, DoH/DoT support, and enterprise features**

```bash
pip install dns-benchmark-tool
dns-benchmark benchmark --use-defaults --formats csv,excel
```

> 🎉 **1,400+ downloads · 600+ active users**
> 🚀 **The web dashboard is now live!** [Try BuildTools free →](https://buildtools.net)

---

**Real Time Tracking**

[![Real Time Tracking](docs/real_time_tracking.gif)](https://github.com/frankovo/dns-benchmark-tool)
*Watch DNS queries in motion*

**Real Time Tracking - Web UI**
<video src="https://github.com/frankovo/dns-benchmark-tool/raw/main/docs/BuildTools_DNS_Test_Demo.mp4" autoplay loop muted playsinline>
  <img src="docs/BuildTools_DNS_Test_Demo_fallback.png" alt="Real Time Tracking - Web UI">
</video>
*Monitor DNS queries live with email alerts*

</div>

## 🎉 What's New in ![new](https://img.shields.io/pypi/v/dns-benchmark-tool.svg?color=brightgreen&label=new)

We've added **three powerful CLI commands** and full support for **DoH, DoT, and DNSSEC**:

- 🚀 **top** — quick ranking of resolvers by speed and reliability
- 📊 **compare** — side-by-side benchmarking with detailed statistics and export options
- 🔄 **monitoring** — continuous performance tracking with alerts and logging
- 🔒 **DoH / DoT / DNSSEC** — encrypted DNS benchmarking with real latency tradeoff data

```bash
# Quick resolver ranking
dns-benchmark top

# Compare resolvers side-by-side
dns-benchmark compare Cloudflare Google Quad9 --show-details

# Run monitoring for 1 hour with alerts
dns-benchmark monitoring --use-defaults --formats csv,excel --interval 30 --duration 3600 \
  --alert-latency 150 --alert-failure-rate 5 --output monitor.log

# Encrypted DNS
dns-benchmark benchmark \
  --resolvers "Cloudflare,Google" \
  --domains "bing.com,google.com" \
  --doh \
  --doh-url "https://cloudflare-dns.com/dns-query,https://dns.google/dns-query" \
  --iterations 1 \
  --formats csv \
  --output ./doh_results_explicit_urls

dns-benchmark benchmark \
  --resolvers "Cloudflare,Quad9" \
  --domains "cloudflare.com,quad9.net" \
  --dot
```

## 📈 Community Highlights

- ⭐ Stars: Grew from 7 → 110+ after posting on Hacker News  
- 📦 Downloads: Rebounded to 200+/day after initially stalling  
- 🐘 Mastodon: Shared there too, but the real surge came from HN  
- 💬 Feedback: Constructive input from HN community directly shaped patches v0.3.0 → v0.3.1
- 🚀 Takeaway: Hacker News visibility was the catalyst for adoption momentum

---

[![CI Tests](https://github.com/frankovo/dns-benchmark-tool/actions/workflows/test.yml/badge.svg)](https://github.com/frankovo/dns-benchmark-tool/actions/workflows/test.yml)
[![Publish to TestPyPI](https://github.com/frankovo/dns-benchmark-tool/actions/workflows/testpypi.yml/badge.svg)](https://github.com/frankovo/dns-benchmark-tool/actions/workflows/testpypi.yml)
[![Publish to PyPI](https://github.com/frankovo/dns-benchmark-tool/actions/workflows/pypi.yml/badge.svg)](https://github.com/frankovo/dns-benchmark-tool/actions/workflows/pypi.yml)
[![PyPI version](https://img.shields.io/pypi/v/dns-benchmark-tool.svg?color=brightgreen)](https://pypi.org/project/dns-benchmark-tool/)
[![PyPI - Python Version](https://img.shields.io/pypi/pyversions/dns-benchmark-tool.svg)](https://pypi.org/project/dns-benchmark-tool/)

![License](https://img.shields.io/badge/license-MIT-green.svg)
![Coverage](https://img.shields.io/badge/coverage-87%25-brightgreen.svg)

[![Downloads](https://img.shields.io/pypi/dm/dns-benchmark-tool.svg?color=blueviolet)](https://pypi.org/project/dns-benchmark-tool/)
[![GitHub stars](https://img.shields.io/github/stars/frankovo/dns-benchmark-tool.svg?style=social&label=Star)](https://github.com/frankovo/dns-benchmark-tool/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/frankovo/dns-benchmark-tool.svg?style=social&label=Fork)](https://github.com/frankovo/dns-benchmark-tool/network/members)
[![Issues](https://img.shields.io/github/issues/frankovo/dns-benchmark-tool.svg?color=orange)](https://github.com/frankovo/dns-benchmark-tool/issues)
[![Last commit](https://img.shields.io/github/last-commit/frankovo/dns-benchmark-tool.svg?color=blue)](https://github.com/frankovo/dns-benchmark-tool/commits/main)
[![Main branch protected](https://img.shields.io/badge/branch%20protection-main%20✅-brightgreen)](https://github.com/frankovo/dns-benchmark-tool/blob/main/RELEASE.md)

## Table of Contents

- [DNS Benchmark Tool](#dns-benchmark-tool)
  - [Part of BuildTools - Network Performance Suite](#part-of-buildtools---network-performance-suite)
  - [🎉 What's New in ](#-whats-new-in-)
  - [📈 Community Highlights](#-community-highlights)
  - [Table of Contents](#table-of-contents)
  - [🎯 Why This Tool?](#-why-this-tool)
    - [The Problem](#the-problem)
    - [The Solution](#the-solution)
    - [Perfect For](#perfect-for)
  - [Quick start](#quick-start)
    - [Installation](#installation)
    - [Run Your First Benchmark](#run-your-first-benchmark)
    - [View Results](#view-results)
  - [⚡ Commands at a Glance](#-commands-at-a-glance)
  - [✨ Key Features](#-key-features)
    - [🚀 Performance](#-performance)
    - [🔒 Security \& Privacy](#-security--privacy)
    - [📊 Analysis \& Export](#-analysis--export)
    - [🏢 Enterprise Features](#-enterprise-features)
    - [🌐 Cross-Platform](#-cross-platform)
  - [🔒 Security \& Encrypted DNS](#-security--encrypted-dns)
  - [🔧 Advanced Capabilities](#-advanced-capabilities)
  - [💼 Use Cases](#-use-cases)
    - [🔧 For Developers: Optimize API Performance](#-for-developers-optimize-api-performance)
    - [🛡️ For DevOps/SRE: Validate Before Migration](#️-for-devopssre-validate-before-migration)
    - [🏠 For Self-Hosters: Prove Pi-hole Performance](#-for-self-hosters-prove-pi-hole-performance)
    - [📊 For Network Admins: Automated Health Checks](#-for-network-admins-automated-health-checks)
    - [🔐 For Privacy Advocates: Test Encrypted DNS](#-for-privacy-advocates-test-encrypted-dns)
  - [📦 Installation \& Setup](#-installation--setup)
    - [Requirements](#requirements)
    - [Install from PyPI](#install-from-pypi)
    - [Install from Source](#install-from-source)
    - [Verify Installation](#verify-installation)
    - [First Run](#first-run)
  - [📖 Usage Examples](#-usage-examples)
    - [Basic Usage](#basic-usage)
    - [Advanced Usage](#advanced-usage)
  - [Inline input support for resolvers and domains](#inline-input-support-for-resolvers-and-domains)
    - [New capabilities](#new-capabilities)
    - [Backward compatibility](#backward-compatibility)
    - [Usage Examples](#usage-examples)
      - [Before (Only files worked)](#before-only-files-worked)
      - [After (Both work)](#after-both-work)
      - [Named resolvers](#named-resolvers)
      - [Mixed input](#mixed-input)
      - [Single](#single)
  - [🔧 Utilities](#-utilities)
    - [Risolver management](#risolver-management)
    - [Domain management](#domain-management)
    - [Category overview](#category-overview)
    - [Configuration management](#configuration-management)
  - [Complete usage guide](#complete-usage-guide)
    - [Quick performance test](#quick-performance-test)
      - [Network administrator](#network-administrator)
      - [ISP \& network operator](#isp--network-operator)
      - [Developer \& DevOps](#developer--devops)
      - [Security auditor](#security-auditor)
      - [Enterprise IT](#enterprise-it)
  - [🔍 README Adjustments for Final Patch](#-readme-adjustments-for-final-patch)
    - [New CLI Options](#new-cli-options)
  - [⚡ CLI Commands](#-cli-commands)
    - [🚀 Top](#-top)
    - [📊 Compare](#-compare)
    - [🔄 Monitoring](#-monitoring)
    - [🌟 Command Showcase](#-command-showcase)
  - [📊 Analysis Enhancements](#-analysis-enhancements)
  - [⚡ Best Practices](#-best-practices)
  - [⚙️ Configuration Files](#️-configuration-files)
    - [Resolvers JSON format](#resolvers-json-format)
    - [Domains text file format](#domains-text-file-format)
  - [Output formats](#output-formats)
    - [CSV outputs](#csv-outputs)
    - [Excel report](#excel-report)
    - [PDF report](#pdf-report)
    - [📄 Optional PDF Export](#-optional-pdf-export)
      - [Install with PDF support](#install-with-pdf-support)
      - [Usage](#usage)
    - [⚠️ WeasyPrint Setup (for PDF export)](#️-weasyprint-setup-for-pdf-export)
      - [🛠 Linux (Debian/Ubuntu)](#-linux-debianubuntu)
      - [🛠 macOS (Homebrew)](#-macos-homebrew)
      - [🛠 Windows](#-windows)
      - [✅ Verify Installation](#-verify-installation)
    - [JSON export](#json-export)
    - [Generate Sample Config](#generate-sample-config)
  - [Performance optimization](#performance-optimization)
  - [Troubleshooting](#troubleshooting)
    - [Debug mode](#debug-mode)
  - [Automation \& CI](#automation--ci)
    - [Cron jobs](#cron-jobs)
    - [GitHub Actions example](#github-actions-example)
  - [Screenshots](#screenshots)
    - [1. CLI Benchmark Run](#1-cli-benchmark-run)
    - [2. Excel Report Output](#2-excel-report-output)
    - [3. PDF Executive Summary](#3-pdf-executive-summary)
    - [4. PDF Charts](#4-pdf-charts)
    - [5. Excel Charts](#5-excel-charts)
    - [6. Real Time Monitoring](#6-real-time-monitoring)
  - [Getting help](#getting-help)
  - [Release workflow](#release-workflow)
  - [🌐 BuildTools Web Dashboard — Now Live](#-buildtools-web-dashboard--now-live)
    - [What's live now (Free + Pro)](#whats-live-now-free--pro)
    - [Coming Q2 2026](#coming-q2-2026)
    - [Coming Q3 2026](#coming-q3-2026)
  - [🛣️ Roadmap](#️-roadmap)
    - [✅ Current Release (CLI Edition)](#-current-release-cli-edition)
    - [✅ Web Dashboard (Live)](#-web-dashboard-live)
    - [🔜 Coming Q2 2026](#-coming-q2-2026)
      - [Q3 2026](#q3-2026)
  - [🤝 Contributing](#-contributing)
    - [Ways to Contribute](#ways-to-contribute)
    - [🛠 Development \& Makefile Commands](#-development--makefile-commands)
    - [Common usage](#common-usage)
    - [Code Guidelines](#code-guidelines)
  - [❓ FAQ](#-faq)
  - [🔗 Links \& Support](#-links--support)
    - [Official](#official)
    - [Community](#community)
    - [Stats](#stats)
  - [License](#license)

---

## 🎯 Why This Tool?

DNS resolution is often the hidden bottleneck in network performance. A slow resolver can add hundreds of milliseconds to every request.

### The Problem

- ⏱️ **Hidden Bottleneck**: DNS can add 300ms+ to every request
- 🤷 **Unknown Performance**: Most developers never test their DNS
- 🌍 **Location Matters**: "Fastest" resolver depends on where YOU are
- 🔒 **Security Varies**: DNSSEC, DoH, DoT support differs wildly

### The Solution

dns-benchmark-tool helps you:

- 🔍 **Find the fastest** DNS resolver for YOUR location
- 📊 **Get real data** - P95, P99, jitter, consistency scores
- 🛡️ **Validate security** - DNSSEC verification built-in
- 🚀 **Test at scale** - 100+ concurrent queries in seconds

### Perfect For

- ✅ **Developers** optimizing API performance
- ✅ **DevOps/SRE** validating resolver SLAs
- ✅ **Self-hosters** comparing Pi-hole/Unbound vs public DNS
- ✅ **Network admins** running compliance checks

---

## Quick start

### Installation

```bash
pip install dns-benchmark-tool
```

### Run Your First Benchmark

```bash
# Test default resolvers against popular domains
dns-benchmark benchmark --use-defaults --formats csv,excel
```

### View Results

Results are automatically saved to `./benchmark_results/` with:

- Summary CSV with statistics
- Detailed raw data
- Optional PDF/Excel reports

**That's it!** You just benchmarked 5 DNS resolvers against 10 domains.

---

## ⚡ Commands at a Glance

| Command | What it does | Quick example |
|---|---|---|
| `benchmark` | Full DNS benchmark with exports | `dns-benchmark benchmark --use-defaults` |
| `top` | Rank all resolvers by speed | `dns-benchmark top --limit 5` |
| `compare` | Side-by-side resolver comparison | `dns-benchmark compare Cloudflare Google Quad9` |
| `monitoring` | Continuous monitoring with alerts | `dns-benchmark monitoring --use-defaults` |

```bash
# Find your fastest resolver right now
dns-benchmark top --limit 5

# Compare the big three
dns-benchmark compare Cloudflare Google Quad9 --show-details

# Monitor with DoT and alerts for 1 hour
dns-benchmark monitoring --use-defaults --dot \
  --interval 30 --duration 3600 \
  --alert-latency 150 --output monitor.log
```

---

## ✨ Key Features

### 🚀 Performance

- **Async queries** - Test 100+ resolvers simultaneously
- **Multi-iteration** - Run benchmarks multiple times for accuracy
- **Statistical analysis** - Mean, median, P95, P99, jitter, consistency
- **Cache control** - Test with/without DNS caching

### 🔒 Security & Privacy

- **DNSSEC validation** - Verify cryptographic trust chains
- **DNS-over-HTTPS (DoH)** - Encrypted DNS benchmarking
- **DNS-over-TLS (DoT)** - Secure transport testing
- **DNS-over-QUIC (DoQ)** - Experimental QUIC support

### 📊 Analysis & Export

- **Multiple formats** - CSV, Excel, PDF, JSON
- **Visual reports** - Charts and graphs
- **Domain statistics** - Per-domain performance analysis
- **Error breakdown** - Identify problematic resolvers

### 🏢 Enterprise Features

- **TSIG authentication** - Secure enterprise queries
- **Zone transfers** - AXFR/IXFR validation
- **Dynamic updates** - Test DNS write operations
- **Compliance reports** - Audit-ready documentation

### 🌐 Cross-Platform

- **Linux, macOS, Windows** - Works everywhere
- **CI/CD friendly** - JSON output, exit codes
- **IDNA support** - Internationalized domain names
- **Auto-detection** - Windows WMI DNS discovery

---

## 🔒 Security & Encrypted DNS

Three protocols are fully supported — each adds privacy at a latency cost.

| Protocol | Flag | Typical overhead | When to use |
|---|---|---|---|
| Plain UDP | *(default)* | baseline | Latency benchmarking |
| DNS-over-HTTPS | `--doh` | +50–200ms | Privacy, firewall bypass |
| DNS-over-TLS | `--dot` | +200–500ms cold, ~50ms warm | Encrypted transport |
| DNSSEC | `--dnssec-validate` | +30–100ms | Validating resolver integrity |

> ⚠️ **Tradeoffs**
> - DoH and DoT add TLS handshake overhead on first query per resolver. Use `--warmup-fast` to absorb this before measuring.
> - `--dnssec-validate` requests RRSIG records and enforces the AD flag. Only ~33% of common domains are DNSSEC-signed — expect `DNSSEC_FAILED` results on unsigned domains. Latency numbers with and without this flag are **not directly comparable**.
> - Results on mobile/hotspot will show 2–5× higher variance than wired ethernet. Use `--iterations 5` and compare median latency, not average.

```bash
# DoH benchmark
dns-benchmark benchmark \
  --resolvers "Cloudflare,Google" \
  --domains "cloudflare.com,google.com" \
  --doh --warmup-fast

# custom resolvers — must supply urls 1:1, order matters, or it fails early
dns-benchmark benchmark \
  --resolvers "Cloudflare,Google" \
  --domains "bing.com,google.com" \
  --doh \
  --doh-url "https://cloudflare-dns.com/dns-query,https://dns.google/dns-query" \
  --iterations 1 \
  --formats csv \
  --output ./doh_results_explicit_urls

# DoT with DNSSEC on signed domains
dns-benchmark benchmark \
  --resolvers "Cloudflare,Quad9" \
  --domains "cloudflare.com,quad9.net" \
  --dot \
  --dnssec-validate

# DOH rank top resolvers
dns-benchmark top --doh --limit 5

# DOT rank top resolvers
dns-benchmark top --dot --metric reliability --limit 5

# Compare DoH resolvers
dns-benchmark compare Cloudflare Google --doh --iterations 3

# Monitor with DoT
dns-benchmark monitoring --use-defaults --dot \
  --interval 60 --alert-latency 300

# DoH + DNSSEC enforced + export
dns-benchmark benchmark --use-defaults --doh --dnssec-validate --formats csv,excel

# DoT + DNSSEC enforced + multiple iterations
dns-benchmark benchmark \
  --resolvers "Cloudflare,Quad9,Google" \
  --domains "cloudflare.com,quad9.net,google.com" \
  --dot \
  --dnssec-validate \
  --iterations 5 \
  --formats excel

# DoH + custom urls + monitoring
dns-benchmark monitoring \
  --resolvers "Cloudflare,Google" \
  --doh \
  --doh-url "https://cloudflare-dns.com/dns-query,https://dns.google/dns-query" \
  --interval 30 --duration 7200
```

**Early failure examples** — these fail immediately before any query runs:

```bash
# --doh and --dot are mutually exclusive
dns-benchmark benchmark --use-defaults --doh --dot
# ERROR: --doh and --dot are mutually exclusive.

# --doh-url count must match --resolvers count
dns-benchmark benchmark --resolvers "Cloudflare,Google" --doh \
  --doh-url "https://cloudflare-dns.com/dns-query"
# ERROR: --doh-url has 1 URL(s) but --resolvers has 2 resolver(s). Counts must match.

# Custom IP with --doh requires --doh-url
dns-benchmark benchmark --resolvers "192.168.1.1" --doh
# ERROR: --doh requires a DoH URL for: 192.168.1.1. Use --doh-url to supply them explicitly.
```

---

## 🔧 Advanced Capabilities

---
> ⚠️ These flags are **documented for visibility** but not yet implemented.  
> They represent upcoming advanced features.

- `--zone-transfer` → AXFR/IXFR zone transfer testing *(coming soon)*
- `--tsig` → TSIG-authenticated queries *(coming soon)*
- `--idna` → Internationalized domain name support *(coming soon)*

---

<details>
<summary><b>🚀 Performance & Concurrency Features</b></summary>

<br>

- **Async I/O with dnspython** - Test 100+ resolvers simultaneously
- **Trio framework support** - High-concurrency async operations
- **Configurable concurrency** - Control max concurrent queries
- **Retry logic** - Exponential backoff for failed queries
- **Cache simulation** - Test with/without DNS caching
- **Multi-iteration benchmarks** - Run tests multiple times for accuracy
- **Warmup phase** - Pre-warm DNS caches before testing
- **Statistical analysis** - Mean, median, P95, P99, jitter, consistency scores

**Example:**

```bash
dns-benchmark benchmark \
  --max-concurrent 200 \
  --iterations 5 \
  --timeout 3.0 \
  --warmup
```

</details>

<details>
<summary><b>🔒 Security & Privacy Features</b></summary>

<br>

- **DNSSEC validation** - Verify cryptographic trust chains
- **DNS-over-HTTPS (DoH)** - Encrypted DNS benchmarking via HTTPS
- **DNS-over-TLS (DoT)** - Secure transport layer testing
- **DNS-over-QUIC (DoQ)** - Experimental QUIC protocol support
- **TSIG authentication** - Transaction signatures for enterprise DNS
- **EDNS0 support** - Extended DNS features and larger payloads

**Example:**

```bash
# Test DoH resolvers
dns-benchmark benchmark \
  --doh \
  --resolvers doh-providers.json \
  --dnssec-validate
```

</details>

<details>
<summary><b>🏢 Enterprise & Migration Features</b></summary>

<br>

- **Zone transfers (AXFR/IXFR)** - Full and incremental zone transfer validation
- **Dynamic DNS updates** - Test DNS write operations and updates
- **EDNS0 support** - Extended DNS options, client subnet, larger payloads
- **Windows WMI integration** - Auto-detect active system DNS settings
- **Compliance reporting** - Generate audit-ready PDF/Excel reports
- **SLA validation** - Track uptime and performance thresholds

**Example:**

```bash
# Validate DNS migration
dns-benchmark benchmark \
  --resolvers old-provider.json,new-provider.json \
  --zone-transfer \ # coming soon
  --output migration-report/ \
  --formats pdf,excel
```

</details>

<details>
<summary><b>📊 Analysis & Reporting Features</b></summary>

<br>

- **Per-domain statistics** - Analyze performance by domain
- **Per-record-type stats** - Compare A, AAAA, MX, TXT, etc.
- **Error breakdown** - Categorize and count error types
- **Comparison matrices** - Side-by-side resolver comparisons
- **Trend analysis** - Performance over time (with multiple runs)
- **Best-by-criteria** - Find best resolver by latency/reliability/consistency

**Example:**

```bash
# Detailed analysis
dns-benchmark benchmark \
  --use-defaults \
  --formats csv,excel \
  --domain-stats \
  --record-type-stats \
  --error-breakdown \
  --formats csv,excel,pdf
```

</details>

<details>
<summary><b>🌐 Internationalization & Compatibility</b></summary>

<br>

- **IDNA support** - Internationalized domain names (IDN)
- **Multiple record types** - A, AAAA, MX, TXT, CNAME, NS, SOA, PTR, SRV, CAA
- **Cross-platform** - Linux, macOS, Windows (native support)
- **CI/CD integration** - JSON output, proper exit codes, quiet mode
- **Custom resolvers** - Load from JSON, test your own DNS servers
- **Custom domains** - Test against your specific domain list

**Example:**

```bash
# Test internationalized domains
dns-benchmark benchmark \
  --domains international-domains.txt \
  --record-types A,AAAA,MX \
  --resolvers custom-resolvers.json
```

</details>

> 💡 **Most users only need basic features.** These advanced capabilities are available when you need them.

---

## 💼 Use Cases

### 🔧 For Developers: Optimize API Performance

```bash
# Find fastest DNS for your API endpoints
dns-benchmark benchmark \
  --domains api.myapp.com,cdn.myapp.com \
  --record-types A,AAAA \
  --resolvers production.json \
  --iterations 10
```

**Result:** Reduce API latency by 100-300ms

---

### 🛡️ For DevOps/SRE: Validate Before Migration

```bash
# Test new DNS provider before switching
dns-benchmark benchmark \
  --resolvers current-dns.json,new-dns.json \
  --use-defaults \
  --dnssec-validate \
  --output migration-report/ \
  --formats csv,excel
```

**Result:** Verify performance and security before migration

---

### 🏠 For Self-Hosters: Prove Pi-hole Performance

```bash
# Compare Pi-hole against public resolvers
dns-benchmark compare \
  --resolvers pihole.local,1.1.1.1,8.8.8.8,9.9.9.9 \
  --domains common-sites.txt \
  --rounds 10
```

**Result:** Data-driven proof your self-hosted DNS is faster (or not!)

---

### 📊 For Network Admins: Automated Health Checks

```bash
# Add to crontab for monthly reports
0 0 1 * * dns-benchmark benchmark \
  --use-defaults \
  --output /var/reports/dns/ \
  --formats excel,csv \
  --domain-stats \
  --error-breakdown
```

**Result:** Automated compliance and SLA reporting

---

### 🔐 For Privacy Advocates: Test Encrypted DNS

```bash
# Benchmark privacy-focused DoH/DoT resolvers
dns-benchmark benchmark \
  --doh \
  --resolvers privacy-resolvers.json \
  --domains sensitive-sites.txt \
  --dnssec-validate
```

**Result:** Find fastest encrypted DNS without sacrificing privacy

---

## 📦 Installation & Setup

### Requirements

- Python 3.9+
- pip package manager

### Install from PyPI

```bash
pip install dns-benchmark-tool
```

### Install from Source

```bash
git clone https://github.com/frankovo/dns-benchmark-tool.git
cd dns-benchmark-tool
pip install -e .
```

### Verify Installation

```bash
dns-benchmark --version
dns-benchmark --help
```

### First Run

```bash
# Test with defaults (recommended for first time)
dns-benchmark benchmark --use-defaults --formats csv,excel
```

---

## 📖 Usage Examples

### Basic Usage

```bash
# Basic test with progress bars
dns-benchmark benchmark --use-defaults --formats csv,excel

# Basic test without progress bars
dns-benchmark benchmark --use-defaults --formats csv,excel --quiet

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
dns-benchmark benchmark --use-defaults --formats csv,excel --record-types A,AAAA,MX

# Custom output location and formats
dns-benchmark benchmark \
  --use-defaults \
  --output ./my-results \
  --formats csv,excel

# Include detailed statistics
dns-benchmark benchmark \
  --use-defaults \
  --formats csv,excel \
  --record-type-stats \
  --error-breakdown

# High concurrency with retries
dns-benchmark benchmark \
  --use-defaults \
  --formats csv,excel \
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

# New top commands
# Run a basic benchmark (default: rank by latency)
dns-benchmark top
# → Tests all resolvers with sample domains, ranks by latency

# Limit the number of resolvers shown
dns-benchmark top --limit 5
# → Shows only the top 5 resolvers

# Rank by success rate
dns-benchmark top --metric success
# → Ranks resolvers by highest success rate

# Rank by reliability (combined score: success rate + latency)
dns-benchmark top --metric reliability
# → Uses weighted score to rank resolvers

# Filter resolvers by category
dns-benchmark top --category privacy
dns-benchmark top --category family
dns-benchmark top --category security
# → Tests only resolvers in the specified category

# Use a custom domain list
dns-benchmark top --domains domains.txt
# → Loads domains from a text file instead of built-in sample list

# Specify DNS record types
dns-benchmark top --record-types A,AAAA,MX
# → Queries multiple record types (comma-separated)

# Adjust timeout and concurrency
dns-benchmark top --timeout 3.0 --max-concurrent 50
# → Sets query timeout to 3 seconds and limits concurrency to 50

# Export results to JSON
dns-benchmark top --output results.json
# → Saves results in JSON format

# Export results to CSV
dns-benchmark top --output results.csv
# → Saves results in CSV format

# Export results to TXT
dns-benchmark top --output results.txt
# → Saves results in plain text format

# Quiet mode (no progress bar, CI/CD friendly)
dns-benchmark top --quiet
# → Suppresses progress output

# Example combined usage
dns-benchmark top --limit 10 --metric reliability --category privacy --output top_resolvers.csv
# → Benchmarks privacy resolvers, ranks by reliability, shows top 10, exports to CSV

# New compare commaands
# Comparison of resolvers by name
dns-benchmark compare Cloudflare Google Quad9
# ^ Compares Cloudflare, Google, and Quad9 resolvers using default domains and record type A

# Basic compare resolvers by IP address
dns-benchmark compare 1.1.1.1 8.8.8.8 9.9.9.9
# ^ Directly specify resolver IPs instead of names

# Increase iterations for more stable results
dns-benchmark compare "Cloudflare" "Google" --iterations 5
# ^ Runs 5 rounds of queries per resolver/domain/record type

# Use a custom domain list from file
dns-benchmark compare Cloudflare Google -d ./data/domains.txt
# ^ Loads domains from domains.txt instead of sample domains

# Query multiple record types
dns-benchmark compare Cloudflare Google -t A,AAAA,MX
# ^ Tests A, AAAA, and MX records for each domain

# Adjust timeout and concurrency
dns-benchmark compare Cloudflare Google --timeout 3.0 --max-concurrent 200
# ^ Sets query timeout to 3 seconds and allows 200 concurrent queries

# Export results to JSON
dns-benchmark compare Cloudflare Google -o results.json
# ^ Saves comparison summary to results.json

# Export results to CSV
dns-benchmark compare Cloudflare Google -o results.csv
# ^ Saves comparison summary to results.csv (via CSVExporter)

# Suppress progress output
dns-benchmark compare Cloudflare Google --quiet
# ^ Runs silently, only prints final results

# Show detailed per-domain breakdown
dns-benchmark compare Cloudflare Google --show-details
# ^ Prints average latency and success counts per domain for each resolver

# New monitoring commands
# Start monitoring with default resolvers and sample domains
dns-benchmark monitoring --use-defaults 
# ^ Runs indefinitely, checking every 60s, using built-in resolvers and 5 sample domains

# Monitor with a custom resolver list from JSON
dns-benchmark monitoring -r resolvers.json --use-defaults
# ^ Loads resolvers from resolvers.json, domains from defaults

# Monitor with a custom domain list
dns-benchmark monitoring -d domains.txt --use-defaults
# ^ Uses default resolvers, but domains are loaded from domains.txt

# Change monitoring interval to 30 seconds
dns-benchmark monitoring --use-defaults --interval 30
# ^ Runs checks every 30 seconds instead of 60

# Run monitoring for a fixed duration (e.g., 1 hour = 3600 seconds)
dns-benchmark monitoring --use-defaults --duration 3600
# ^ Stops automatically after 1 hour

# Set stricter alert thresholds
dns-benchmark monitoring --use-defaults --alert-latency 150 --alert-failure-rate 5
# ^ Alerts if latency >150ms or failure rate >5%

# Save monitoring results to a log file
dns-benchmark monitoring --use-defaults --output monitor.log
# ^ Appends results and alerts to monitor.log

# Combine options: custom resolvers, domains, interval, duration, and logging
dns-benchmark monitoring -r resolvers.json -d domains.txt -i 45 --duration 1800 -o monitor.log
# ^ Monitors resolvers from resolvers.json against domains.txt every 45s, for 30 minutes, logging to monitor.log

# Run monitoring for 1 hour with alerts
dns-benchmark monitoring --use-defaults --interval 30 --duration 3600 \
  --alert-latency 150 --alert-failure-rate 5 --output monitor.log

```

---

⚠️ **Note for new commands:** Resolvers with no successful queries are excluded from ranking and will display `Avg Latency: N/A`.

---

## Inline input support for resolvers and domains

This patch introduces full support for comma‑separated inline values for the
`--resolvers` and `--domains` flags, fixing issue [#39](https://github.com/frankovo/dns-benchmark-tool/issues/39) and improving cli usability without breaking any existing workflows.

### New capabilities

1. **inline resolvers**: `--resolvers "1.1.1.1,8.8.8.8,9.9.9.9"`
2. **inline domains**: `--domains "google.com,github.com"`
3. **single values**: `--resolvers "1.1.1.1"` or `--domains "google.com"`
4. **named resolvers**: `--resolvers "cloudflare,google,quad9"`
5. **mixed input**: `--resolvers "1.1.1.1,cloudflare,8.8.8.8"`

### Backward compatibility

- all existing file‑based configurations continue to work
- no breaking changes to the cli
- file detection takes priority over inline parsing

### Usage Examples

#### Before (Only files worked)

```bash
dns-benchmark benchmark \
    --resolvers data/resolvers.json \
    --domains data/domains.txt
```

#### After (Both work)

```bash
# Inline (New)
dns-benchmark benchmark \
    --resolvers "1.1.1.1,8.8.8.8,9.9.9.9" \
    --domains "google.com,github.com" \
    --timeout 10 \
    --retries 3 \
    --formats csv \
    --output ./troubleshooting

# Files (STILL WORKS)
dns-benchmark benchmark \
    --resolvers data/resolvers.json \
    --domains data/domains.txt \
    --formats csv
```

#### Named resolvers

```bash
# Named resolvers
dns-benchmark benchmark \
    --resolvers "Cloudflare,Google,Quad9" \
    --domains "google.com,github.com" \
    --timeout 10 \
    --retries 3 \
    --formats csv \
    --output ./troubleshooting_named
```

#### Mixed input

```bash
# Mixed input
dns-benchmark benchmark \
    --resolvers "1.1.1.1,Cloudflare,8.8.8.8" \
    --domains "google.com,github.com" \
    --timeout 10 \
    --retries 3 \
    --formats csv \
    --output ./troubleshooting_mixed
```

#### Single

```bash

# Single
dns-benchmark benchmark \
    --resolvers "1.1.1.1" \
    --domains "google.com" \
    --timeout 10 \
    --retries 3 \
    --formats csv \
    --output ./troubleshooting
```

## 🔧 Utilities

### Risolver management

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

### Domain management

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

### Category overview

```bash
# View all available categories
dns-benchmark list-categories
```

### Configuration management

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

## Complete usage guide

### Quick performance test

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

## 🔍 README Adjustments for Final Patch

### New CLI Options

| Option             | Description                                                                 | Example                                                                 |
|--------------------|-----------------------------------------------------------------------------|-------------------------------------------------------------------------|
| `--iterations, -i` | Run the full benchmark loop **N times**                                     | `dns-benchmark benchmark --use-defaults -i 3`                           |
| `--use-cache`      | Allow cached results to be reused across iterations                         | `dns-benchmark benchmark --use-defaults -i 3 --use-cache`               |
| `--warmup`         | Run a **full warmup** (all resolvers × domains × record types)              | `dns-benchmark benchmark --use-defaults --warmup`                       |
| `--warmup-fast`    | Run a **lightweight warmup** (one probe per resolver)                       | `dns-benchmark benchmark --use-defaults --warmup-fast`                  |
| `--include-charts` | Embed charts and graphs in PDF/Excel reports for visual performance analysis | `dns-benchmark benchmark --use-defaults --formats pdf,excel --include-charts` |

---

## ⚡ CLI Commands

The DNS Benchmark Tool now includes three specialized commands for different workflows:

### 🚀 Top

Quickly rank resolvers by speed and reliability.

```bash
# Rank resolvers quickly
dns-benchmark top

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
| **top**      | Quick ranking of resolvers by speed and reliability | Fast check to see which resolver is best right now | `--domains`, `--record-types`, `--output` | Sorted list of resolvers with latency & success rate |
| **compare**  | Side‑by‑side comparison of specific resolvers | Detailed benchmarking across chosen resolvers/domains | `--domains`, `--record-types`, `--iterations`, `--output`, `--show-details` | Table of resolvers with latency, success rate, per‑domain breakdown |
| **monitoring** | Continuous monitoring with alerts | Real‑time tracking of resolver performance over time | `--interval`, `--duration`, `--alert-latency`, `--alert-failure-rate`, `--output`, `--use-defaults` | Live status indicators, alerts, optional log file |

---

## 📊 Analysis Enhancements

- **Iteration count**: displayed when more than one iteration is run.  
- **Cache hits**: shows how many queries were served from cache (when `--use-cache` is enabled).  
- **Failure tracking**: resolvers with repeated errors are counted and can be inspected with `get_failed_resolvers()`.  
- **Cache statistics**: available via `get_cache_stats()`, showing number of cached entries and whether cache is enabled.  
- **Warmup results**: warmup queries are marked with `iteration=0` in raw data, making them easy to filter out in analysis.  

Example summary output:

```markdown

=== BENCHMARK SUMMARY ===
Total queries: 150
Successful: 140 (93.33%)
Average latency: 212.45 ms
Median latency: 198.12 ms
Fastest resolver: Cloudflare
Slowest resolver: Quad9
Iterations: 3
Cache hits: 40 (26.7%)
```

## ⚡ Best Practices

| Mode            | Recommended Flags                                                                 | Purpose                                                                 |
|-----------------|------------------------------------------------------------------------------------|-------------------------------------------------------------------------|
| **Quick Run**   | `--iterations 1 --timeout 1 --retries 0 --warmup-fast`                             | Fast feedback, minimal retries, lightweight warmup. Good for quick checks. |
| **Thorough Run**| `--iterations 3 --use-cache --warmup --timeout 5 --retries 2`                      | Multiple passes, cache enabled, full warmup. Best for detailed benchmarking. |
| **Debug Mode**  | `--iterations 1 --timeout 10 --retries 0 --quiet`                                  | Long timeout, no retries, minimal output. Useful for diagnosing resolver issues. |
| **Balanced Run**| `--iterations 2 --use-cache --warmup-fast --timeout 2 --retries 1`                 | A middle ground: moderate speed, some retries, cache enabled, quick warmup. |


## ⚙️ Configuration Files

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

### 📄 Optional PDF Export

By default, the tool supports **CSV** and **Excel** exports.  
PDF export requires the extra dependency **weasyprint**, which is not installed automatically to avoid runtime issues on some platforms.

#### Install with PDF support

```bash
pip install dns-benchmark-tool[pdf]
```

#### Usage

Once installed, you can request PDF output via the CLI:

```bash
dns-benchmark --use-defaults --formats pdf --output ./results
```

If `weasyprint` is not installed and you request PDF output, the CLI will show:

```bash
[-] Error during benchmark: PDF export requires 'weasyprint'. Install with: pip install dns-benchmark-tool[pdf]
```

---

### ⚠️ WeasyPrint Setup (for PDF export)

The DNS Benchmark Tool uses **WeasyPrint** to generate PDF reports.  
If you want PDF export, you need extra system libraries in addition to the Python package.

#### 🛠 Linux (Debian/Ubuntu)

```bash
sudo apt install python3-pip libpango-1.0-0 libpangoft2-1.0-0 \
  libharfbuzz-subset0 libjpeg-dev libopenjp2-7-dev libffi-dev
```

---

#### 🛠 macOS (Homebrew)

```bash
brew install pango cairo libffi gdk-pixbuf jpeg openjpeg harfbuzz
```

---

#### 🛠 Windows

Install GTK+ libraries using one of these methods:

- **MSYS2**: [Download MSYS2](https://www.msys2.org/), then run:

  ```bash
  pacman -S mingw-w64-x86_64-gtk3 mingw-w64-x86_64-libffi
  ```

- **GTK+ 64‑bit Installer**: [Download GTK+ Runtime](https://github.com/tschoonj/GTK-for-Windows-Runtime-Environment-Installer/releases) and run the installer.

Restart your terminal after installation.

---

#### ✅ Verify Installation

After installing the system libraries, install the Python extra:

```bash
pip install dns-benchmark-tool[pdf]
```

Then run:

```bash
dns-benchmark --use-defaults --formats pdf --output ./results
```

### JSON export

- Machine‑readable bundle including:
  - Overall statistics
  - Resolver statistics
  - Raw query results
  - Domain statistics
  - Record type statistics
  - Error breakdown

### Generate Sample Config

```bash
dns-benchmark generate-config \
  --category privacy \
  --output my-config.yaml
```

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

## Screenshots

Place images in `docs/screenshots/`:

- `docs/screenshots/cli_run.png`
- `docs/screenshots/excel_report.png`
- `docs/screenshots/pdf_summary.png`
- `docs/screenshots/pdf_charts.png`
- `docs/screenshots/excel_charts.png`
- `docs/screenshots/real_time_monitoring.png`

### 1. CLI Benchmark Run

[![CLI Benchmark Run](docs/screenshots/cli_run.png)](https://github.com/frankovo/dns-benchmark-tool)

### 2. Excel Report Output

[![Excel Report Output](docs/screenshots/excel_report.png)](https://github.com/frankovo/dns-benchmark-tool)

### 3. PDF Executive Summary

[![PDF Executive Summary](docs/screenshots/pdf_summary.png)](https://github.com/frankovo/dns-benchmark-tool)

### 4. PDF Charts

[![PDF Charts](docs/screenshots/pdf_charts.png)](https://github.com/frankovo/dns-benchmark-tool)

### 5. Excel Charts

[![Excel Charts](docs/screenshots/excel_charts.png)](https://github.com/frankovo/dns-benchmark-tool)

### 6. Real Time Monitoring

[![Real Time Monitoring](docs/screenshots/real_time_monitoring.png)](https://github.com/frankovo/dns-benchmark-tool)

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

## Release workflow

- **Prerequisites**
  - **GPG key configured:** run `make gpg-check` to verify.
  - **Branch protection:** main requires signed commits and passing CI.
  - **CI publish:** triggered on signed tags matching vX.Y.Z.

- **Prepare release (signed)**
  - **Patch/minor/major bump:**
  
    ```bash
    make release-patch      # or: make release-minor / make release-major
    ```

    - Updates versions.
    - Creates or reuses `release/X.Y.Z`.
    - Makes a signed commit and pushes the branch.
  - **Open PR:** from `release/X.Y.Z` into `main`, then merge once CI passes.

- **Tag and publish**
  - **Create signed tag and push:**

    ```bash
    make release-tag VERSION=X.Y.Z
    ```

    - Tags main with `vX.Y.Z` (signed).
    - CI publishes to PyPI.

- **Manual alternative**
  - **Create branch and commit signed:**
  
    ```bash
    git checkout -b release/manually-update-version-based-on-release-pattern
    git add .
    git commit -S -m "Release release/$NEXT_VERSION"
    git push origin release/$NEXT_VERSION
    ```

  - **Open PR and merge into main.**
  - **Then tag:**
  
    ```bash
    make release-tag VERSION=$NEXT_VERSION
    ```

- **Notes**
  - **Signed commits:** `git commit -S ...`
  - **Signed tags:** `git tag -s vX.Y.Z -m "Release vX.Y.Z"`
  - **Version sources:** `pyproject.toml` and `src/dns_benchmark/__init__.py`

---

## 🌐 BuildTools Web Dashboard — Now Live

**CLI stays free forever.** The web dashboard is now available at [buildtools.net](https://buildtools.net)

### What's live now (Free + Pro)

- 📊 **DNS Benchmark** — Visual results, history, powered by this CLI engine
- 🔔 **DNS Monitoring** — Real-time alerts when your records change
- 🆓 **Free tier** — Get started immediately, no credit card required
- 💼 **Pro at €14/mo** — Extended retention and priority support

### Coming Q2 2026

- ⚡ **HTTP Benchmark** — Measure API response times and CDN performance
- 🔒 **SSL Monitor** — Certificate expiry alerts before issues occur

### Coming Q3 2026

- 🌍 **Multi-region testing** — Test from multiple locations simultaneously

[→ Sign up free at buildtools.net](https://buildtools.net)

---

## 🛣️ Roadmap

### ✅ Current Release (CLI Edition)

- Benchmark, compare, monitor DNS resolvers
- DoH, DoT, DNSSEC support (new in this release)
- Export to CSV, Excel, PDF, JSON

### ✅ Web Dashboard (Live)

- DNS Benchmark with visual history
- DNS Monitoring with real-time alerts
- Free tier + Pro at €14/mo
- [buildtools.net](https://buildtools.net)

### 🔜 Coming Q2 2026

- HTTP Benchmark
- SSL Monitor
  
#### Q3 2026

- Multi-region testing

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

### 🛠 Development & Makefile Commands

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

### Code Guidelines

- Follow PEP 8 style guide
- Add tests for new features
- Update documentation
- Keep PRs focused and atomic

---

## ❓ FAQ

<details>
<summary><b>Why is my ISP's DNS not fastest?</b></summary>

Local ISP DNS often has caching advantages but may lack:
- Global anycast network (slower for distant domains)
- DNSSEC validation
- Privacy features (DoH/DoT)
- Reliability guarantees

Test both and decide based on YOUR priorities!

</details>

<details>
<summary><b>How often should I benchmark DNS?</b></summary>

- **One-time**: When choosing DNS provider
- **Monthly**: For network health checks
- **Before migration**: When switching providers
- **After issues**: To troubleshoot performance

</details>

<details>
<summary><b>Can I test my own DNS server?</b></summary>

Yes! Just add it to a custom resolvers JSON file:

```json
{
  "resolvers": [
    {"name": "My DNS", "ip": "192.168.1.1"}
  ]
}
```

</details>

<details>
<summary><b>What's the difference between CLI and hosted version?</b></summary>

**CLI (Free Forever):**

- Run tests from YOUR location
- Save results locally
- Open source — same engine powering the dashboard

**Web Dashboard (Live at buildtools.net):**

- Visual benchmark results and history
- DNS monitoring with real-time alerts
- Free tier available, Pro at €14/mo
- Multi-region testing coming Q3 2026
</details>

<details>
<summary><b>Is this tool safe to use in production?</b></summary>

Yes! The tool only performs DNS lookups (read operations). It does NOT:
- Modify DNS records
- Perform attacks
- Send data to external servers (unless you enable hosted features)

All tests are standard DNS queries that any resolver handles daily.

</details>

<details>
<summary><b>Why do results vary between runs?</b></summary>

DNS performance varies due to:
- Network conditions
- DNS caching (resolver and intermediate)
- Server load
- Geographic routing changes

Run multiple iterations (`--iterations 5`) for more consistent results.

</details>

---

## 🔗 Links & Support

### Official

- **Website**: [buildtools.net](https://buildtools.net)
- **PyPI**: [dns-benchmark-tool](https://pypi.org/project/dns-benchmark-tool/)
- **GitHub**: [frankovo/dns-benchmark-tool](https://github.com/frankovo/dns-benchmark-tool)

### Community

- **Discussions**: [GitHub Discussions](https://github.com/frankovo/dns-benchmark-tool/discussions)
- **Issues**: [Bug Reports](https://github.com/frankovo/dns-benchmark-tool/issues)

### Stats

- **Downloads**: 1,400+ (this week)
- **Active Users**: 600+

---

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

---

<div align="center">

**Built with ❤️ by [@frankovo](https://github.com/frankovo)**

Part of [BuildTools](https://buildtools.net) - Network Performance Suite

[⭐ Star on GitHub](https://github.com/frankovo/dns-benchmark-tool) • [📦 Install from PyPI](https://pypi.org/project/dns-benchmark-tool/)

</div>
