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
[![Main branch protected](https://img.shields.io/badge/branch%20protection-main%20✅-brightgreen)](https://github.com/frankovo/dns-benchmark-tool/blob/main/RELEASE.md)

Benchmark DNS resolvers across domains and record types.  
Generates analytics and exports to CSV, Excel, PDF, and JSON.

## Installation

```bash
pip install dns-benchmark-tool
```

## Quick usage

```bash
# Benchmark with default resolvers and domains
dns-benchmark benchmark --use-defaults

# Custom resolvers and domains
dns-benchmark benchmark --resolvers data/resolvers.json --domains data/domains.txt
```

## Features

- Compare DNS resolver performance globally
- Export results to CSV, Excel, PDF, JSON
- Domain and record‑type statistics
- Error breakdowns
- Automation support (cron jobs, CI/CD)

## Documentation

Full usage guide, advanced examples, and screenshots are available on [GitHub](https://github.com/frankovo/dns-benchmark-tool).

---

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

---
