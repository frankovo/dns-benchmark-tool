# DNS Benchmark Tool

<div align="center">

## 🎉 1000+ Downloads in 5 Days! 🎉

🙏 Thank you to our amazing community!
📢 Help shape the roadmap: [**Take 2-min survey →**](https://forms.gle/BJBiyBFvRJHskyR57)

</div>

---

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

## Key Features

✅ **Multi-resolver benchmarking** - Compare Google, Cloudflare, Quad9, OpenDNS, and custom resolvers  
✅ **Multiple record types** - Test A, AAAA, MX, TXT, NS, CNAME, and more  
✅ **Rich analytics** - Per-resolver, per-domain, and per-record-type statistics  
✅ **Export formats** - CSV, Excel, PDF, JSON for reporting and automation  
✅ **High concurrency** - Async queries with configurable limits  
✅ **Cache control** - Test with/without DNS caching  
✅ **Iteration support** - Run multiple test iterations for reliability  
✅ **CI/CD ready** - Quiet mode, JSON output, exit codes for automation  

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

## Links

- **GitHub:** https://github.com/frankovo/dns-benchmark-tool
- **Documentation:** Full usage guide, advanced examples, and screenshots are available.
- **Issues:** https://github.com/frankovo/dns-benchmark-tool/issues
- **PyPI:** https://pypi.org/project/dns-benchmark-tool/
- **Feedback Survey:** https://forms.gle/BJBiyBFvRJHskyR57

---

## License

MIT License - see [LICENSE](https://github.com/frankovo/dns-benchmark-tool/blob/main/LICENSE) file for details.

---

## Contributing

Contributions welcome! Please check our [GitHub repository](https://github.com/frankovo/dns-benchmark-tool) for guidelines.

**Help us improve:** Run `dns-benchmark feedback` to share your experience! 🙏
