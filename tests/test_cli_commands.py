import subprocess
import tempfile
import time
from pathlib import Path

import pytest

WAIT_INTERVAL = 3

RESOLVERS = "./sample_data/resolvers.json"
DOMAINS = "./sample_data/domains.txt"

COMMANDS = [
    f"dns-benchmark benchmark --resolvers {RESOLVERS} --domains {DOMAINS} --output {{outdir}}",
    f"dns-benchmark benchmark --resolvers {RESOLVERS} --domains {DOMAINS} "
    "--formats csv,excel,pdf --domain-stats --record-type-stats --error-breakdown --json --output {{outdir}}",
    # Quick performance test
    f"dns-benchmark benchmark --resolvers {RESOLVERS} --domains {DOMAINS} --output {{outdir}}",
    f"dns-benchmark benchmark --resolvers {RESOLVERS} --domains {DOMAINS} --formats csv --quiet --output {{outdir}}",
    f"dns-benchmark benchmark --resolvers {RESOLVERS} --domains {DOMAINS} --record-types A,AAAA,MX --output {{outdir}}",
    f"dns-benchmark benchmark --resolvers {RESOLVERS} --domains {DOMAINS} --domain-stats --record-type-stats --error-breakdown --output {{outdir}}",
    f"dns-benchmark benchmark --resolvers {RESOLVERS} --domains {DOMAINS} --json --output {{outdir}}",
    # New options smoke tests
    f"dns-benchmark benchmark --resolvers {RESOLVERS} --domains {DOMAINS} --iterations 2 --output {{outdir}}",
    f"dns-benchmark benchmark --resolvers {RESOLVERS} --domains {DOMAINS} --iterations 2 --use-cache --output {{outdir}}",
    f"dns-benchmark benchmark --resolvers {RESOLVERS} --domains {DOMAINS} --warmup --output {{outdir}}",
    f"dns-benchmark benchmark --resolvers {RESOLVERS} --domains {DOMAINS} --warmup-fast --output {{outdir}}",
    # Information & discovery
    "dns-benchmark list-defaults",
    "dns-benchmark list-resolvers",
    "dns-benchmark list-resolvers --details",
    "dns-benchmark list-resolvers --category security",
    "dns-benchmark list-resolvers --category privacy",
    "dns-benchmark list-resolvers --category family",
    "dns-benchmark list-resolvers --format csv",
    "dns-benchmark list-resolvers --format json",
    "dns-benchmark list-domains",
    "dns-benchmark list-domains --category tech",
    "dns-benchmark list-domains --category ecommerce",
    "dns-benchmark list-domains --category social",
    "dns-benchmark list-domains --count 10",
    "dns-benchmark list-domains --category news --count 5",
    "dns-benchmark list-domains --format csv",
    "dns-benchmark list-domains --format json",
    "dns-benchmark list-categories",
    # Configuration management
    "dns-benchmark generate-config --output {{outdir}}/sample_config.yaml",
    "dns-benchmark generate-config --category security --output {{outdir}}/security_test.yaml",
    "dns-benchmark generate-config --category family --output {{outdir}}/family_protection.yaml",
    "dns-benchmark generate-config --category performance --output {{outdir}}/performance_test.yaml",
    "dns-benchmark generate-config --category privacy --output {{outdir}}/privacy_audit.yaml",
    # Performance optimization
    f"dns-benchmark benchmark --resolvers {RESOLVERS} --domains {DOMAINS} --max-concurrent 50 --timeout 3 --quiet --formats csv --output {{outdir}}",
    f"dns-benchmark benchmark --resolvers {RESOLVERS} --domains {DOMAINS} --timeout 10 --retries 3 --max-concurrent 10 --output {{outdir}}",
    f"dns-benchmark benchmark --resolvers {RESOLVERS} --domains {DOMAINS} --formats csv --quiet --timeout 2 --output {{outdir}}",
    # Troubleshooting
    "python -m dns_benchmark.cli --help",
    f"dns-benchmark benchmark --resolvers {RESOLVERS} --domains {DOMAINS} --formats csv,excel --output {{outdir}}",
    f"dns-benchmark benchmark --resolvers {RESOLVERS} --domains {DOMAINS} --timeout 10 --retries 3 --output {{outdir}}",
    f"dns-benchmark benchmark --resolvers {RESOLVERS} --domains {DOMAINS} --max-concurrent 25 --output {{outdir}}",
    f"python -m dns_benchmark.cli benchmark --resolvers {RESOLVERS} --domains {DOMAINS} --formats csv --output {{outdir}}",
    f"dns-benchmark benchmark --resolvers {RESOLVERS} --domains {DOMAINS} --formats csv --output {{outdir}}",
    # Use case examples
    f"dns-benchmark benchmark --resolvers {RESOLVERS} --domains {DOMAINS} --formats excel,pdf --output {{outdir}}/migration_analysis",
    f"dns-benchmark benchmark --resolvers {RESOLVERS} --domains {DOMAINS} --formats csv,excel --output {{outdir}}/provider_selection",
    f"dns-benchmark benchmark --resolvers {RESOLVERS} --domains {DOMAINS} --timeout 10 --retries 3 --formats csv --output {{outdir}}/troubleshooting",
    f"dns-benchmark benchmark --resolvers {RESOLVERS} --domains {DOMAINS} --formats pdf --output {{outdir}}/security_assessment",
    f"dns-benchmark benchmark --resolvers {RESOLVERS} --domains {DOMAINS} --formats csv --quiet --output {{outdir}}/performance_monitoring",
]

# Give each test a readable ID instead of [0], [1], …
IDS = [f"cmd_{i}" for i in range(len(COMMANDS))]


@pytest.fixture(scope="session")
def temp_output_dir():
    """Create a temporary directory for all test outputs and clean up after all tests."""
    outdir = Path(tempfile.mkdtemp(prefix="dns_benchmark_test_"))
    print(f"\n=== Created test output directory: {outdir} ===\n")
    yield outdir


@pytest.mark.cli
@pytest.mark.parametrize("cmd", COMMANDS, ids=IDS)
def test_cli_command(cmd, temp_output_dir):
    """Run each CLI command and assert it completes successfully."""
    # Replace placeholder with actual temp directory
    cmd = cmd.replace("{{outdir}}", str(temp_output_dir))

    result = subprocess.run(
        cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
    )
    # Preview output for debugging
    print("\n--- OUTPUT ---\n", result.stdout[:200])
    print("\n--- ERROR ---\n", result.stderr[:200])

    # Assert command exited cleanly
    assert result.returncode == 0, f"Command failed: {cmd}\n{result.stderr}"

    # Wait before next command to avoid blocking
    time.sleep(WAIT_INTERVAL)
