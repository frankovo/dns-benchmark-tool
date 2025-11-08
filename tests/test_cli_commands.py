import subprocess
import time
import tempfile
import shutil
from pathlib import Path

import pytest

WAIT_INTERVAL = 3

RESOLVERS = "./sample_data/resolvers.json"
DOMAINS = "./sample_data/domains.txt"

COMMANDS = [
    f"dns-benchmark benchmark --resolvers {RESOLVERS} --domains {DOMAINS}",
    f"dns-benchmark benchmark --resolvers {RESOLVERS} --domains {DOMAINS} "
    "--formats csv,excel,pdf --domain-stats --record-type-stats --error-breakdown --json --output ./results",
    # Quick performance test
    f"dns-benchmark benchmark --resolvers {RESOLVERS} --domains {DOMAINS}",
    f"dns-benchmark benchmark --resolvers {RESOLVERS} --domains {DOMAINS} --formats csv --quiet",
    f"dns-benchmark benchmark --resolvers {RESOLVERS} --domains {DOMAINS} --record-types A,AAAA,MX",
    f"dns-benchmark benchmark --resolvers {RESOLVERS} --domains {DOMAINS} --domain-stats --record-type-stats --error-breakdown",
    f"dns-benchmark benchmark --resolvers {RESOLVERS} --domains {DOMAINS} --json --output ./results",
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
    "dns-benchmark generate-config --output sample_config.yaml",
    "dns-benchmark generate-config --category security --output security_test.yaml",
    "dns-benchmark generate-config --category family --output family_protection.yaml",
    "dns-benchmark generate-config --category performance --output performance_test.yaml",
    "dns-benchmark generate-config --category privacy --output privacy_audit.yaml",
    # Performance optimization
    f"dns-benchmark benchmark --resolvers {RESOLVERS} --domains {DOMAINS} --max-concurrent 50 --timeout 3 --quiet --formats csv",
    f"dns-benchmark benchmark --resolvers {RESOLVERS} --domains {DOMAINS} --timeout 10 --retries 3 --max-concurrent 10",
    f"dns-benchmark benchmark --resolvers {RESOLVERS} --domains {DOMAINS} --formats csv --quiet --timeout 2",
    # Troubleshooting
    "python -m dns_benchmark.cli --help",
    f"dns-benchmark benchmark --resolvers {RESOLVERS} --domains {DOMAINS} --formats csv,excel",
    f"dns-benchmark benchmark --resolvers {RESOLVERS} --domains {DOMAINS} --timeout 10 --retries 3",
    f"dns-benchmark benchmark --resolvers {RESOLVERS} --domains {DOMAINS} --max-concurrent 25",
    f"python -m dns_benchmark.cli benchmark --resolvers {RESOLVERS} --domains {DOMAINS} --formats csv",
    f"dns-benchmark benchmark --resolvers {RESOLVERS} --domains {DOMAINS} --formats csv",
    # Use case examples
    f"dns-benchmark benchmark --resolvers {RESOLVERS} --domains {DOMAINS} --formats excel,pdf --output ./migration_analysis",
    f"dns-benchmark benchmark --resolvers {RESOLVERS} --domains {DOMAINS} --formats csv,excel --output ./provider_selection",
    f"dns-benchmark benchmark --resolvers {RESOLVERS} --domains {DOMAINS} --timeout 10 --retries 3 --formats csv --output ./troubleshooting",
    f"dns-benchmark benchmark --resolvers {RESOLVERS} --domains {DOMAINS} --formats pdf --output ./security_assessment",
    f"dns-benchmark benchmark --resolvers {RESOLVERS} --domains {DOMAINS} --formats csv --quiet --output ./performance_monitoring",
]

# Give each test a readable ID instead of [0], [1], …
IDS = [f"cmd_{i}" for i in range(len(COMMANDS))]


@pytest.fixture
def temp_output_dir():
    """Create a temporary directory for outputs and clean up afterwards."""
    outdir = Path(tempfile.mkdtemp(prefix="dns_benchmark_test_"))
    yield outdir
    shutil.rmtree(outdir)


@pytest.mark.cli
@pytest.mark.parametrize("cmd", COMMANDS, ids=IDS)
def test_cli_command(cmd):
    """Run each CLI command and assert it completes successfully."""
    # Replace placeholder with actual temp directory
    cmd = cmd.replace("{outdir}", str(temp_output_dir))

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
