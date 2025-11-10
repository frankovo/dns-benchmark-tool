.PHONY: install install-dev uninstall mypy black isort flake8 cov test clean cli-test \
	gpg-check release-patch release-minor release-major release-tag

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

# GPG sanity check
gpg-check:
	./gpg-check.sh

# Release targets
release-patch:
	./release.sh patch

release-minor:
	./release.sh minor

release-major:
	./release.sh major

# Tag after PR merge
release-tag:
	@if [ -z "$(VERSION)" ]; then \
    	echo "❌ Usage: make release-tag VERSION=X.Y.Z"; exit 1; \
    fi
	./release-tag.sh $(VERSION)

