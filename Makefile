.PHONY: install install-dev uninstall mypy black isort flake8 cov test clean cli-test \
    gpg-check release-patch release-minor release-major release-tag release-tag-dry \
    release-check release-flow release-clean release-build release-info release-status cz-commit cz-changelog cz-bump

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

test: mypy black isort flake8 cov clean

clean:
	rm -rf __pycache__ .pytest_cache .mypy_cache htmlcov .coverage coverage.xml \
	build dist *.egg-info .eggs benchmark_results {outdir}

cli-test:
    # Run only the CLI smoke tests marked with @pytest.mark.cli
	pytest -vv -s -m cli tests/test_cli_commands.py \
	clean

# 🔑 GPG sanity check
gpg-check:
	./gpg-check.sh

# 🚀 Release targets using commitizen
release-patch:
	./release.sh patch

release-minor:
	./release.sh minor

release-major:
	./release.sh major

# 🏷️ Tag after PR merge
release-tag:
	./release-tag.sh

release-tag-dry:
	./release-tag.sh --dry-run

# 🔎 Version consistency check
release-check:
	@echo "🔎 Checking versions..."
	@PYPROJECT_VERSION=$$(grep '^version = ' pyproject.toml | head -n1 | cut -d'"' -f2); \
	INIT_VERSION=$$(grep '^__version__ = ' src/dns_benchmark/__init__.py | head -n1 | cut -d'"' -f2); \
	echo "pyproject.toml version: $$PYPROJECT_VERSION"; \
	echo "__init__.py version:    $$INIT_VERSION"; \
	if [ "$$PYPROJECT_VERSION" = "$$INIT_VERSION" ]; then \
		echo "✅ Versions are in sync."; \
	else \
		echo "❌ Version mismatch! Please fix before tagging."; \
		exit 1; \
	fi

# 🔮 Preview next version bump (no changes applied)
release-preview:
	@if [ -z "$(INCREMENT)" ]; then \
		echo "❌ Usage: make release-preview INCREMENT=patch|minor|major"; exit 1; \
	fi; \
	CURRENT_VERSION=$$(grep '^version = ' pyproject.toml | sed -E 's/version = "(.*)"/\1/'); \
	IFS='.' read -r MAJOR MINOR PATCH <<< "$$CURRENT_VERSION"; \
	case "$(INCREMENT)" in \
		patch) PATCH=$$((PATCH + 1)); NEXT_VERSION="$$MAJOR.$$MINOR.$$PATCH" ;; \
		minor) MINOR=$$((MINOR + 1)); PATCH=0; NEXT_VERSION="$$MAJOR.$$MINOR.$$PATCH" ;; \
		major) MAJOR=$$((MAJOR + 1)); MINOR=0; PATCH=0; NEXT_VERSION="$$MAJOR.$$MINOR.$$PATCH" ;; \
		*) echo "❌ Unknown bump type: $(INCREMENT)"; exit 1 ;; \
	esac; \
	echo "🔎 Current version: $$CURRENT_VERSION"; \
	echo "⬆️  Bump type: $(INCREMENT)"; \
	echo "✨ Next version would be: $$NEXT_VERSION"

# 📊 Show current release info
release-info:
	@bash -euo pipefail -c '\
	PYPROJECT_VERSION=$$(grep "^version = " pyproject.toml | head -n1 | cut -d"\"" -f2); \
	INIT_VERSION=$$(grep "^__version__ = " src/dns_benchmark/__init__.py | head -n1 | cut -d"\"" -f2); \
	LATEST_TAG=$$(git describe --tags --abbrev=0 2>/dev/null || echo "none"); \
	printf "📊 Release information:\n"; \
	printf "pyproject.toml version: %s\n" "$$PYPROJECT_VERSION"; \
	printf "__init__.py version:    %s\n" "$$INIT_VERSION"; \
	printf "Latest Git tag:         %s\n" "$$LATEST_TAG"; \
	if [ "$$LATEST_TAG" = "v$$PYPROJECT_VERSION" ]; then \
		printf "✅ Repo is in sync: latest tag matches pyproject.toml\n"; \
	else \
		printf "⚠️  Repo not in sync: pyproject.toml version and latest tag differ\n"; \
	fi'


# 🔄 Full release flow: check → dry-run → tag
release-flow:
	@echo "🚦 Starting full release flow..."
	@$(MAKE) release-check
	@$(MAKE) release-tag-dry
	@echo "✅ Dry-run complete. If everything looks good, proceeding to actual tag..."
	@$(MAKE) release-tag
	@echo "🎉 Release flow finished. Signed tag pushed, CI will publish to PyPI."


# 🧹 Clean & build targets
release-clean:
	@echo "🧹 Cleaning build artifacts..."
	@rm -rf build/ dist/ *.egg-info
	@find . -name '__pycache__' -type d -exec rm -rf {} +
	@find . -name '*.pyc' -delete
	@echo "✅ Clean complete. Ready for a fresh build."

release-build: release-clean
	@echo "🔧 Building package..."
	@python -m pip install --upgrade pip build
	@python -m build
	@if [ ! -d "dist" ]; then \
		echo "❌ Build failed."; \
		exit 1; \
	fi
	@echo "✅ Build complete. Artifacts in dist/"


# 🔁 Release status: check + info
release-status:
	@$(MAKE) release-check
	@$(MAKE) release-info

# Commitizen helpers
cz-commit:
	cz commit

cz-changelog:
	cz changelog

cz-bump:
	@if [ -z "$(INCREMENT)" ]; then \
		echo "❌ Usage: make cz-bump INCREMENT=patch|minor|major"; exit 1; \
	fi
	cz bump --changelog --increment $(INCREMENT)
