# Contributing Guidelines

Thank you for considering contributing to `dns-benchmark-tool`!  
We welcome improvements, bug fixes, and new ideas.

---

## How to Contribute

- Fork the repository and create a new branch (`feature/<name>` or `fix/<issue>`).
- Make your changes with clear, signed commit messages.
- Ensure all tests pass locally (`pytest` recommended).
- Run `flake8` to check code style before submitting.
- Submit a Pull Request (PR) to the `main` branch.

---

## Code Style

- Follow [PEP8](https://peps.python.org/pep-0008/) guidelines.
- Use `flake8` for linting.
- Keep commits focused and descriptive.

---

## Pull Requests

- All PRs must pass CI checks before merge.
- Branch protection rules require signed commits.
- Reviews may be requested depending on the type of change.
- PRs should not include version bumps or release tags — those are handled by the maintainer.

---

## Release Process

- Releases are managed by the maintainer using `release/x.y.z` branches.
- Once stable, the branch is merged into `main`.
- A tag (`vX.Y.Z`) is created on `main` to trigger publishing to PyPI.
- Contributors should not push tags; only the maintainer handles releases.

---

## Reporting Issues

- Use GitHub Issues for bugs, feature requests, or questions.
- Please include steps to reproduce and environment details when reporting bugs.

---

## Community

- Be respectful and constructive in discussions.
- Focus on clear communication and collaborative problem‑solving.

## Releases

Releases are managed separately by the maintainer.  
See [RELEASE.md](./RELEASE.md) for the full release process.
