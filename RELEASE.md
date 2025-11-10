# Release Process

This document describes how releases are managed for `dns-benchmark-tool`.

---

## Workflow Overview

1. **Create a release branch**
   - From `main`, create a branch named `release/x.y.z`.
   - Example: `release/0.2.1`.

2. **Make changes**
   - Update `pyproject.toml` and `src/dns_benchmark/__init__.py` with the new version.
   - Update changelog or documentation as needed.
   - Commit changes with **signed commits**.

3. **Push the branch**

   ```bash
   git push origin release/x.y.z
   ```

4. **Open a Pull Request**
   - Target branch: `main`.
   - CI must pass before merge.
   - Branch protection rules apply (signed commits, tests, etc.).

5. **Merge the PR**
   - Once stable, merge `release/x.y.z` into `main`.
   - At this point, `main` reflects the new version.

6. **Tag the release**

   - After merging, create and push a tag on `main`:
  
     ```bash
     git checkout main
     git pull origin main
     git tag vX.Y.Z
     git push origin vX.Y.Z
     ```

   - Example: `v0.2.1`.

7. **Publish**
   - GitHub Actions sees the tag and publishes the package to PyPI.
   - Verify the new version is available on PyPI.

---

## Notes

- **Do not push tags from release branches.** Tags should only be created on `main` after the PR is merged.
- **One tag per version.** PyPI does not allow re‑uploads of the same version.
- **Iterate freely** on the release branch until you are satisfied, then merge and tag.
- **Only the maintainer** (with write access) should create and push release tags.

---

## Hotfixes

For urgent bug fixes:

- Create a new branch from `main` named `release/x.y.z` (next patch version).
- Apply the fix, commit, and push.
- Open a PR into `main`, merge once CI passes.
- Tag the merge commit (`vX.Y.Z`) to publish the hotfix.
