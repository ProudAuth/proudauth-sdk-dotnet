# Standalone validation — 2026-10-13

Source checkout HEAD: `5ff6ddb852b572a05d4b1b5e6afdf2ecc1350a11`.
SOURCE-MANIFEST.json records working-tree input hashes, including unpublished
changes; it does not assert that the input bytes equal that commit. The vendored
contracts/vectors are pinned separately in testdata/manifest.json.

Runtime: **.NET SDK 8.0.421; runtime 8.0.27; macOS arm64**.

Contract/vector hashes (11 files): pass. Locked offline restore: pass. Release build: **0 warnings/errors**. Test executable: **342 passed, 0 failed, 0 skipped**. Format verification: pass. NuGet pack: **both 0.2.0 packages built**. Isolated installed-package ASP.NET Core consumer: **0 warnings/errors**.

The consumer used its own package cache and source mapping: ProudAuth packages came from the new artifacts, BouncyCastle from the existing cache. This avoided selecting an older unpublished 0.2.0 package from the global cache. NuGetAudit=false was used only for the offline local restore. Windows/Linux CI is configured, not locally tested.

All restores used existing local caches with network package/module downloads
disabled. No Docker, database or public deployment was used; tests use synthetic
data and loopback mock servers. Commands: python3 scripts/check-contracts.py;
the standalone README and CI contain the build/test commands. npm used --offline;
Dart used pub get --offline; .NET used only local feeds and NuGetAudit=false.

Generated build outputs/dependencies and temporary consumer directories were
removed after verification. Dependency lockfiles and synthetic vectors remain.
Final documentation/repository metadata edits do not change runtime behavior.
No GitHub or registry publication was performed by this staging work. Independent
CI is prepared but has not run yet for this repository.

Excluded: original .git history, actual .env/credentials, deployment state,
private screenshots/database backups, SDK caches/build output, image archives,
benchmark seeds and customer data. The original checkout was not modified.
