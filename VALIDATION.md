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
The staging checks preceded public source publication. The reviewed source is
now public at [`proudbase/proudauth-sdk-dotnet`](https://github.com/proudbase/proudauth-sdk-dotnet).
No package-registry release or SDK release tag has been published.

The [initial CI matrix](https://github.com/proudbase/proudauth-sdk-dotnet/actions/runs/38454592098)
passed Linux/macOS but exposed six Windows failures: native RSA accepted three
noncanonical DigestInfo vectors, and invalid EC points threw a platform exception.
The verifier now requires exact SHA-256 DER encoding and treats unsupported EC
key imports as unusable keys. Existing vectors remain unchanged; two additional
public-verifier regression cases cover both behaviors. Post-fix local validation:
**344 tests pass**, Release build/format and both package builds pass.
The [corrected independent CI matrix](https://github.com/proudbase/proudauth-sdk-dotnet/actions/runs/38455524378)
passed at commit `a555f8c6b6f72244c2692aa520ac4ed501fe2bcb` on
Windows 2022, Ubuntu 24.04 and macOS 14: all 344 tests, locked restore, Release
build, formatting and both NuGet package builds. No fixture expectations were
weakened or OS skipped. Private vulnerability reporting is enabled.

Excluded: original .git history, actual .env/credentials, deployment state,
private screenshots/database backups, SDK caches/build output, image archives,
benchmark seeds and customer data. The original checkout was not modified.
