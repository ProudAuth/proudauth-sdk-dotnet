# Changelog

All changes, including breaking changes, are documented here. Package releases
will use semantic versioning; the initial 0.x API may change between minor versions.

## Unreleased — 0.2.0 standalone extraction

### Added

- Independent repository layout, root-level package metadata and CI.
- Vendored shared access-token and support-operation fixtures, with source HEAD
  and SHA-256 provenance, and an offline integrity check.
- Standalone contribution and private vulnerability reporting policies.

### Changed

- Monorepo-relative test inputs and documentation links now work from this checkout.

### Fixed

- RS256 verification now rejects noncanonical SHA-256 DigestInfo encodings on
  Windows as on Linux/macOS, matching the existing shared negative vectors.
- Invalid EC public keys fail closed when the platform throws
  `PlatformNotSupportedException`; other valid keys in the JWKS remain usable.

The standalone source is public. No registry package or release tag has been published.
The 0.2.0 version identifiers are retained; there is no published registry package.
