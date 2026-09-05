# Dependency Surface Review

This document is a **dated Stage 9 snapshot** (2026-09-04) of the
`rust-conversion` tree while Cargo and uv still coexisted. It is historical
review evidence, not a current description of the repository after Stage 10
Python retirement. Do not treat the Python/`uv.lock` rows below as present
dependencies.

Low-cost provenance/maturity triage of ChainCheck's committed manifests on the
`rust-conversion` branch after Stage 8. This is not a vulnerability audit, source
review, or CVE scan.

Date: 2026-09-04  
Lockfiles: `Cargo.lock` (Cargo lock version 4), `uv.lock` (uv lock version 1)

## Summary

- Direct dependencies reviewed: **12** (8 Rust runtime from `Cargo.toml`; 2 Python runtime, 1 Python test, 1 Python build-system).
- Classified **Concern**: **0**
- Classified **Watch**: **1** (`serde-saphyr`)
- Classified **Unable to assess**: **0**
- Remaining **No surface concern identified**: **11**
- `Cargo.toml` / `Cargo.lock` are appropriate committed inputs for GitHub's Cargo dependency scanning (all Cargo sources are `registry+https://github.com/rust-lang/crates.io-index`). The repository also contains committed Python `pyproject.toml` / `uv.lock` dependency information. Exact GitHub dependency-graph/Dependabot coverage and repository security-feature enablement cannot be established from repository contents alone.
- No dependency requires prompt human investigation as a release blocker. `serde-saphyr` is Watch only; leave it in place for Stage 9.
- Major limitations: surface review only; most transitives not researched; absence of a surface warning is not proof of safety.

The Rust graph is the expected small CLI set (JSON/JSONC, regex, serde, YAML, TOML, SHA-256, blocking HTTPS/TLS). Feature flags on `jsonc-parser`, `serde-saphyr`, and `ureq` are already minimised. `ureq` + `rustls` + `ring` is the largest subtree and is proportionate to TLS. Duplicate `winnow` majors via `toml` and Windows crates via `ring` are lockfile noise, not Stage 9 churn.

## Dependencies of concern

| Dependency | Resolved version | Scope | Status | Warning signals | Evidence | Suggested next step |
|---|---:|---|---|---|---|---|
| serde-saphyr | 1.2.0 | Rust runtime (`Cargo.toml` / `Cargo.lock`) | Watch | Relatively young crate; name historically associated with the saphyr project though independently maintained; YAML parser is a documented fork (`granit-parser`) | crates.io since 2025-09-27; ~5.9M downloads; owner `bourumir-wyngs`; crate docs state it is not part of saphyr; `granit-parser` 1.2.0 is crates.io, not a git dependency | Leave in place for Stage 9; re-check provenance if YAML parsing is revisited later. Not a release blocker. |

## Detailed notes

No Concern items.

## Direct dependency register

| Dependency | Resolved version | Scope | Result | Brief rationale |
|---|---:|---|---|---|
| jsonc-parser | 0.33.1 | Rust runtime (`Cargo.toml` / `Cargo.lock`) | No surface concern identified | crates.io since 2020; dprint/`dsherret` JSONC parser; used for text `bun.lock`. Features limited to `serde`. |
| regex | 1.13.1 | Rust runtime (`Cargo.toml` / `Cargo.lock`) | No surface concern identified | Mature rust-lang ecosystem crate for log/content matching. |
| serde | 1.0.229 | Rust runtime (`Cargo.toml` / `Cargo.lock`) | No surface concern identified | Mature serde-rs crate; `derive` only. |
| serde-saphyr | 1.2.0 | Rust runtime (`Cargo.toml` / `Cargo.lock`) | Watch | See repository observations. Independent YAML deserializer (not the saphyr project) used for `pnpm-lock.yaml`. High downloads, crates.io source, recently published 1.2.0. Not a Stage 9 replacement candidate. |
| serde_json | 1.0.151 | Rust runtime and dev (`Cargo.toml` / `Cargo.lock`) | No surface concern identified | Mature serde JSON crate; also listed under `[dev-dependencies]` (same crate). |
| sha2 | 0.10.9 | Rust runtime (`Cargo.toml` / `Cargo.lock`) | No surface concern identified | Mature RustCrypto digest crate for payload SHA-256. |
| toml | 0.9.12+spec-1.1.0 | Rust runtime (`Cargo.toml` / `Cargo.lock`) | No surface concern identified | Official toml-rs crate for pyproject/Pipfile/Python locks. Pulls two `winnow` majors; observation only. |
| ureq | 3.4.0 | Rust runtime (`Cargo.toml` / `Cargo.lock`) | No surface concern identified | Established blocking HTTP client; `default-features = false`, `rustls` + `gzip`. TLS via `rustls`/`ring` (native `cc` at build time only). Proportionate to live Aikido fetches. |
| pyyaml | 6.0.3 | Python runtime (`pyproject.toml` / `uv.lock`) | No surface concern identified | Mature PyPI YAML library for the retained Python implementation. |
| tqdm | 4.70.0 | Python runtime (`pyproject.toml` / `uv.lock`) | No surface concern identified | Mature progress-bar library used by the Python CLI only. |
| pytest | 9.1.1 | Python test (`pyproject.toml` `[dependency-groups].test` / `uv.lock`) | No surface concern identified | Mature test runner for the Python/oracle suite. |
| setuptools | >=61 (not lock-resolved) | Python build (`pyproject.toml` `[build-system]`) | No surface concern identified | Established Python packaging component. Not a runtime dependency of either scanner. The `[build-system]` floor is not an exact uv lock pin; that is a reproducibility observation, not a provenance warning. |

## Repository-level observations

- `Cargo.lock` is committed. Every non-root Cargo package uses crates.io; there are no git, path, or URL dependencies.
- `uv.lock` is committed for Python runtime and test groups. `setuptools` is a pep517 `[build-system]` requirement (`setuptools>=61`) and is not lock-resolved in `uv.lock`; that is a build-backend reproducibility observation, not a surface-concern classification.
- Some Rust constraints are broad (`serde_json = "1"`, `toml = "0.9"`, `ureq = "3.4"`, `sha2 = "0.10"`) but the lockfile pins exact versions for `--locked` builds.
- Two package managers coexist by design until Stage 10 (Cargo + uv). That is expected, not a conflict.
- No `.github/dependabot.yml`. Exact GitHub dependency-graph/Dependabot coverage and repository security-feature enablement cannot be established from repository contents alone.
- `serde-saphyr` 1.2.0 (crates.io created 2025-09-27; ~5.9M downloads; repository `bourumir-wyngs/serde-saphyr`; single crates.io owner `bourumir-wyngs`; updated 2026-08-30). The crate documents that it is **not** part of the saphyr project; the name is historical. Transitive `granit-parser` 1.2.0 is a documented fork of `saphyr-parser` from the same owner (crates.io since 2026-05; ~3.1M downloads; not a git dependency). Single maintainer and youth are not Concern by themselves. Combined with the saphyr name/project mismatch, this is **Watch**. Do not replace the YAML stack in Stage 9. A similarly named `prek-serde-saphyr` exists on crates.io; this repository depends on `serde-saphyr`, not that package.
- `jsonc-parser` and `serde_json` both parse JSON-family input; `jsonc-parser` is required for JSONC (`bun.lock`). Not duplicate accidental parsers.
- `ureq` → `ring` introduces a C build (`cc`) and Windows target crates in the lockfile. Expected for rustls-on-ring; no OpenSSL/native-tls.
- Production CLI uses `load_generic_intelligence()` (uncached live fetch). The Stage 7 cache module is dormant and was not treated as a dependency-graph issue.

## Limitations

- This is a surface review of manifests, lockfiles, and shortlisted registry metadata. Package source code was not audited.
- Most transitive crates were not researched. `granit-parser`, `ring`, `rustls`, and `cc` were inspected only as far as they inform `serde-saphyr` and `ureq`.
- Absence of a surface warning is not proof of safety.
- Known-vulnerability coverage should come from GitHub/ecosystem advisory tooling, not from this document.
- Repository security-feature and Dependabot enablement cannot be established from committed files.
