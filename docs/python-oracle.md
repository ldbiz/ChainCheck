# Historical Python behavioural oracle

This document freezes the **externally meaningful** behaviour of the retired Python ChainCheck at:

**`8caa0f1934d8276cd7c56b546aa2579f5c96d1ce`**

That SHA is also recorded as `oracle_reference` in [`tests/cases.json`](../tests/cases.json). The Python implementation is no longer present or executable in this repository. Native ChainCheck is the sole supported implementation. This oracle is historical scan-semantics evidence, not a runtime.

Shared inputs live under [`tests/fixtures/shared/`](../tests/fixtures/shared/). Machine-readable cases are [`tests/cases.json`](../tests/cases.json). Native tests in [`tests/oracle_compat.rs`](../tests/oracle_compat.rs) consume the same fixtures and cases.

## How to use the corpus

- Paths in cases are relative to `tests/fixtures/shared/` and must stay under that root (no absolute paths, no `..` escape).
- Default malware intelligence is the top-level `intelligence` field in `cases.json`. Per-case or per-invocation `intelligence` overrides that default. Feed cases use `invocation.files` as the payload under test.
- `classification: compatibility` — `expected` is the semantic target the native implementation must preserve.
- `classification: intentional-change` — `python_expected` is the frozen Python result; `rust_direction` is what the native implementation must **not** copy.
- `classification: new-rust-capability` is reserved in this document only; there are no empty machine cases.

Normalized findings are compared as an **exact multiset** (order-insensitive; duplicates matter). Fields are severity, code, package, version, evidence class, wildcard, and campaign family. Extra or missing findings fail unless a case sets `allow_additional_findings`. Report prose is not an API.

`coverage` in a case is a listed-key map of detector name to `ran` / `partial` / `skipped`. Unlisted detectors are ignored so walk bookkeeping for unused artefact kinds is not frozen.

Package versions are opaque exact strings. The oracle does not assume a leading digit or apply semver/PEP 440. An installed identity fixture with version `release-alpha` is part of the corpus.

Package/version is taken from structured scanner state when a finding maps to exactly one `package_evidence` pair; otherwise from location/detail tokens.

## Compatibility requirements

Behaviour the native implementation is expected to preserve semantically.

### CLI and invocation

- Command name: `chaincheck`.
- Optional positional scan root.
- `--self-test` is a distinct invocation: not a malware scan; synthetic HIGH/CONFIRMED results do not describe the host; exit `1` means scanner/test failure.
- `ROOT + --self-test` is invalid and exits `64`.
- Unrecognised options exit `64`.
- A nonexistent scan root exits `3`.

### Environment

- `CHAINCHECK_REPORT_DIR` selects the report directory (otherwise `$HOME/chaincheck-<UTC timestamp>`).
- `CHAINCHECK_NO_PROGRESS=1` disables the terminal progress bar.
- `npm_config_cache` adds that cache’s `_cacache/index-v5` to npm cache inspection when the directory exists.

### Scan scope

Without an explicit root, the file walk includes `$HOME`, relevant npm global package locations, and still runs host-level npm cache/log and credential/network checks where applicable.

An explicit root:

- restricts the filesystem walk to that root;
- must not silently widen the walk to `$HOME` or unrelated global package trees;
- still allows the separately designed host-level checks to run.

### Reports

Externally meaningful concepts (exact prose is not required):

- `summary.txt`
- `findings.tsv` with columns `severity`, `category`, `location`, `detail`
- bounded console evidence listing (truncates after 10 evidence rows)
- privacy warning: reports contain local filesystem paths and should be reviewed before sharing

### Exit codes (normal scan)

- `0` — clean under available required intelligence
- `1` — MEDIUM/review evidence
- `2` — HIGH or CONFIRMED evidence
- `3` — scan could not start
- `4` — otherwise-clean scan where required generic malware intelligence is unavailable
- `64` — command-line usage error

Precedence: `2 → 1 → 4 → 0`. `--self-test` exit `1` is not MEDIUM malware evidence.

### Evidence semantics

Severity describes **strength of local evidence**, not how dangerous a malware family is.

Distinctions to preserve:

- dependency declaration vs resolution vs package download/cache presence vs installed package vs npm install-context
- exact campaign payload hash vs campaign indicator vs contextual information
- exposure/credential inventory (non-evidentiary)

Evidence classes used for package corroboration: `manifest`, `lockfile`, `npm-cache`, `npm-log`, `installed`. Host-local classes: `installed`, `npm-cache`, `npm-log`.

Corroboration policy:

1. package/version is malware-listed;
2. at least two independent evidence classes agree;
3. at least one class is host-local;
4. purely declarative evidence does not escalate;
5. equivalent direct HIGH evidence suppresses redundant corroborated HIGH.

A non-exact specifier must not be fabricated into an exact resolved version. Wildcard non-exact declarations must not enter the exact package/version corroboration map.

### Generic npm intelligence

Aikido npm malware feed, defensive ~50 MiB response limit, no persistent cache:

- valid `MALWARE` records (case-insensitive `reason`)
- exclude `TELEMETRY`, `PROTESTWARE`, unknown/non-MALWARE statuses
- exact package/version match and `version == "*"` wildcard
- unknown additional fields on a valid record are ignored
- malformed individual records ignored; invalid top-level or zero valid MALWARE records → unavailable/degraded
- oversized `Content-Length`, oversized body read, or malformed JSON at fetch → degraded
- otherwise-clean degraded intelligence exits `4`; finding exits `1`/`2` take precedence

### npm detectors

Representative shared cases cover installed `package.json` (HIGH), exact and wildcard declarations, package-lock v1/v3, `npm-shrinkwrap.json` **filename discovery during walk**, Yarn classic, pnpm v6/v9, text `bun.lock` token matching, cacache `index-v5` tarball URL evidence, install-context vs non-install npm logs, and corroboration combinations listed in `cases.json`.

Cache evidence is host-local and proves download/cache presence, not lifecycle execution.

### Campaign (ChainDrop/Shai-Hulud)

Known payload filenames; exact published or injected synthetic hash → CONFIRMED; payload content + preinstall context → HIGH; benign `setup.mjs` filename alone → INFO; `.vscode/tasks.json` / `.claude/settings.json`; strong config content → HIGH; contextual config → MEDIUM; NodeReal domain alone is contextual; campaign contract is strong; Git author email `claude@users.noreply.github.com` + exact subject `chore: update config` → HIGH; email-only → MEDIUM; display author name is not part of the HIGH match. Git fixtures remain dynamically generated.

Shared config artefacts are stored as `campaign/config/vscode-strong/tasks.json` and `campaign/config/claude-weak/settings.json` so the historical Python wheel packaging did not strip dotted directories. Content scanning does not require those directory names; walk filename discovery is covered by native tests that copy the artefacts into `.vscode` / `.claude` trees.

### Coverage

Partial coverage for oversized, unreadable/stat-failed, parse-failed, inaccessible, cache-inspection-capped, unsupported, or unavailable-feed situations. The semantic expectation is portable; the fault-injection mechanism need not match the retired Python tests.

## Intentional behaviour changes

Recorded at freeze. `intentional-change` cases in `cases.json` keep `python_expected` as historical Python output. Native tests assert `rust_direction`.

1. Parse failures move out of findings and into coverage (`INFO parse-error` in the frozen Python tree).
2. Unsupported formats move out of findings and into coverage (`INFO unsupported-lockfile` in the frozen Python tree, including binary `bun.lockb`).
3. Campaign payload hashing becomes size-bounded. The native library implements this at 10 MiB (`LIMIT_PAYLOAD`): oversized, unreadable, symlink, or non-regular payloads are `payload-file` Partial coverage and do not fall through to an unknown-hash finding. The frozen Python scanner was unbounded.
4. Packaged self-test is native and does not invoke pytest. The binary implements this as `chaincheck --self-test`.
5. Python environment discovery replaces the frozen Python `.venv` / `venv` / `.tox` pruning.
6. Generic malware intelligence state is per ecosystem rather than one global feed state.
7. PyPI package identities use PEP 503 normalisation.
8. Report organisation may differ while retaining the external concepts above.
9. A Stage 7 persistent generic-intelligence cache under `$XDG_CACHE_HOME/chaincheck/intelligence/` was a migration remnant. Stage 10 removed it. Production live-fetches npm and PyPI feeds on every scan, matching the frozen Python no-cache semantics. There is no persistent generic feed cache and no offline fallback.

## Native Python/PyPI scanning

Not part of the Python oracle freeze. The native scanner implements these independently; see `src/python/` and `tests/python_*.rs`:

- PyPI malware intelligence
- installed `.dist-info/METADATA`
- Python environment discovery
- Python manifests and lockfiles
- pip wheel-cache evidence
- independent npm/PyPI feed degradation

## Language-specific tests

Native tests under `tests/*.rs` cover permission/stat failure, oversized blobs, Git repo construction, HTTP/feed mocks, CLI/env wiring, progress TTY, report smoke, INFO payload wording, and Python/PyPI detector behaviour. The retired pytest suite is not present.
