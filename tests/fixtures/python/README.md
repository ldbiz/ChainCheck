# Python Stage 6–7 fixtures

Synthetic and captured layouts for Rust Python detector tests.
Provenance is recorded per subdirectory where fixtures are copied from real tools.

## Locks

Proven fixtures were generated on **2026-09-04** in an isolated temporary project
(`/tmp/chaincheck-stage7-fixtures`, not the ChainCheck tree). The pinned
dependency was `six==1.17.0`. Package managers were not executed against any
scanned ChainCheck test tree.

| Path | Producer / source | Captured | Proven marker |
|------|-------------------|----------|---------------|
| `locks/pylock/proven-1.0.toml` | uv 0.9.9 `uv export --format pylock.toml` (PEP 751 `lock-version` `"1.0"`) | 2026-09-04 | `lock-version = "1.0"` |
| `locks/uv/proven-v1.lock` | uv 0.9.9 `uv lock` | 2026-09-04 | `version = 1` (`revision = 3`) |
| `locks/poetry/proven-2.1.lock` | Poetry 2.4.2 `poetry lock` | 2026-09-04 | `[metadata].lock-version = "2.1"` |
| `locks/pipfile/proven-spec-6.lock` | pipenv 2026.8.0 `pipenv lock` | 2026-09-04 | `_meta.pipfile-spec = 6` |
| `locks/pdm/proven-4.5.1.lock` | PDM 2.29.0 `pdm lock` | 2026-09-04 | `[metadata].lock_version = "4.5.1"` |

PDM Proven is **exactly** `lock_version = "4.5.1"` from the captured fixture.
Other `4.x` values, including the previous synthetic `"4.5.0"`, are Degraded.

Degraded, unsupported, and malformed siblings remain synthetic and are not
fixture-gated as Proven:

- pylock `1.1` (degraded), `2.0` (unsupported), missing/`1.0.0`/`1.0.extra` (malformed), `proven-1.0-malformed-sibling.toml` (Proven marker with a broken sibling)
- uv `version = 2` (unsupported), `version = 1.9` float (malformed), `local-git.lock` (non-registry source)
- poetry other `2.x` (degraded), `1.x` (unsupported), `2.1.foo` (malformed)
- Pipfile.lock other `pipfile-spec` (unsupported)
- pdm `4.4.0` / `4.5.0` (degraded), major `3` (unsupported)

## Wheel cache

Wheel files under `wheel-cache/pip-wheels/` are empty placeholders; only filenames matter.
