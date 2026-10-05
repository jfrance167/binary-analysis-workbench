# Setup and reproducible benign fixtures

Use Windows x64 and trusted x64 CPython 3.13. Tested here: Python 3.13.7. Work from the project directory; `scripts/dev.py` runs the source tree directly, avoiding an unpinned build-environment download. The conventional package entry point is also declared in pyproject.toml; editable/package installation itself was not the verified execution path.

## Python environment

```powershell
python -m venv .venv
.venv/Scripts/python.exe -m pip install --require-hashes -r requirements.lock
```

All three runtime wheel digests were independently compared with canonical official PyPI release metadata before installation. `requirements-core.lock` contains only pefile/pyelftools, and `requirements-signatures.lock` adds YARA-X. Install from a prepared wheelhouse with `--no-index --find-links .tools/wheels` for offline setup. Do not substitute an arbitrary mirror/artifact or drop hashes to get an install to pass.

Development tests use:

```powershell
.venv/Scripts/python.exe -m pip install --require-hashes --no-deps `
  -r requirements-test.lock -r requirements-test-local.lock
```

`requirements-test.lock` has independently publisher-verified dependencies. The two test-only packages in `requirements-test-local.lock` (colorama 0.4.6, Pygments 2.21.0) were downloaded from PyPI, then compared byte for byte—including package source, entry points, metadata and licenses—with their already installed local distributions because official metadata transport failed. Their lock digests preserve the reviewed bytes; **that local-equivalence check is not independent publisher-digest verification**. The helper is `scripts/reuse_test_wheels.py`; it requires matching existing distributions and does not download/execute a replacement. This distinction does not apply to runtime parsers or YARA-X.

## Ghidra/JDK/Zig

Fixed official artifacts and independently verified SHA-256 values are in `toolchain.lock.json`:

- [Ghidra 12.1.4 Windows-inclusive distribution](https://github.com/NationalSecurityAgency/ghidra/releases/tag/Ghidra_12.1.4_build).
- [Temurin/OpenJDK 21.0.12.1+1 Windows x64](https://github.com/adoptium/temurin21-binaries/releases/tag/jdk-21.0.12.1%2B1).
- [Zig 0.14.1 Windows x64](https://ziglang.org/download/0.14.1/).

The release-supported JDK requirement is 21, even though Ghidra's development branch requests a newer JDK. Archives are large; tool setup is separate from sample analysis. No sample contents are downloaded or sent anywhere by this helper.

```powershell
python scripts/setup_tools.py --download
.venv/Scripts/python.exe scripts/dev.py doctor --tools-config .tools/paths.json
```

The setup helper uses the fixed publisher URLs, refuses a hash mismatch and verifies every archive before extraction. It rejects absolute/traversal/link paths and an expanded total above 3 GiB. Existing extracted tool directories are refused; it does not overwrite a prepared toolchain. If publisher connectivity fails, preserve the failed artifact, obtain the exact archive through the official source and independently verify its hash, then run the helper without `--download`. No automatic retry, upgrade or alternate-source fallback occurs. Existing project tools are already prepared; do not rerun extraction over them.

Alternatively configure independently reviewed external installations through a trusted JSON file with `ghidra` and `java` absolute paths. Only Ghidra 12.1.4 is accepted by this adapter; changing that pin requires source/advisory review and fixture verification. Runtime launches java.exe directly, never analyzeHeadless.bat. Preserve the official distributions' licenses/notices.

## Fixtures and demonstration

Zig is only needed to compile included harmless source. Compiler outputs must be outside the synced project; choose fresh nonsynchronized directories. Never run the compiled executables/shared libraries.

```powershell
.venv/Scripts/python.exe scripts/build_fixtures.py "$env:LOCALAPPDATA/BinaryWorkbench/my-fixtures"
.venv/Scripts/python.exe scripts/build_variants.py "$env:LOCALAPPDATA/BinaryWorkbench/my-variants"
.venv/Scripts/python.exe scripts/verify_integration.py "$env:LOCALAPPDATA/BinaryWorkbench/my-fixtures"
.venv/Scripts/python.exe scripts/verify_failure_paths.py "$env:LOCALAPPDATA/BinaryWorkbench/my-fixtures" "$env:LOCALAPPDATA/BinaryWorkbench/my-variants"
$env:WB_VARIANTS="$env:LOCALAPPDATA/BinaryWorkbench/my-variants"
.venv/Scripts/python.exe -m pytest -q --basetemp "$env:LOCALAPPDATA/BinaryWorkbench/my-tests"
```

The main fixtures target PE32/64 and ELF32/64 with three noinline functions, a marker, URL, wide text and an inert HTML/control-character payload. Variants add PE imports/resources, a benign ELF dependency, PIE, stripped symbols and optimized instructions. Build manifests record target/commands/hashes and that outputs were never executed. Native debug paths are removed/remapped from the public-demo builds. PE linker timestamps, compiler versions and backend versions can change hashes/output; byte-for-byte rebuild determinism is not claimed.

`scripts/prepare_demo.py` exports only a checked source-built benign fixture summary to a fresh reviewed example directory. It refuses existing output and checks for machine-private path text. Its explicit `--refresh` mode verifies the same benign sample, archives existing curated example files with byte equality to private fixture history, then refreshes those named example artifacts. It is not a general public exporter. Normal sample analysis/export always stays in newly protected private runtime directories.

## Troubleshooting

| Symptom | Next step |
|---|---|
| `unavailable` RE | Inventory trusted tool paths, Ghidra version and JDK; supply `--tools-config` |
| `timeout` | Narrow selected functions or inspect static evidence; do not remove containment |
| `partial` static PE | Review warnings, declared versus available headers/ranges and truncation |
| Collection failure | Use a regular local non-reparse file, close writers, check size/permissions; originals remain unchanged |
| AppData path differs | The desktop app may redirect storage; use the physical path printed by the CLI |
| Existing output/directory | Choose a new run/build directory; no automatic deletion/overwrite |
| Rule failure | Check UTF-8 syntax and engine presence; include directives are intentionally disabled |
| Missing selected name | Use `functions`, retain symbol decoration or choose an address; stripped names are inferred |
| Huge report rejected | Narrow RE selection and review extraction limits; private worker artifacts may exist, but no successful report is claimed |
| Browser automation rejects file URL | The installed test CLI disallows that protocol; use the documented benign loopback-only test, then disconnect its browser network |

The tested CLI never exposes raw exception text, so diagnose private backend logs inside the lab rather than posting them publicly. A parser/decompiler failure does not establish maliciousness.

For workflow/schema/credential-pattern hygiene, scripts/verify_project.py uses the pinned test validator and reuses an already installed base-interpreter PyYAML (as used by local Bandit); it performs no dependency download. It reports unavailable tooling as failure rather than a pass. CI YAML syntax/pins are local preparation checks, not hosted execution.

