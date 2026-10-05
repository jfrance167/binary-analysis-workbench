# Binary Analysis Workbench — approved implementation plan

Research date: October 5, 2026. Tier 3. All six stages/defaults approved October 5, 2026 ("okay, begin").
This document records the approved intended behavior. Actual implementation evidence, supported matrix and limitations are in STATE.md, README.md and docs/verification.md; a plan requirement alone is not a test claim.

## Problem and success criteria

Build a local learning and investigation tool that connects static binary evidence, function-level reverse engineering, and explained triage observations. A user selects an authorized file, identifies its format/architecture, examines evidence and relevant functions, follows references, and exports reproducible JSON and searchable offline HTML. Analysis never requires an account, cloud service, payment, or LLM.

Release acceptance requires all of the following:

1. Four included-source fixture builds cover native PE32/x86, PE32+/x64, ELF32/x86, and ELF64/x64, with symbol-bearing and stripped variants where applicable. Static fields match independently recorded expectations.
2. Real Ghidra integration produces instructions, discovered functions, cross-references, available control flow, and nonempty pseudocode for representative functions across that matrix. Selected addresses resolve or receive a precise error. No placeholder can satisfy this criterion.
3. Every observation references evidence and location, explains uncertainty and false positives, and distinguishes facts from interpretations and unavailable checks.
4. Malformed input, missing/failed/timed-out workers, injection, changing input, unsafe output paths, and resource caps produce bounded, explicit outcomes. Process cleanup is verified with harmless child-process fixtures.
5. A reproducible benign demonstration traverses all three capabilities and produces usable HTML and schema-valid JSON without executing the submitted fixture.

## Recommended stack

Build a thin orchestration application; adopt specialist components without forking initially. See [research.md](../research.md) for inspected sources and caveats.

| Component | Proposal | Reason / tradeoff |
|---|---|---|
| Core and CLI | CPython 3.13 x64; argparse, dataclasses, hashlib, math, json, html, pathlib, ipaddress, subprocess | Installed Python family; standard library fits these tasks. Package/release compatibility still needs verification. |
| PE parser | pefile, initially evaluate release 2024.8.26 | Detailed PE evidence; Python implementation is inspectable. Recent source improvements are not necessarily in the older release; test relevant edge cases before locking. |
| ELF parser | pyelftools, initially evaluate 0.33 | ELF headers, segments, symbols and dynamic dependencies; no external runtime dependencies. Bundled Construct has a separate MIT notice. |
| Reverse engineering | Official Ghidra 12.1.4 release + supported 64-bit JDK 21; small reviewed Java export adapter | One coherent function/reference/decompiler model. More installation weight than a disassembler alone; Java and native decompiler processes require containment. Recheck advisories before installation/locking. |
| Local signatures | Optional YARA-X 1.21.0 worker using reviewed Python bindings | Local pattern matching with offsets; separate process keeps optional feature failures explicit. Verify Windows wheel availability and exact API before committing. Rules are supplied explicitly, never fetched. |
| Reports | Locally bundled HTML/CSS/trusted search JavaScript; JSON Schema document | No CDN/server; evidence inserted only as inert text. Core is independent of rendering. |
| Tests and development | pytest, bounded Hypothesis tests, JSON Schema validator, Bandit and eligible CodeQL | Development dependencies justified by malformed-input, schema, and regression verification; pin only reviewed versions and hashes. |

Do not add Capstone initially: Ghidra already supplies required disassembly, function discovery and references. Do not implement a decompiler or complex PE/ELF parsing. Build only bounded format recognition, normalization and validation around maintained parsers. Do not use LIEF Extended or account-gated features.

Lock artifacts after compatibility/advisory checks. Verify canonical publisher/repository identity, artifact hashes, dependency closure and notices; record Ghidra/JDK archive versions and hashes separately from Python locks. Setup is an explicit online preparation step; analysis and report viewing work offline afterward. No automatic update/download behavior.

## Host, format and architecture matrix

Current environment observed through .NET: Windows build 10.0.26200, X64; python.exe points to Python313. No Ghidra, compiler or YARA executable was found on PATH in the bounded check. Their absence elsewhere was not established. The Java PATH points to an Oracle java8path shim; its version and other installed JDKs were not checked. WMI inventory was unavailable.

| Dimension | First-release acceptance target | Explicit limits |
|---|---|---|
| Host | Windows 11 x64, beginning with this build | No tested support yet. Ghidra upstream supports additional hosts; this application's Linux/macOS resource enforcement and packaging are deferred. |
| PE | Native EXE/DLL, PE32 and PE32+, x86/x64, little endian | Managed assemblies: PE metadata only, with managed-code decompilation unavailable. Drivers may expose metadata, but no dedicated driver-analysis acceptance claim. |
| ELF | ET_EXEC / ET_DYN, x86/x64, little endian, including PIE/shared libraries | ELF dependencies/imports are dynamic names and undefined symbols, not Windows DLL imports. Sectionless files use segments/dynamic data where recoverable. |
| Other inputs | Bounded hashes/strings and recognized header facts when reliable | Unsupported architecture/endianness clearly marked; no full parsing or RE claim. ELF ET_REL/core, Mach-O, archives, raw firmware and other formats are excluded from full support. |
| RE coverage | Four native format/architecture combinations above | Stripped names and boundaries remain inferred; optimized/obfuscated/packed code may be partial. |

## Architecture and data flow

```text
Authorized regular file
  -> guarded collection + controlled immutable snapshot + SHA-256
  -> bounded worker supervisor
       -> PE / ELF adapters -> normalized static evidence
       -> Ghidra adapter -> functions, instructions, references, CFG, pseudocode
       -> optional local rule adapter -> rule matches and locations
  -> validated versioned analysis model
  -> transparent heuristic rules referencing evidence IDs
  -> CLI investigation + JSON export + offline HTML
```

The controller owns limits, storage and output policy. Workers return only schema-validated bounded data. Evidence records have stable IDs, file offsets and lengths where known, typed RVA/VA/address-space fields, source component/version, and validity/uncertainty. Store 64-bit addresses as canonical hexadecimal strings in JSON to avoid JavaScript precision loss. Do not infer a file offset from an address lacking a file-backed mapping.

Static extraction covers content-based detection; headers/entry point; hashes/size/provenance; bounded ASCII and UTF-16LE strings; PE sections, permissions, imports/delayed imports, exports, resources, symbol availability, certificates and trailing data; ELF sections/segments, flags, defined/undefined symbols and DT_NEEDED entries. Preserve absent versus unavailable versus malformed fields.

Address conversion checks overflow, overlaps, range validity, zero-fill and file bounds. PE certificate directory values are file offsets, not RVAs. Treat validated certificate ranges separately from unexplained trailing data. ELF permissions/entry mapping derive from PT_LOAD segments; do not assume sections describe loaded memory. PIE addresses are linked addresses with no claimed runtime load base. Ordinary static imports do not prove reachable use.

Entropy is byte-frequency Shannon entropy in bits/byte: H = -sum(p * log2(p)), computed over the entire bounded file and each valid file-backed section range. Empty range = unavailable with a reason. Do not include virtual zero-fill as raw section bytes; label overlaps/invalid ranges. High entropy alone can reflect compressed resources or data; timestamps are untrusted metadata.

Indicator candidates retain original encoding/offset and extraction context. Validate IP syntax with ipaddress; domain and URL syntax are conservative candidates, not proof of communication. Render as plain text without automatic links, previews, DNS, WHOIS or network requests.

Proposed CLI verbs: doctor, analyze, functions, inspect, export. Inspect accepts a function ID or explicitly typed address, shows instructions/pseudocode and incoming/outgoing references, and follows string/import references. Report search covers static evidence, functions, references and findings. A report contains the function index and bounded selected function details; missing pseudocode explains selection limits or backend failure. Re-analysis for another function uses the same retained controlled snapshot only when retention was explicitly requested; otherwise require the original digest to match a new collection. No sample execution is involved.

JSON model separates schema version, stable analysis content, and variable run metadata. Record backend/configuration/ruleset hashes, truncation, timings, warnings, skipped checks and limit enforcement. Stable IDs are scoped to artifact hash and evidence location; no absolute private path in default report provenance. Proposed exit codes: 0 requested checks completed (even with findings); 2 invalid arguments; 3 unsupported input; 4 partial analysis; 5 collection/security-boundary failure; 6 required backend unavailable/failed. Findings never alone change exit code. A schema-valid diagnostic report may still be produced for partial/unsupported cases.

## Threat model and boundaries

Assets: original sample integrity, private evidence, host files/credentials, host availability, trusted tool configuration, and report consumers. Attackers can control sample bytes, names, extracted strings, malformed tables, resource sizes and misleading symbols. Backend output and rule files are also treated as untrusted data. A malicious process already running as the same Windows user is outside the complete protection claim; restrictive ACLs reduce races but are not a same-user security boundary.

| Threat | Likelihood / impact | Proposed controls and residual risk |
|---|---|---|
| Parser/backend exploit or resource exhaustion | Plausible / high | Patched pinned components, allowlisted PE/ELF loaders and analyzer settings, bounded workers. Genuinely hostile samples require a disposable offline VM; no subprocess, venv or ordinary container is claimed to contain compromise. |
| Input changes or redirection | Plausible / high for evidence integrity | Open regular local file with a Windows handle that denies write/delete sharing; reject devices, pipes, UNC paths and reparse points. Copy under caps into a controlled root, hash those exact bytes, hold snapshot read-only through all workers. Record collection limitations and fail if stability cannot be established. |
| Output overwrite or reparse race | Plausible / high | Fresh per-run directory, restrictive ACL, trusted handles/final paths, reject reparse traversal, exclusive file creation, no force overwrite; verify final destination at commit. Simple resolve/check alone is insufficient. |
| Shell/tool/configuration injection | Plausible / high | Explicit trusted executable paths and argv arrays; no user-selected scripts, shell command strings, backend plugins, inherited Ghidra projects or sample-driven tool paths. Direct JVM launch from inspected vendor recipe must pass an early spike; never interpolate a filename into a .bat command. |
| Child-process escape or timeout hang | Plausible / high availability | Create workers suspended, assign to Windows Job Object before resuming; deny breakaway, enforce active-process/commit limits, terminate job on deadline/close and verify child cleanup. JVM heap caps alone are insufficient. |
| Evidence leaks, uploads or auxiliary reads | Plausible / high privacy | Offline backend profile; no network indicator access, server projects, external library/debug-symbol fetching, remote workers, telemetry, automatic rules or reports. pyelftools receives a controlled stream without an external DWARF loader. Treat backend logs as private; don't echo raw logs. |
| Terminal/HTML injection | Plausible / medium-high | Escape terminal controls; HTML text-node insertion/escaping, fixed trusted assets and restrictive CSP; no sample content in executable script contexts, HTML attributes or clickable indicator URLs. Treat exported report evidence as private data. |
| Misleading triage/decompilation | Likely / medium-high | Facts separate from heuristic interpretations, provenance and uncertain mappings, negative fixtures, disassembly/reference checks. No malware probability, safety verdict or original-source recovery claim. |

Storage is consequential: the development workspace is under OneDrive. Private samples, snapshots, Ghidra projects, logs and private reports must live in a separately selected nonsynchronized local directory, proposed under LOCALAPPDATA/BinaryWorkbench. Only harmless fixtures and reviewed example reports enter the portfolio workspace. Genuine malware is not acquired or analyzed in this task. The VM procedure disables network, shared folders, clipboard and host mounts for hostile analysis; moving artifacts remains a deliberate user operation.

## Initial limits to implement and test

These are conservative starting policies, not performance measurements. Changes are recorded in provenance.

| Resource | Proposed default | Enforcement / gap |
|---|---|---|
| Input | 64 MiB, one regular file/run | Handle-based bounded collection; reject excess before parsing. |
| Static worker | 30 s, 1 GiB committed memory, 2 active processes | Controller deadline + Job Object memory/process limits. |
| RE worker | 180 s overall, 15 s/function, 2 GiB Java heap, 4 GiB job commit, 4 active processes | Ghidra timeouts plus independent supervisor; Java/native startup verified under caps. |
| Signature worker | 15 s, 1 GiB commit, 2 processes; rules input 4 MiB | Explicit trusted rules root, bounded includes/compilation/matches; supervisor covers reading and compilation too. |
| Strings | Minimum 4 characters, max 4,096 characters/string, 20,000 retained records, 8 MiB retained text | Streaming extraction; record suppressed/truncated counts and policy. UTF-16LE alignment handled explicitly. |
| Tables/RE data | 50,000 records/category, 20 selected decompilations, 10,000 instructions/function, 100,000 references total | Validate before iteration where possible; cap adapter serialization; limits do not make parser allocations safe. |
| Output | 32 MiB backend payload, 16 MiB JSON, 24 MiB HTML; 1 MiB captured diagnostics/worker | Bounded writes/readers and overflow state; no silent truncation. Backend database/temp budget proposed 256 MiB with monitor. |

Job commit limits are not identical to resident-memory limits. Disk monitoring has scheduling races and cannot guarantee a hard disk quota; use a bounded VM volume for hostile input. Likewise application configuration alone does not guarantee network isolation after parser compromise; the offline VM provides that boundary. If mandatory process/memory/path controls cannot be established, fail before invoking risky parsers/RE. Doctor reports enforced versus advisory controls honestly.

## Findings and signatures

Each finding includes stable rule ID/version, explanation, evidence IDs and typed locations, investigation priority, uncertainty and false-positive notes. Initial rules: writable+executable sections/segments; suspicious import combinations; possible packing with multiple supporting observations; invalid/unusual entry mapping; embedded indicators; supplied local-rule matches. Do not make a scalar score in v1.

High entropy plus few imports may suggest packing, but compressed benign resources and small static programs are counterexamples. Import combinations do not prove execution; valid entry points can be thunks. Rule matches identify patterns, not necessarily families or behavior. Signature findings include namespace/rule ID, rule-file hash/license, pattern offsets/lengths and bounded match context. Rules and includes cannot read arbitrary paths or cause network fetches. No findings means inconclusive; a disabled/missing engine is an unavailable check.

## Stages and verification

Detailed acceptance tasks and dependencies are in [todo.md](todo.md). Approval may cover all stages or selected stages. Routine verification continues within approved scope; a material change in scope/security/data exposure requires Jake's decision.

1. Research, architecture and approval: this plan and source review; after approval, prove safe Windows process launch and a minimal real decompile on a benign fixture early. Failure revises the plan before extensive feature work.
2. Complete PE static slice: controlled collection, evidence model, full planned PE fields, mappings, strings/entropy/indicators and useful CLI output; security boundaries accompany it.
3. ELF + reports: complete ELF adapter and searchable inert HTML plus versioned JSON. Validate segment mappings, PIE, stripped/sectionless inputs and privacy.
4. Working RE integration: expand the early spike into function discovery, selection, instructions, pseudocode, xrefs and CFG; prove the four-fixture matrix and honest partial states.
5. Explained triage: evidence-linked heuristics and optional local signatures with positive/negative fixtures and rule provenance.
6. Hardening and portfolio demonstration: targeted property/fuzz checks, cleanup and limit verification, documentation/locks/notices, verified full benign walkthrough and reviewed example exports.

Compile fixtures from included harmless C/assembly/resource source after toolchain review. Building trusted included source is permitted by approved implementation; submitted analysis samples are never executed. Use deterministic compiler flags where supported and record compiler versions, hashes and linker maps. Compare static headers/symbols/imports and addresses with independent llvm-readobj/llvm-objdump/readelf outputs and handcrafted expectations; decompiler strings need not match across versions. Test instruction bytes/addresses, calls, branches, returned constants and references rather than exact pseudocode formatting. Compiler optimization can change expected assembly; source shape alone is not the oracle.

Security cases include truncated/overlapping tables, excessive counts, malformed unwind/resource/DWARF data within safe lab scope, Unicode paths, terminal/HTML payloads, symlink/reparse races, changing source, worker crash/hang/grandchildren, unsupported architectures and omitted checks. Use bounded property testing of address mapping/extraction/controller validation; no blind use of upstream malware test corpora. Negative fixtures include compressed resources, benign import combinations and legitimate certificate/trailing-data layouts.

Final documentation covers setup, CLI/exit states, JSON schema evolution, platform/feature matrix, limits and enforcement gaps, privacy/isolation, attribution/license, AI assistance, troubleshooting and exact recorded verification. Add useful STATE/DECISIONS/LEARNING updates at milestones. Apply the owned-repository security baseline when repo creation/completion is authorized; no publication, push, public release or merge is authorized by this planning request.

## Decisions requiring Jake

Jake approved all six stages/defaults with "okay, begin" on October 5, 2026. Python workbench + Ghidra + optional YARA-X, Windows x64, MIT original code and private nonsynchronized runtime storage are the authorized scope. No live hostile-sample acquisition/execution, publication or merge is authorized. A suitable VM remains required for genuinely hostile inputs; the included source-built benign demonstration did not require one.

No claim of parser safety, completed implementation, passing product tests or measured performance is made by this plan.
