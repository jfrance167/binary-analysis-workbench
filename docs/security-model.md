# Security model and enforcement

The assets are original-file integrity, private analysis evidence, host files/credentials, host availability, trusted tool configuration and report consumers. Sample bytes/names, rules, extracted text and backend output can be attacker controlled. Malformed tables, enormous allocations, misleading symbols, path redirection, terminal/HTML payloads and parser exploits are relevant threats.

## Boundaries

| Boundary | Implemented behavior | Residual limit |
|---|---|---|
| Collection | Local regular disk files; reject UNC/device/ADS/reparse paths; canonicalized physical path checked against opened handle; deny write/delete sharing; hash copied bytes; locked snapshot held through all workers | A process already acting as the same user/admin is outside the complete protection claim; antivirus/filesystem behavior can make collection unavailable |
| Runtime ownership | Fresh UUID directory with protected owner/SYSTEM DACL installed at creation; existing roots are not re-permissioned | Host compromise and other sync products are not controlled; existing roots/ancestors must be privately owned and trusted, not attacker-writable; choose private nonsynchronized storage |
| Worker startup | Explicit .exe and argv, no shell; suspended start, mandatory Job Object limits/assignment, explicit inherited handles, minimal environment | Explicit tool configuration must be trusted; this is not token/network/filesystem isolation |
| Lifetime | Kill job on timeout and normal parent exit, wait for parent and verify zero active job processes | Mandatory setup/cleanup failure stops the operation; OS failures are reported rather than bypassed |
| Memory/processes | Job committed-memory and active-process caps; no breakaway; JVM heap cap too | Commit is not resident memory; memory-limit failures may appear as generic worker failure |
| Disk | Sampled worker-directory total at 250 ms intervals; output/log caps checked during/after completion | Brief overshoot is possible; a bounded VM disk is required for hostile inputs |
| Parser scope | pefile fast-load selected directories; pyelftools on a byte stream without external DWARF loader; bounded normalized tables | Specialist parsers may allocate before adapters apply caps; workers contain resource failures, not exploitation |
| Ghidra scope | Only complete native x86/x64 PE/ELF evidence; fixed 12.1.4 profile; allowlisted analyzers; no PDB/external-symbol analyzers; private temporary project and deleteProject | Function discovery, indirect calls and references can remain incomplete; decompiler is native risky code |
| Rules | Explicit local UTF-8 rules snapshot, includes disabled, compiler/scan supervised, per-pattern and total-match caps | Local rules can be expensive or misleading; modules parse hostile input inside the worker |
| Rendering | HTML escaping, fixed hash-authorized JS/CSS, CSP default/connect/base/form deny, inert evidence; terminal JSON escaping | Browser/tool vulnerabilities remain external; very large valid reports can hit output caps |
| Publication | Normal reports remain private; only reviewed source-built benign examples go into prospective tracked files | Sharing/exporting evidence is a deliberate user decision; no automated upload exists |

The application has no telemetry, network-indicator requests, cloud scanner, rule updater, dynamic debugger, emulator, unpacker or sample execution feature. The headless Java environment excludes inherited JAVA_TOOL_OPTIONS/PYTHONPATH and disables external XML DTD/schema access. Configuration does not enforce OS network isolation after compromise. Use an offline disposable VM with shared folders/clipboard/host mounts disabled for genuinely hostile analysis. Never regard a venv or subprocess as that VM boundary.

## Approved limits

Input: 64 MiB. Static parser: 30 seconds, 1 GiB job commit, two active processes. Signature worker: 15 seconds, 1 GiB, two processes, 4 MiB rule input, ten-second engine scan deadline, 100 matches/pattern, 10,000 retained matches. Reaching a pattern cap is reported as possible truncation.

Ghidra: 180-second default/maximum supervisor deadline; 90-second analysis deadline; 15 seconds per selected function; 2 GiB JVM heap; 4 GiB job commit; four processes; two requested analysis CPU threads. A wall deadline limits total work; no complete CPU quota is claimed. Up to 50,000 indexed functions and 20 selected details, 10,000 instructions/function, 100,000 references/callers total, 100,000 CFG edges total, 1 MiB pseudocode/function.

Common strings: minimum four characters, up to 20,000 records, 4,096 characters/run, 8 MiB retained raw text. Additional wide BMP Unicode requires a NUL terminator; non-BMP/surrogate-pair strings are excluded. Offsets and encodings are explicit. Binary bytes can form accidental printable runs.

Output: 32 MiB backend JSON, 16 MiB final JSON, 24 MiB final HTML, 1 MiB each worker stdout/stderr. Sampled total worker disk budget: 256 MiB. Reports are exclusively created; oversized reports fail without claiming completion. Private raw worker artifacts can remain for lab diagnosis.

## Interpreting evidence

PE RVA, linked VA and file offset are separate coordinates. PE certificates use file offsets. ELF PIE has no known runtime load base during static analysis. Mapping accepts only unique valid file-backed regions; overlaps/zero-fill return unknown. Ghidra references preserve their address space; stack/external spaces are not treated as file offsets. Unknown joins remain unknown. Inferred function boundaries and pseudocode are analysis results, not recovered original source.

Entropy is Shannon byte entropy over the complete file/validated raw region, measured in bits/byte (0–8); empty regions use null. High entropy can mean compression/encryption/assets and does not prove packing. Timestamps are forgeable and build-dependent. An unsigned or unverified certificate directory is not a trust verdict. Imports do not prove calls occurred. Candidate URLs/domains/IPs may be documentation or decoys. No findings is inconclusive.

Jake's manual review of these consequential untrusted-input boundaries remains necessary before any separately authorized merge/deployment. The ECC checklist and local tests do not constitute an independent audit or comprehensive fuzzing campaign.

