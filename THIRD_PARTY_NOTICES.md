# Third-party components

Original orchestration, adapters, fixture source, rule, report presentation and tests use the project MIT license. They integrate the following components without copying their implementations. Tool archives and environments are excluded from prospective tracked files. Redistributing a dependency/tool bundle requires preserving that bundle's own licenses and third-party notices; this file is not a replacement for them.

| Component | Reviewed version | License / source |
|---|---|---|
| pefile | 2024.8.26 | [MIT](https://github.com/erocarrera/pefile/blob/master/LICENSE) |
| pyelftools | 0.33 | [Public domain portions and MIT fallback, including construct](https://github.com/eliben/pyelftools/blob/main/LICENSE) |
| YARA-X Python/native engine | 1.21.0 | [BSD-3-Clause](https://github.com/VirusTotal/yara-x/blob/main/LICENSE) plus bundled component notices |
| Ghidra | 12.1.4 | [Apache-2.0](https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.4_build/LICENSE) and extensive third-party notices in its official distribution |
| Eclipse Temurin/OpenJDK | 21.0.12.1+1 | [GPLv2 with Classpath Exception](https://github.com/adoptium/temurin21-binaries); preserve distribution legal files |
| Zig compiler | 0.14.1 | [MIT](https://github.com/ziglang/zig/blob/0.14.1/LICENSE) and bundled LLVM/Clang/libc notices |
| pytest / Hypothesis / jsonschema | locked test versions | MIT / MPL-2.0 / MIT respectively; development-only |
| Bandit | installed 1.9.4 | Apache-2.0; development/CI-only |

The Ghidra Java scripts use public APIs and the distribution's bundled Gson. No Ghidra decompiler code is copied. COFF symbol normalization uses the documented fixed-size record format and skips auxiliary records; complex PE parsing remains in pefile. Research/source links and evaluated alternatives are in [research.md](research.md).

AI assistance: Codex assisted with research, implementation, tests, review and documentation. Two bounded Ollama drafting attempts were retained privately and reviewed; weak/incomplete suggestions were not accepted as implementation. No sample contents were sent to a drafting worker, and no remote drafting inference was performed. ECC review was a self-review by the implementing agent, not an independent audit.
