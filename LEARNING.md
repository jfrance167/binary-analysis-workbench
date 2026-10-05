# Learning notes

- File offset, PE RVA, linked VA and runtime VA are different coordinates. ELF PIE lacks a known runtime base during static analysis; PE certificate directories are an important file-offset exception.
- Specialist parsers and decompilers process hostile input. A Python environment or subprocess isolates neither arbitrary file access nor parser compromise; resource controls and a VM solve different problems.
- Decompiled code approximates machine behavior. Symbols, inferred names and function boundaries need separate provenance; check consequential conclusions against instructions and references.
- Backend release requirements can differ from development README requirements: Ghidra 12.1.4 uses JDK 21 while master currently requests JDK 25.
- A dependency's test source/CI matrix is evidence of engineering practices, not proof this integration passes. Independent fixture expectations remain necessary.
- A local model draft can confidently suggest the wrong test surface or nonexistent workflow. Retain raw drafts, inspect completeness and verify APIs before using them.
- High entropy, imports and rule matches provide investigation leads; no findings is inconclusive. Avoid turning a heuristic into a malware probability.
- Windows packaged apps can redirect AppData without a reparse point. Canonicalize after rejecting reparse paths, then compare the physical opened handle path; do not simply remove the integrity check.
- A tolerant parser accepting truncated PE headers does not establish completeness. Independently compare declared header/table sizes with available bytes and preserve partial status.
- Ghidra analyzer names/options must be verified from the actual pinned backend. `Reference` is singular, and disabling every suboption can remove legitimate string/pointer references while calls still appear.
- Worker limits do not bound controller algorithms. Mapping and evidence joins need indexed spans/lookups; a full regions/strings scan per reference can defeat availability safeguards.
- UTF-16 decoded character indices are not byte offsets when surrogate pairs occur. Track encoded gaps at both alignments; the current extractor deliberately excludes non-BMP wide evidence and describes that limit.
- A native match cap needs an explicit possible-truncation signal even if the scanner returns normally. Rule-only conditions need unknown locations, not invented offsets.
- Decompiled endpoints may span gaps. Address inspection should use actual retained instruction ranges; optimized branches can become conditional moves and one CFG block.
- Independent header/byte expectations, bounded property campaigns and real backend failures complement one another. A source inspection or schema pass cannot substitute for genuine disassembly/decompilation.
