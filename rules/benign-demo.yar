// Original learning rule. A match identifies our harmless fixture, not malware.
rule BinaryWorkbenchBenignMarker {
    strings:
        $marker = "BINARY_WORKBENCH_BENIGN_FIXTURE" ascii
    condition:
        $marker
}
