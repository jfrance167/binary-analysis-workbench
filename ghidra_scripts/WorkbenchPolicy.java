// Original script: restrict analyzers before processing hostile data.
import ghidra.app.script.GhidraScript;
import ghidra.framework.options.Options;
import java.util.Set;

public class WorkbenchPolicy extends GhidraScript {
    public void run() throws Exception {
        Options options = currentProgram.getOptions("Analyzers");
        Set<String> allowed = Set.of("Disassemble Entry Points", "Function Start Search",
            "Function ID", "Reference", "Data Reference", "Subroutine References",
            "ASCII Strings", "Stack", "Create Address Tables", "Shared Return Calls",
            "Scalar Operand References", "x86 Constant Reference Analyzer",
            "Reference.Ascii String References", "Reference.Unicode String References",
            "Reference.References to Pointers", "Reference.Respect Execute Flag",
            "Data Reference.Ascii String References", "Data Reference.Unicode String References",
            "Data Reference.References to Pointers", "Data Reference.Respect Execute Flag",
            "Disassemble Entry Points.Respect Execute Flag",
            "x86 Constant Reference Analyzer.Stored Value Pointer analysis",
            "x86 Constant Reference Analyzer.Function parameter/return Pointer analysis",
            "x86 Constant Reference Analyzer.Create Data from pointer");
        for (String name : options.getOptionNames()) {
            Object value = options.getObject(name, null);
            if (value instanceof Boolean) options.setBoolean(name, allowed.contains(name));
        }
    }
}
