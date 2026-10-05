// Original bounded export adapter. Pseudocode approximates machine code.
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.framework.Application;
import ghidra.framework.options.Options;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.block.*;
import com.google.gson.Gson;
import java.util.*;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;

public class WorkbenchExport extends GhidraScript {
    Map<String,Object> address(Address a) {
        return Map.of("space", a.getAddressSpace().getName(), "value", "0x" + Long.toUnsignedString(a.getOffset(),16));
    }
    public void run() throws Exception {
        String[] args = getScriptArgs();
        String selection = args.length > 1 ? args[1] : "";
        List<Object> functions = new ArrayList<>();
        List<Object> details = new ArrayList<>();
        List<String> warnings = new ArrayList<>();
        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);
        int totalReferences = 0, totalEdges = 0;
        try {
            FunctionIterator iterator = currentProgram.getFunctionManager().getFunctions(true);
            while (iterator.hasNext() && functions.size() < 50000) {
                monitor.checkCancelled();
                Function function = iterator.next();
                Map<String,Object> row = new LinkedHashMap<>();
                row.put("name", function.getName());
                row.put("address", address(function.getEntryPoint()));
                row.put("end", address(function.getBody().getMaxAddress()));
                row.put("name_source", function.getSymbol().getSource().toString());
                row.put("boundary_source", "ghidra_analysis");
                functions.add(row);
                boolean selected = selection.isEmpty() ? details.size() < 3 :
                    Arrays.asList(selection.split(",")).contains(function.getName());
                if (selection.startsWith("0x")) {
                    Address target = toAddr(selection);
                    selected = function.getBody().contains(target);
                }
                if (!selected || details.size() >= 20) continue;
                Map<String,Object> detail = new LinkedHashMap<>(row);
                List<Object> instructions = new ArrayList<>(), references = new ArrayList<>(), blocks = new ArrayList<>();
                InstructionIterator listing = currentProgram.getListing().getInstructions(function.getBody(), true);
                while (listing.hasNext() && instructions.size() < 10000) {
                    Instruction instruction = listing.next();
                    StringBuilder bytes = new StringBuilder();
                    for (byte b : instruction.getBytes()) bytes.append(String.format("%02x", b & 255));
                    instructions.add(Map.of("address", address(instruction.getAddress()), "bytes", bytes.toString(), "text", instruction.toString()));
                    Reference[] outgoing = currentProgram.getReferenceManager().getReferencesFrom(instruction.getAddress());
                    for (Reference reference : outgoing) {
                        if (totalReferences++ >= 100000) break;
                        Symbol symbol = currentProgram.getSymbolTable().getPrimarySymbol(reference.getToAddress());
                        references.add(Map.of("from", address(reference.getFromAddress()), "to", address(reference.getToAddress()),
                            "type", reference.getReferenceType().toString(), "symbol", symbol == null ? "" : symbol.getName(true)));
                    }
                }
                ReferenceIterator incoming = currentProgram.getReferenceManager().getReferencesTo(function.getEntryPoint());
                List<Object> callers = new ArrayList<>();
                while(incoming.hasNext() && totalReferences++ < 100000) {
                    Reference reference = incoming.next();
                    callers.add(Map.of("from", address(reference.getFromAddress()), "type", reference.getReferenceType().toString()));
                }
                CodeBlockIterator blockIterator = new BasicBlockModel(currentProgram).getCodeBlocksContaining(function.getBody(), monitor);
                while(blockIterator.hasNext() && blocks.size() < 10000 && totalEdges < 100000) {
                    CodeBlock block = blockIterator.next();
                    List<Object> edges = new ArrayList<>();
                    CodeBlockReferenceIterator destinations = block.getDestinations(monitor);
                    while(destinations.hasNext() && edges.size() < 1000 && totalEdges < 100000) {
                        CodeBlockReference ref = destinations.next();
                        edges.add(Map.of("to", address(ref.getDestinationAddress()), "type", ref.getFlowType().toString()));
                        totalEdges++;
                    }
                    if(destinations.hasNext()) warnings.add("cfg_edges_truncated");
                    blocks.add(Map.of("start", address(block.getFirstStartAddress()), "end", address(block.getMaxAddress()), "edges", edges));
                }
                if(blockIterator.hasNext()) warnings.add("cfg_blocks_truncated");
                DecompileResults result = decompiler.decompileFunction(function, 15, monitor);
                detail.put("instructions", instructions);
                detail.put("references", references);
                detail.put("callers", callers);
                detail.put("blocks", blocks);
                String pseudocode = result.decompileCompleted() && result.getDecompiledFunction()!=null ? result.getDecompiledFunction().getC() : "";
                if(pseudocode.length() > 1024*1024) { pseudocode = pseudocode.substring(0,1024*1024); warnings.add("pseudocode_truncated"); }
                detail.put("pseudocode", pseudocode);
                detail.put("decompilation_status", result.decompileCompleted() ? "complete" : "unavailable");
                detail.put("decompilation_error", result.decompileCompleted() ? "" : result.getErrorMessage());
                detail.put("instructions_truncated", listing.hasNext());
                details.add(detail);
            }
            if(iterator.hasNext()) warnings.add("function_index_truncated");
            if(totalReferences >= 100000) warnings.add("references_truncated");
            Map<String,Object> output = new LinkedHashMap<>();
            output.put("backend", "ghidra");
            output.put("version", Application.getApplicationVersion());
            output.put("language", currentProgram.getLanguageID().toString());
            Options analyzerOptions = currentProgram.getOptions("Analyzers");
            Map<String,Boolean> analyzers = new TreeMap<>();
            for(String name : analyzerOptions.getOptionNames()) {
                Object value = analyzerOptions.getObject(name,null);
                if(value instanceof Boolean) analyzers.put(name,(Boolean)value);
            }
            output.put("analyzers",analyzers);
            output.put("sha256", currentProgram.getExecutableSHA256());
            output.put("functions", functions);
            output.put("details", details);
            output.put("warnings", new ArrayList<>(new LinkedHashSet<>(warnings)));
            byte[] serialized = new Gson().toJson(output).getBytes(StandardCharsets.UTF_8);
            if(serialized.length > 32*1024*1024) throw new IllegalStateException("backend_output_limit");
            Files.write(Path.of(args[0]), serialized, StandardOpenOption.CREATE_NEW);
        } finally { decompiler.dispose(); }
    }
}
