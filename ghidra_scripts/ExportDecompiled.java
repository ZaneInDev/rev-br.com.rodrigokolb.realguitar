//@category Export
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.util.task.ConsoleTaskMonitor;
import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;

public class ExportDecompiled extends GhidraScript {

    @Override
    protected void run() throws Exception {
        String programName = currentProgram.getName();
        String execPath = currentProgram.getExecutablePath();

        String arch = "native";
        if (execPath != null) {
            File f = new File(execPath);
            File parent = f.getParentFile();
            if (parent != null && parent.getName() != null
                    && !parent.getName().isEmpty() && !parent.getName().equals("lib")) {
                arch = parent.getName();
            }
        }

        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);
        ConsoleTaskMonitor localMonitor = new ConsoleTaskMonitor();

        File outDir = new File("decoded-output/lib");
        if (!outDir.exists()) {
            outDir.mkdirs();
        }

        String outFilename = arch + "_" + programName + "_decompiled.c";
        File outFile = new File(outDir, outFilename);
        println("Writing full Ghidra pseudo-C output to: " + outFile.getAbsolutePath());

        PrintWriter writer = null;
        try {
            writer = new PrintWriter(new FileWriter(outFile));
            writer.write("// Ghidra Full Decompilation Summary for " + programName + " (" + arch + ")\n\n");
            writer.flush();

            FunctionManager fm = currentProgram.getFunctionManager();
            int count = 0;
            int skipped = 0;

            for (Function func : fm.getFunctions(true)) {
                if (func.isThunk() || func.isExternal()) {
                    skipped++;
                    continue;
                }

                writer.write("/* Function: " + func.getName() + " @ " + func.getEntryPoint() + " */\n");

                DecompileResults res = decompiler.decompileFunction(func, 60, localMonitor);
                if (res != null && res.getDecompiledFunction() != null) {
                    String cCode = res.getDecompiledFunction().getC();
                    writer.write((cCode != null ? cCode : "/* Empty decompiler result */") + "\n\n");
                } else {
                    writer.write("/* Failed to decompile */\n\n");
                }
                writer.flush();
                count++;
            }

            println("SUCCESS: Exported " + count + " functions (" + skipped + " thunks/external skipped) to " + outFile.getAbsolutePath());
        } catch (Exception e) {
            printerr("ERROR during Ghidra export: " + e.getMessage());
        } finally {
            if (writer != null) {
                writer.close();
            }
            decompiler.dispose();
        }
    }
}
