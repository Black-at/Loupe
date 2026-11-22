using System.Diagnostics;
using System.Text;
using Iced.Intel;

namespace Loupe.Core;

/// <summary>Programmes natifs (C, C++, Rust, Go, Delphi…) : désassemblage intégré + pseudo-C via Ghidra si installé.</summary>
public static class NativeExtractor
{
    /// <summary>Désassemble les premières instructions à partir du point d'entrée.</summary>
    public static string DisassembleEntry(PeFile pe, int maxInstructions = 600)
    {
        if (!pe.Valid || pe.EntryPointRva == 0) return "";
        if (pe.Machine != 0x14c && pe.Machine != 0x8664) return "; Désassemblage intégré disponible seulement pour x86 / x64.\n";
        long off = pe.RvaToOffset(pe.EntryPointRva);
        if (off < 0) return "; Point d'entrée hors du fichier (programme compressé ?).\n";
        int len = (int)Math.Min(64 * 1024, pe.Data.Length - off);
        var bytes = pe.Data.AsSpan((int)off, len).ToArray();
        int bitness = pe.Is64 ? 64 : 32;
        ulong ip = pe.ImageBase + pe.EntryPointRva;
        var decoder = Iced.Intel.Decoder.Create(bitness, new ByteArrayCodeReader(bytes), ip);
        var fmt = new IntelFormatter();
        fmt.Options.FirstOperandCharIndex = 10;
        fmt.Options.HexPrefix = "0x"; fmt.Options.HexSuffix = "";
        var sb = new StringBuilder();
        sb.AppendLine("; Désassemblage (syntaxe Intel) depuis le point d'entrée");
        sb.AppendLine($"; Architecture : {(pe.Is64 ? "x64" : "x86")}   Point d'entrée : 0x{ip:X}");
        sb.AppendLine("; Les programmes natifs ne contiennent plus leur code source : ceci est le code machine traduit en assembleur.");
        sb.AppendLine();
        var output = new StringOutput();
        int count = 0, rets = 0;
        while (decoder.IP < ip + (ulong)bytes.Length && count < maxInstructions)
        {
            decoder.Decode(out var instr);
            if (instr.IsInvalid) { sb.AppendLine($"{instr.IP:X16}  ??"); break; }
            fmt.Format(instr, output);
            int start = (int)(instr.IP - ip);
            var hex = Convert.ToHexString(bytes, start, Math.Min(instr.Length, 10)).ToLowerInvariant();
            sb.Append(instr.IP.ToString(pe.Is64 ? "X16" : "X8")).Append("  ").Append(hex.PadRight(22)).Append(output.ToStringAndReset()).AppendLine();
            count++;
            if (instr.Mnemonic == Mnemonic.Ret || instr.Mnemonic == Mnemonic.Int3 && rets > 0) { rets++; sb.AppendLine(); if (rets >= 12) break; }
        }
        return sb.ToString();
    }

    public static string? FindGhidraHeadless(string? ghidraDir)
    {
        if (string.IsNullOrWhiteSpace(ghidraDir) || !Directory.Exists(ghidraDir)) return null;
        foreach (var name in new[] { "analyzeHeadless.bat", "analyzeHeadless" })
        {
            var p = Path.Combine(ghidraDir, "support", name);
            if (File.Exists(p)) return p;
        }
        // l'utilisateur a peut-être choisi le dossier parent
        foreach (var sub in Directory.EnumerateDirectories(ghidraDir, "ghidra_*"))
        {
            var r = FindGhidraHeadless(sub);
            if (r != null) return r;
        }
        return null;
    }

    const string GhidraScript = """
        //Exporte le pseudo-C de toutes les fonctions (script de Loupe)
        //@category Loupe
        import ghidra.app.script.GhidraScript;
        import ghidra.app.decompiler.*;
        import ghidra.program.model.listing.*;
        import java.io.*;

        public class LoupeExport extends GhidraScript {
            @Override
            public void run() throws Exception {
                String[] args = getScriptArgs();
                File out = new File(args[0]);
                int max = args.length > 1 ? Integer.parseInt(args[1]) : 4000;
                DecompInterface d = new DecompInterface();
                d.openProgram(currentProgram);
                int n = 0;
                try (PrintWriter w = new PrintWriter(new OutputStreamWriter(new FileOutputStream(out), "UTF-8"))) {
                    w.println("// Pseudo-C généré par Ghidra pour " + currentProgram.getName());
                    w.println("// C'est une reconstruction : noms de variables et types sont devinés.");
                    w.println();
                    FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
                    while (it.hasNext() && !monitor.isCancelled() && n < max) {
                        Function f = it.next();
                        if (f.isExternal() || f.isThunk()) continue;
                        DecompileResults r = d.decompileFunction(f, 30, monitor);
                        if (r != null && r.decompileCompleted() && r.getDecompiledFunction() != null) {
                            w.println("// ---- " + f.getName() + " @ " + f.getEntryPoint());
                            w.println(r.getDecompiledFunction().getC());
                            n++;
                        }
                    }
                }
                d.dispose();
                println("LOUPE_OK " + n);
            }
        }
        """;

    /// <summary>Lance Ghidra en mode sans fenêtre pour produire du pseudo-C. Ghidra ANALYSE le fichier, il ne l'exécute pas.</summary>
    public static (bool Ok, string Message) RunGhidra(string headless, string samplePath, string outFile, int timeoutSec, CancellationToken ct, Action<string>? log = null)
    {
        var work = Path.Combine(Path.GetTempPath(), "loupe-ghidra-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(work);
        try
        {
            File.WriteAllText(Path.Combine(work, "LoupeExport.java"), GhidraScript, new UTF8Encoding(false));
            var psi = new ProcessStartInfo(headless)
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                WorkingDirectory = work,
            };
            foreach (var a in new[] { work, "loupe", "-import", samplePath, "-scriptPath", work, "-postScript", "LoupeExport.java", outFile, "4000", "-deleteProject", "-analysisTimeoutPerFile", timeoutSec.ToString() })
                psi.ArgumentList.Add(a);
            using var proc = Process.Start(psi)!;
            var tail = new Queue<string>();
            bool ok = false;
            void OnLine(string? l)
            {
                if (l == null) return;
                if (l.Contains("LOUPE_OK")) ok = true;
                lock (tail) { tail.Enqueue(l); if (tail.Count > 30) tail.Dequeue(); }
                if (l.Contains("INFO  ANALYZING") || l.Contains("Decompil")) log?.Invoke(l.Trim());
            }
            proc.OutputDataReceived += (_, e) => OnLine(e.Data);
            proc.ErrorDataReceived += (_, e) => OnLine(e.Data);
            proc.BeginOutputReadLine(); proc.BeginErrorReadLine();
            var sw = Stopwatch.StartNew();
            while (!proc.WaitForExit(500))
            {
                if (ct.IsCancellationRequested || sw.Elapsed.TotalSeconds > timeoutSec * 2 + 120)
                {
                    try { proc.Kill(true); } catch { }
                    return (false, ct.IsCancellationRequested ? "annulé" : "Ghidra a mis trop de temps");
                }
            }
            proc.WaitForExit();
            if (ok && File.Exists(outFile)) return (true, "");
            string last;
            lock (tail) last = string.Join("\n", tail.TakeLast(6));
            return (false, "Ghidra n'a pas produit de résultat. " + last);
        }
        catch (Exception ex) { return (false, ex.Message); }
        finally { try { Directory.Delete(work, true); } catch { } }
    }
}
