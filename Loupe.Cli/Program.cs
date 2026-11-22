using System.Text.Json;
using Loupe.Core;

// Loupe en ligne de commande : loupe <fichier.exe> [dossier-de-sortie] [--ghidra <dossier>] [--outils <dossier>]
if (args.Length == 0)
{
    Console.WriteLine("Usage : loupe <fichier> [dossier-de-sortie] [--ghidra <dossier Ghidra>] [--outils <dossier>] [--json]");
    return 1;
}
if (args[0] == "--export-rules")
{
    var defs = Rules.All.Select(r => new RuleDef { Id = r.Id, Severity = r.Severity, Weight = r.Weight, Category = r.Category, Title = r.Title, Explanation = r.Explanation, MinDistinct = r.MinDistinct, Groups = r.Groups.Select(g => g.ToString()).ToList() }).ToList();
    File.WriteAllText(args[1], JsonSerializer.Serialize(defs, Analyzer.Json));
    Console.WriteLine(defs.Count + " règles exportées");
    return 0;
}
var opt = new AnalyzeOptions();
string? file = null; bool json = false;
for (int i = 0; i < args.Length; i++)
{
    if (args[i] == "--ghidra" && i + 1 < args.Length) opt.GhidraDir = args[++i];
    else if (args[i] == "--outils" && i + 1 < args.Length) opt.ToolsDir = args[++i];
    else if (args[i] == "--json") json = true;
    else if (file == null) file = args[i];
    else opt.OutputDir = args[i];
}
Console.OutputEncoding = System.Text.Encoding.UTF8;
var progress = new Progress<Progress>(p => Console.Error.WriteLine($"[{p.Percent,3}%] {p.Step}"));
var r = Analyzer.Run(file!, opt, progress);
if (json) { Console.WriteLine(JsonSerializer.Serialize(r, Analyzer.Json)); return 0; }
Console.WriteLine();
Console.WriteLine($"Fichier  : {r.FileName} ({Util.HumanSize(r.FileSize)})");
Console.WriteLine($"SHA-256  : {r.Hashes.Sha256}");
Console.WriteLine($"Type     : {r.KindLabel} — {r.Language}");
foreach (var d in r.KindDetails) Console.WriteLine($"           · {d}");
Console.WriteLine($"Verdict  : {r.Verdict} ({r.Score}/100)");
Console.WriteLine();
foreach (var i in r.Indicators)
{
    Console.WriteLine($"[{i.Severity,-8}] +{i.Weight,-3} {i.Title}  ({i.Hits} occurrences)");
    foreach (var e in i.Evidence.Take(3)) Console.WriteLine($"              {e.Where} : {Util.Truncate(e.Text, 150)}");
}
Console.WriteLine();
Console.WriteLine("Domaines : " + string.Join(", ", r.Domains.Take(40)));
Console.WriteLine("IP       : " + string.Join(", ", r.Ips.Take(20)));
foreach (var n in r.Notes) Console.WriteLine("Note : " + n);
foreach (var w in r.Warnings) Console.WriteLine("ATTENTION : " + w);
Console.WriteLine($"Sortie   : {r.OutputDir} ({r.Files.Count} fichiers, {r.Seconds} s)");
return 0;
