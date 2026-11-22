using System.Text.RegularExpressions;

namespace Loupe.Core;

/// <summary>Une règle de détection : elle se déclenche si CHAQUE groupe trouve au moins un motif
/// (et au moins MinDistinct motifs différents au total).</summary>
public sealed class Rule
{
    public string Id = "";
    public Severity Severity;
    public int Weight;
    public string Category = "";
    public string Title = "";
    public string Explanation = "";
    public Regex[] Groups = Array.Empty<Regex>();
    public int MinDistinct = 1;
}

/// <summary>Forme « données » d'une règle (fichier rules.json).</summary>
public sealed class RuleDef
{
    public string Id { get; set; } = "";
    public Severity Severity { get; set; }
    public int Weight { get; set; }
    public string Category { get; set; } = "";
    public string Title { get; set; } = "";
    public string Explanation { get; set; } = "";
    public int MinDistinct { get; set; } = 1;
    public List<string> Groups { get; set; } = new();
}

/// <summary>Les règles sont dans Regles/regles.json. À la compilation, ce fichier est compressé et intégré au programme :
/// ainsi Loupe ne contient pas en clair les noms et commandes de malwares qu'il recherche (sinon il se détecterait lui-même,
/// et certains antivirus pourraient se méfier de lui).</summary>
public static class Rules
{
    const RegexOptions O = RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled | RegexOptions.Multiline;

    public static readonly Rule[] All = Load();

    static Rule[] Load()
    {
        using var st = typeof(Rules).Assembly.GetManifestResourceStream("Loupe.Core.regles.bin")
            ?? throw new InvalidOperationException("Règles de détection introuvables dans le programme.");
        using var z = new System.IO.Compression.DeflateStream(st, System.IO.Compression.CompressionMode.Decompress);
        var defs = System.Text.Json.JsonSerializer.Deserialize<List<RuleDef>>(z, Analyzer.Json) ?? new();
        return defs.Select(d => new Rule
        {
            Id = d.Id, Severity = d.Severity, Weight = d.Weight, Category = d.Category, Title = d.Title,
            Explanation = d.Explanation, MinDistinct = Math.Max(1, d.MinDistinct),
            Groups = d.Groups.Select(g => new Regex(g, O, TimeSpan.FromSeconds(2))).ToArray(),
        }).ToArray();
    }
}
