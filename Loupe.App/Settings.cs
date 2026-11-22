using System.Text.Json;
using Loupe.Core;

namespace Loupe.App;

public sealed class RecentItem
{
    public string Name { get; set; } = "";
    public string Verdict { get; set; } = "";
    public string Level { get; set; } = "";
    public string Date { get; set; } = "";
    public string Kind { get; set; } = "";
    public string Sha256 { get; set; } = "";
    public string OutputDir { get; set; } = "";
}

/// <summary>Réglages enregistrés dans %LOCALAPPDATA%\Loupe\settings.json</summary>
public sealed class Settings
{
    public string OutputRoot { get; set; } = "";
    public string GhidraDir { get; set; } = "";
    public string ToolsDir { get; set; } = "";
    public bool Decompile { get; set; } = true;
    public List<RecentItem> Recents { get; set; } = new();

    static string FilePath => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Loupe", "settings.json");

    public static string DefaultOutputRoot =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), "Loupe");

    public static Settings Load()
    {
        try
        {
            if (File.Exists(FilePath))
                return JsonSerializer.Deserialize<Settings>(File.ReadAllText(FilePath), Analyzer.Json) ?? new Settings();
        }
        catch { }
        return new Settings();
    }

    public void Save()
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(FilePath)!);
            File.WriteAllText(FilePath, JsonSerializer.Serialize(this, Analyzer.Json));
        }
        catch { }
    }

    public object ToUi() => new
    {
        outputRoot = string.IsNullOrWhiteSpace(OutputRoot) ? DefaultOutputRoot : OutputRoot,
        ghidraDir = GhidraDir,
        toolsDir = ToolsDir,
        decompile = Decompile,
    };

    public void AddRecent(AnalysisResult r)
    {
        Recents.RemoveAll(x => x.OutputDir == r.OutputDir);
        Recents.Insert(0, new RecentItem
        {
            Name = r.FileName, Verdict = r.Verdict, Level = r.VerdictLevel, Kind = r.KindLabel,
            Sha256 = r.Hashes.Sha256, OutputDir = r.OutputDir, Date = DateTime.Now.ToString("dd/MM/yyyy HH:mm"),
        });
        if (Recents.Count > 15) Recents.RemoveRange(15, Recents.Count - 15);
        Save();
    }
}
