using System.Text.Json.Serialization;

namespace Loupe.Core;

public enum Severity { Info = 0, Faible = 1, Moyen = 2, Eleve = 3, Critique = 4 }

public sealed class Hashes
{
    public string Md5 { get; set; } = "";
    public string Sha1 { get; set; } = "";
    public string Sha256 { get; set; } = "";
}

public sealed class SectionInfo
{
    public string Name { get; set; } = "";
    public uint VirtualAddress { get; set; }
    public uint VirtualSize { get; set; }
    public uint RawSize { get; set; }
    public uint RawOffset { get; set; }
    public double Entropy { get; set; }
    public string Flags { get; set; } = "";
}

public sealed class ImportDll
{
    public string Dll { get; set; } = "";
    public List<string> Functions { get; set; } = new();
}

public sealed class ResourceInfo
{
    public string Type { get; set; } = "";
    public string Name { get; set; } = "";
    public uint Size { get; set; }
    public string Detected { get; set; } = "";
}

public sealed class SignatureInfo
{
    public bool Present { get; set; }
    public string Signer { get; set; } = "";
    public string Issuer { get; set; } = "";
    public string ValidFrom { get; set; } = "";
    public string ValidTo { get; set; } = "";
    /// <summary>"valide", "invalide", "non vérifiée" (hors Windows)</summary>
    public string Status { get; set; } = "";
}

public sealed class PeSummary
{
    public bool IsPe { get; set; }
    public string Machine { get; set; } = "";
    public bool Is64 { get; set; }
    public bool IsDll { get; set; }
    public string Subsystem { get; set; } = "";
    public string CompiledAt { get; set; } = "";
    public string EntryPoint { get; set; } = "";
    public string ImageBase { get; set; } = "";
    public List<SectionInfo> Sections { get; set; } = new();
    public List<ImportDll> Imports { get; set; } = new();
    public List<string> Exports { get; set; } = new();
    public List<ResourceInfo> Resources { get; set; } = new();
    public Dictionary<string, string> VersionInfo { get; set; } = new();
    public string Manifest { get; set; } = "";
    public bool RequiresAdmin { get; set; }
    public long OverlayOffset { get; set; }
    public long OverlaySize { get; set; }
    public string OverlayType { get; set; } = "";
    public SignatureInfo Signature { get; set; } = new();
    public bool HasRichHeader { get; set; }
}

public sealed class Evidence
{
    public string Where { get; set; } = "";
    public string Text { get; set; } = "";
}

public sealed class Indicator
{
    public string Id { get; set; } = "";
    public Severity Severity { get; set; }
    public string Category { get; set; } = "";
    public string Title { get; set; } = "";
    public string Explanation { get; set; } = "";
    public int Weight { get; set; }
    public List<Evidence> Evidence { get; set; } = new();
    public int Hits { get; set; }
}

public sealed class ExtractedFile
{
    public string Path { get; set; } = "";
    public long Size { get; set; }
    public string Kind { get; set; } = "";
}

public sealed class AnalysisResult
{
    public string ToolVersion { get; set; } = Analyzer.Version;
    public string FilePath { get; set; } = "";
    public string FileName { get; set; } = "";
    public long FileSize { get; set; }
    public string AnalyzedAt { get; set; } = "";
    public Hashes Hashes { get; set; } = new();
    public PeSummary Pe { get; set; } = new();

    /// <summary>Code court : dotnet, dotnet-bundle, pyinstaller, native, upx, installer, autoit, not-pe…</summary>
    public string Kind { get; set; } = "";
    public string KindLabel { get; set; } = "";
    public string Language { get; set; } = "";
    public List<string> KindDetails { get; set; } = new();
    public string DecompileQuality { get; set; } = "";

    public List<Indicator> Indicators { get; set; } = new();
    public int Score { get; set; }
    public string Verdict { get; set; } = "";
    public string VerdictLevel { get; set; } = "";
    public string VerdictText { get; set; } = "";

    public List<string> Urls { get; set; } = new();
    public List<string> Domains { get; set; } = new();
    public List<string> Ips { get; set; } = new();
    public List<string> RegistryKeys { get; set; } = new();
    public List<string> Commands { get; set; } = new();
    public int StringCount { get; set; }

    public string OutputDir { get; set; } = "";
    public List<ExtractedFile> Files { get; set; } = new();
    public List<string> Notes { get; set; } = new();
    public List<string> Warnings { get; set; } = new();
    public double Seconds { get; set; }
}

public sealed class AnalyzeOptions
{
    /// <summary>Dossier où tout est écrit (créé s'il n'existe pas).</summary>
    public string OutputDir { get; set; } = "";
    /// <summary>Chemin du dossier d'installation de Ghidra (facultatif) pour le pseudo-C des programmes natifs.</summary>
    public string? GhidraDir { get; set; }
    /// <summary>Dossier contenant les outils facultatifs (pycdc.exe, upx.exe).</summary>
    public string? ToolsDir { get; set; }
    public bool Decompile { get; set; } = true;
    public int GhidraTimeoutSeconds { get; set; } = 600;
}

public sealed record Progress(int Percent, string Step);
