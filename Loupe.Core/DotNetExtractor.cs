using System.IO.Compression;
using System.IO.MemoryMappedFiles;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Reflection.PortableExecutable;
using ICSharpCode.Decompiler;
using ICSharpCode.Decompiler.CSharp.ProjectDecompiler;
using ICSharpCode.Decompiler.Metadata;

namespace Loupe.Core;

/// <summary>Décompilation des programmes .NET (C#, VB.NET, F#) avec le moteur d'ILSpy, intégré.</summary>
public static class DotNetExtractor
{
    public sealed class MetaInfo
    {
        public string AssemblyName = "";
        public string Runtime = "";
        public int TypeCount, MethodCount;
        public List<string> References = new();
        public List<string> ApiNames = new();      // "System.Net.WebClient::DownloadString", P/Invoke "kernel32!VirtualAllocEx"
        public List<string> UserStrings = new();
        public List<string> ResourceNames = new();
        public int UnreadableNames;
        public string? Obfuscator;
    }

    public static MetaInfo ReadMetadata(byte[] data)
    {
        var info = new MetaInfo();
        using var pe = new PEReader(new MemoryStream(data));
        if (!pe.HasMetadata) return info;
        var md = pe.GetMetadataReader();
        info.Runtime = md.MetadataVersion;
        if (md.IsAssembly) info.AssemblyName = md.GetString(md.GetAssemblyDefinition().Name);
        info.TypeCount = md.TypeDefinitions.Count;
        info.MethodCount = md.MethodDefinitions.Count;
        foreach (var h in md.AssemblyReferences)
        {
            var r = md.GetAssemblyReference(h);
            info.References.Add(md.GetString(r.Name) + " " + r.Version);
        }
        foreach (var h in md.MemberReferences)
        {
            try
            {
                var m = md.GetMemberReference(h);
                string parent = m.Parent.Kind switch
                {
                    HandleKind.TypeReference => TypeRefName(md, (TypeReferenceHandle)m.Parent),
                    HandleKind.TypeDefinition => TypeDefName(md, (TypeDefinitionHandle)m.Parent),
                    _ => "",
                };
                info.ApiNames.Add(parent + "::" + md.GetString(m.Name));
            }
            catch { }
        }
        foreach (var h in md.MethodDefinitions)
        {
            var m = md.GetMethodDefinition(h);
            var name = md.GetString(m.Name);
            if (LooksObfuscated(name)) info.UnreadableNames++;
            var imp = m.GetImport();
            if (!imp.Module.IsNil)
            {
                var mod = md.GetString(md.GetModuleReference(imp.Module).Name);
                var entry = imp.Name.IsNil ? name : md.GetString(imp.Name);
                info.ApiNames.Add(mod + "!" + entry);
            }
        }
        foreach (var h in md.TypeDefinitions)
        {
            var t = md.GetTypeDefinition(h);
            var n = md.GetString(t.Name);
            if (LooksObfuscated(n)) info.UnreadableNames++;
            foreach (var known in KnownObfuscators)
                if (n.Contains(known.Key, StringComparison.OrdinalIgnoreCase)) info.Obfuscator ??= known.Value;
        }
        foreach (var h in md.CustomAttributes)
        {
            try
            {
                var a = md.GetCustomAttribute(h);
                if (a.Constructor.Kind == HandleKind.MemberReference)
                {
                    var mr = md.GetMemberReference((MemberReferenceHandle)a.Constructor);
                    if (mr.Parent.Kind == HandleKind.TypeReference)
                    {
                        var tn = TypeRefName(md, (TypeReferenceHandle)mr.Parent);
                        foreach (var known in KnownObfuscators)
                            if (tn.Contains(known.Key, StringComparison.OrdinalIgnoreCase)) info.Obfuscator ??= known.Value;
                    }
                }
            }
            catch { }
        }
        foreach (var h in md.ManifestResources)
            info.ResourceNames.Add(md.GetString(md.GetManifestResource(h).Name));

        // chaînes littérales du code (#US)
        var us = md.GetHeapSize(HeapIndex.UserString) > 1 ? MetadataTokens.UserStringHandle(1) : default;
        int guard = 0;
        while (!us.IsNil && guard++ < 500_000)
        {
            var s = md.GetUserString(us);
            if (s.Length > 0) info.UserStrings.Add(s);
            us = md.GetNextHandle(us);
        }
        return info;
    }

    static readonly Dictionary<string, string> KnownObfuscators = new(StringComparer.OrdinalIgnoreCase)
    {
        ["ConfusedBy"] = "ConfuserEx", ["Confuser"] = "ConfuserEx", ["Dotfuscator"] = "Dotfuscator",
        ["SmartAssembly"] = "SmartAssembly", ["Babel"] = "Babel Obfuscator", ["Eazfuscator"] = "Eazfuscator.NET",
        ["Reactor"] = ".NET Reactor", ["Xenocode"] = "Xenocode", ["CryptoObfuscator"] = "Crypto Obfuscator",
        ["Agile.NET"] = "Agile.NET", ["ObfuscatedByGoliath"] = "Goliath", ["NETGuard"] = "NETGuard",
    };

    static bool LooksObfuscated(string n)
    {
        if (n.Length == 0) return false;
        int weird = 0;
        foreach (var c in n) if (c > 0x2000 || char.IsControl(c)) weird++;
        return weird > 0 && weird >= n.Length / 2;
    }

    static string TypeRefName(MetadataReader md, TypeReferenceHandle h)
    {
        var t = md.GetTypeReference(h);
        var ns = md.GetString(t.Namespace);
        return (ns.Length > 0 ? ns + "." : "") + md.GetString(t.Name);
    }

    static string TypeDefName(MetadataReader md, TypeDefinitionHandle h)
    {
        var t = md.GetTypeDefinition(h);
        var ns = md.GetString(t.Namespace);
        return (ns.Length > 0 ? ns + "." : "") + md.GetString(t.Name);
    }

    /// <summary>Décompile un assembly .NET en projet C# complet (fichiers .cs + ressources).</summary>
    public static (bool Ok, int Files, string Error) Decompile(string displayName, byte[] data, string targetDir, CancellationToken ct, string? searchDir = null)
    {
        try
        {
            Directory.CreateDirectory(targetDir);
            var file = new PEFile(displayName, new MemoryStream(data), PEStreamOptions.PrefetchEntireImage, MetadataReaderOptions.Default, null);
            string tfm = "";
            try { tfm = file.DetectTargetFrameworkId() ?? ""; } catch { }
            var resolver = new UniversalAssemblyResolver(displayName, false, tfm, null, PEStreamOptions.PrefetchMetadata, MetadataReaderOptions.Default);
            if (searchDir != null) resolver.AddSearchDirectory(searchDir);
            var settings = new DecompilerSettings(ICSharpCode.Decompiler.CSharp.LanguageVersion.Latest)
            {
                ThrowOnAssemblyResolveErrors = false,
                RemoveDeadCode = false,
                UseNestedDirectoriesForNamespaces = true,
                LoadInMemory = true,
            };
            var dec = new WholeProjectDecompiler(settings, resolver, null, null, null)
            {
                MaxDegreeOfParallelism = Math.Max(1, Environment.ProcessorCount),
            };
            dec.DecompileProject(file, targetDir, ct);
            int n = Directory.EnumerateFiles(targetDir, "*.cs", SearchOption.AllDirectories).Count();
            return (true, n, "");
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            return (false, 0, ex.GetType().Name + " : " + ex.Message);
        }
    }

    /// <summary>Programme .NET 5+ "fichier unique" : un lanceur natif qui contient les DLL .NET.</summary>
    public static bool TryGetBundle(string path, out SingleFileBundle.Header header)
    {
        header = default;
        try
        {
            using var mmf = MemoryMappedFile.CreateFromFile(path, FileMode.Open, null, 0, MemoryMappedFileAccess.Read);
            using var view = mmf.CreateViewAccessor(0, 0, MemoryMappedFileAccess.Read);
            if (!SingleFileBundle.IsBundle(view, out long offset)) return false;
            header = SingleFileBundle.ReadManifest(view, offset);
            return true;
        }
        catch { return false; }
    }

    public static byte[] ReadBundleEntry(byte[] data, SingleFileBundle.Entry e)
    {
        if (e.CompressedSize == 0)
            return data.AsSpan((int)e.Offset, (int)e.Size).ToArray();
        using var input = new MemoryStream(data, (int)e.Offset, (int)e.CompressedSize);
        using var z = new DeflateStream(input, CompressionMode.Decompress);
        var output = new MemoryStream((int)Math.Min(e.Size, int.MaxValue));
        z.CopyTo(output);
        return output.ToArray();
    }

    // jetons de clé publique des assemblies signés par Microsoft (.NET, WPF, WinForms, ASP.NET, WebView2…)
    static readonly HashSet<string> MicrosoftTokens = new(StringComparer.OrdinalIgnoreCase)
    { "b03f5f7f11d50a3a", "b77a5c561934e089", "31bf3856ad364e35", "cc7b13ffcd2ddd51", "7cec85d7bea7798e", "adb9793829ddae60", "2a8ab48044d2601e", "89845dcd8080cc91", "30ad4fe6b2a6aeed" };

    public static bool IsFrameworkAssembly(string name, byte[]? bytes = null)
    {
        if (bytes != null)
        {
            try
            {
                using var pe = new PEReader(new MemoryStream(bytes));
                if (pe.HasMetadata)
                {
                    var md = pe.GetMetadataReader();
                    if (md.IsAssembly)
                    {
                        var key = md.GetBlobBytes(md.GetAssemblyDefinition().PublicKey);
                        if (key.Length > 0)
                        {
                            var hash = System.Security.Cryptography.SHA1.HashData(key);
                            var token = hash.AsSpan(hash.Length - 8).ToArray();
                            Array.Reverse(token);
                            if (MicrosoftTokens.Contains(Convert.ToHexString(token))) return true;
                        }
                    }
                }
            }
            catch { }
        }
        var n = Path.GetFileNameWithoutExtension(name);
        string[] prefixes = { "System.", "Microsoft.", "runtime.", "Windows.", "WinRT.", "Presentation", "UIAutomation", "ReachFramework", "DirectWriteForwarder", "WindowsFormsIntegration", "Accessibility", "PenImc", "wpfgfx",
            /* bibliothèques connues, très répandues */ "Newtonsoft.Json", "Iced", "ICSharpCode.", "Mono.Cecil", "Serilog", "NLog", "log4net", "Dapper", "AutoMapper", "MahApps.", "MaterialDesign", "BouncyCastle", "SQLitePCLRaw", "Google.Protobuf", "Avalonia", "SkiaSharp", "HarfBuzzSharp", "CommunityToolkit.", "Polly", "RestSharp", "YamlDotNet", "CsvHelper", "HtmlAgilityPack", "SharpCompress", "ZstdSharp", "K4os.", "MessagePack", "protobuf-net", "Humanizer", "Spectre.Console" };
        return n is "mscorlib" or "netstandard" or "System" or "WindowsBase"
            || prefixes.Any(p => n.StartsWith(p, StringComparison.OrdinalIgnoreCase));
    }
}
