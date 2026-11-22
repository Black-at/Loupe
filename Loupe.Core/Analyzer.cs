using System.Diagnostics;
using System.IO.Compression;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Loupe.Core;

/// <summary>Chef d'orchestre de l'analyse. Le fichier analysé n'est JAMAIS exécuté : il est seulement lu.</summary>
public static class Analyzer
{
    public const string Version = "1.0.0";
    public const long MaxFileSize = 1_500L * 1024 * 1024;

    public static readonly JsonSerializerOptions Json = new()
    {
        WriteIndented = true,
        Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
        Converters = { new JsonStringEnumConverter() },
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
    };

    public static AnalysisResult Run(string path, AnalyzeOptions opt, IProgress<Progress>? progress = null, CancellationToken ct = default)
    {
        var sw = Stopwatch.StartNew();
        void P(int pct, string step) => progress?.Report(new Progress(pct, step));
        var r = new AnalysisResult
        {
            FilePath = Path.GetFullPath(path),
            FileName = Path.GetFileName(path),
            AnalyzedAt = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"),
        };

        P(2, "Lecture du fichier");
        var fi = new FileInfo(path);
        if (!fi.Exists) throw new FileNotFoundException("Fichier introuvable", path);
        if (fi.Length > MaxFileSize) throw new InvalidOperationException("Fichier trop gros (plus de 1,5 Go).");
        byte[] data;
        using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
        {
            data = new byte[fs.Length];
            fs.ReadExactly(data);
        }
        r.FileSize = data.Length;

        var outDir = Path.GetFullPath(string.IsNullOrWhiteSpace(opt.OutputDir)
            ? Path.Combine(Path.GetTempPath(), "Loupe", Util.SafeName(Path.GetFileNameWithoutExtension(path)) + "_" + DateTime.Now.ToString("yyyyMMdd-HHmmss"))
            : opt.OutputDir);
        Directory.CreateDirectory(outDir);
        r.OutputDir = outDir;

        P(5, "Calcul des empreintes");
        r.Hashes = Util.ComputeHashes(data);

        P(8, "Lecture de la structure du programme");
        var pe = new PeFile(data);
        var scanner = new Scanner();
        List<PeFile.RawResource> resources = new();
        if (pe.Valid) resources = FillPe(r, pe, path);
        else r.Pe.IsPe = false;

        P(14, "Extraction des textes");
        var strings = StringsExtractor.Extract(data);
        r.StringCount = strings.Count;
        File.WriteAllLines(Path.Combine(outDir, "textes-trouves.txt"), strings, new UTF8Encoding(false));

        P(18, "Identification du type de programme");
        Detect(r, pe, data, strings, path);
        // un .NET « fichier unique » contient tout le moteur .NET de Microsoft : on n'examine que le lanceur et le code du programme
        if (r.Kind != "dotnet-bundle")
        {
            scanner.AddLines("Textes du fichier", strings);
            if (r.Pe.Imports.Count > 0)
                scanner.AddLines("Fonctions Windows importées", r.Pe.Imports.SelectMany(i => i.Functions.Select(f => i.Dll + "!" + f)).Concat(r.Pe.Imports.SelectMany(i => i.Functions)));
        }

        // ---------- extraction / décompilation ----------
        var codeDir = Path.Combine(outDir, "code-source");
        bool hasEmbeddedExe = false;
        try
        {
            switch (r.Kind)
            {
                case "dotnet": DoDotNet(r, data, path, codeDir, scanner, opt, P, ct); break;
                case "dotnet-bundle": DoBundle(r, data, path, outDir, codeDir, scanner, opt, P, ct); break;
                case "pyinstaller": DoPython(r, data, outDir, codeDir, scanner, opt, P, ct); break;
                case "upx": DoUpx(r, data, path, outDir, codeDir, scanner, opt, P, ct); break;
                case "sfx-zip": DoZipOverlay(r, data, pe, outDir, ct); break;
            }
            if (pe.Valid && r.Kind is "native" or "installer-nsis" or "installer-inno" or "autoit" or "nuitka" or "go" or "rust" or "delphi" or "vb6" or "sfx-7z" or "sfx-zip")
                DoNative(r, pe, path, outDir, codeDir, opt, P, ct);
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex) { r.Warnings.Add("Erreur pendant l'extraction : " + ex.Message); }

        P(80, "Extraction des ressources");
        if (pe.Valid)
        {
            hasEmbeddedExe |= DumpResources(r, pe, resources, outDir);
            hasEmbeddedExe |= DumpOverlay(r, pe, outDir);
        }

        P(83, "Sécurisation des fichiers extraits");
        DefangTree(outDir);

        P(85, "Recherche de comportements suspects");
        ScanTextFiles(outDir, scanner, ct);
        var indicators = scanner.Run(ct);
        indicators.AddRange(StructuralIndicators(r, pe, data, hasEmbeddedExe));
        r.Indicators = indicators.OrderByDescending(i => i.Severity).ThenByDescending(i => i.Weight).ToList();

        var net = scanner.Network();
        r.Urls = net.Urls; r.Domains = net.Domains; r.Ips = net.Ips; r.RegistryKeys = net.Reg; r.Commands = net.Cmds;
        if (r.Ips.Count > 0 && !r.Indicators.Any(i => i.Id == "public_ip"))
        {
            r.Indicators.Add(new Indicator
            {
                Id = "public_ip", Severity = Severity.Faible, Weight = 3, Category = "Réseau", Title = "Adresses IP écrites en dur",
                Explanation = "Le programme contient des adresses IP publiques. Un programme normal utilise plutôt des noms de domaine ; une IP fixe peut être un serveur de contrôle.",
                Evidence = r.Ips.Take(8).Select(ip => new Evidence { Where = "Adresse", Text = ip }).ToList(), Hits = r.Ips.Count,
            });
        }

        Score(r);

        P(95, "Écriture du rapport");
        r.Files = ListFiles(outDir);
        r.Seconds = Math.Round(sw.Elapsed.TotalSeconds, 1);
        File.WriteAllText(Path.Combine(outDir, "rapport.json"), JsonSerializer.Serialize(r, Json), new UTF8Encoding(false));
        File.WriteAllText(Path.Combine(outDir, "rapport.html"), ReportWriter.Html(r), new UTF8Encoding(false));
        File.WriteAllText(Path.Combine(outDir, "LISEZ-MOI.txt"), ReadMe(r), new UTF8Encoding(true));
        r.Files = ListFiles(outDir);
        P(100, "Terminé");
        return r;
    }

    // ================= structure PE =================
    static List<PeFile.RawResource> FillPe(AnalysisResult r, PeFile pe, string path)
    {
        var s = r.Pe;
        s.IsPe = true;
        s.Machine = pe.MachineName;
        s.Is64 = pe.Is64;
        s.IsDll = pe.IsDll;
        s.Subsystem = pe.SubsystemName;
        s.HasRichHeader = pe.HasRichHeader;
        var date = DateTimeOffset.FromUnixTimeSeconds(pe.TimeDateStamp).UtcDateTime;
        s.CompiledAt = pe.TimeDateStamp == 0 ? "inconnue" : date.ToString("yyyy-MM-dd HH:mm") + " UTC";
        s.EntryPoint = "0x" + pe.EntryPointRva.ToString("X");
        s.ImageBase = "0x" + pe.ImageBase.ToString("X");
        foreach (var sec in pe.Sections)
        {
            var span = sec.RawSize > 0 && sec.RawOffset < pe.Data.Length
                ? pe.Data.AsSpan((int)sec.RawOffset, (int)Math.Min(sec.RawSize, pe.Data.Length - sec.RawOffset)) : ReadOnlySpan<byte>.Empty;
            s.Sections.Add(new SectionInfo
            {
                Name = sec.Name, VirtualAddress = sec.VirtualAddress, VirtualSize = sec.VirtualSize,
                RawOffset = sec.RawOffset, RawSize = sec.RawSize, Entropy = Util.Entropy(span), Flags = PeFile.SectionFlags(sec.Characteristics),
            });
        }
        try { s.Imports = pe.ReadImports().Select(i => new ImportDll { Dll = i.Dll, Functions = i.Funcs }).ToList(); } catch { }
        try { s.Exports = pe.ReadExports(); } catch { }
        var res = new List<PeFile.RawResource>();
        try { res = pe.ReadResources(); } catch { }
        foreach (var x in res)
        {
            var span = pe.Data.AsSpan((int)x.Offset, (int)Math.Min(x.Size, 64));
            s.Resources.Add(new ResourceInfo { Type = x.Type, Name = x.Name, Size = x.Size, Detected = Util.Sniff(span) });
        }
        s.VersionInfo = pe.ReadVersionInfo(res);
        var man = res.FirstOrDefault(x => x.Type == "MANIFEST");
        if (man != null)
        {
            s.Manifest = Encoding.UTF8.GetString(pe.Data, (int)man.Offset, (int)Math.Min(man.Size, 64 * 1024)).Trim('﻿', '\0', ' ', '\r', '\n');
            s.RequiresAdmin = s.Manifest.Contains("requireAdministrator", StringComparison.OrdinalIgnoreCase);
        }
        var ov = pe.Overlay;
        s.OverlayOffset = ov.Offset; s.OverlaySize = ov.Size;
        if (ov.Size > 0) s.OverlayType = Util.Sniff(pe.Data.AsSpan((int)ov.Offset, (int)Math.Min(ov.Size, 64)));
        s.Signature = Signature.Read(pe, path);
        return res;
    }

    // ================= type de programme =================
    static void Detect(AnalysisResult r, PeFile pe, byte[] data, List<string> strings, string path)
    {
        bool Has(string s) => PeFile.IndexOf(data, Encoding.ASCII.GetBytes(s)) >= 0;
        bool HasImport(string dll) => r.Pe.Imports.Any(i => i.Dll.Equals(dll, StringComparison.OrdinalIgnoreCase));

        if (!pe.Valid && PyInstallerExtractor.IsPyInstaller(data))
        {
            r.Kind = "pyinstaller";
            r.KindLabel = "Programme Python empaqueté (PyInstaller, hors Windows)";
            r.Language = "Python";
            r.DecompileQuality = "Bonne : les scripts Python sont extraits.";
            return;
        }
        if (!pe.Valid)
        {
            var kind = Util.Sniff(data);
            r.Kind = "not-pe";
            r.KindLabel = "Ce n'est pas un programme Windows (" + (kind == "" ? "format inconnu" : kind) + ")";
            r.Language = "";
            r.DecompileQuality = "Rien à décompiler : seuls les textes et le contenu sont analysés.";
            if (kind == "zip") r.KindDetails.Add("C'est une archive ZIP : ouvrez-la avec 7-Zip ou l'explorateur Windows.");
            r.Notes.Add("Le fichier ne commence pas par l'en-tête « MZ » des programmes Windows (" + pe.Error + ").");
            return;
        }

        if (pe.IsDotNet)
        {
            r.Kind = "dotnet";
            r.KindLabel = "Programme .NET";
            r.Language = "C#";
            r.DecompileQuality = "Excellente : le code C# retrouvé est presque identique à l'original (seuls les commentaires et les noms des variables locales sont perdus).";
            return;
        }
        if (DotNetExtractor.TryGetBundle(path, out var bundle))
        {
            r.Kind = "dotnet-bundle";
            r.KindLabel = "Programme .NET « fichier unique » (.NET 5 ou plus récent)";
            r.Language = "C#";
            r.DecompileQuality = "Excellente : les DLL .NET contenues dans le fichier sont décompilées en C#.";
            r.KindDetails.Add(bundle.FileCount + " fichiers intégrés");
            return;
        }
        if (PyInstallerExtractor.IsPyInstaller(data))
        {
            r.Kind = "pyinstaller";
            r.KindLabel = "Programme Python empaqueté (PyInstaller)";
            r.Language = "Python";
            r.DecompileQuality = "Bonne : les scripts Python sont extraits. Ils sont retraduits en code Python si l'outil pycdc est présent, sinon on garde les fichiers .pyc.";
            return;
        }
        if (pe.Sections.Any(s => s.Name.StartsWith("UPX", StringComparison.OrdinalIgnoreCase)) || Has("UPX!"))
        {
            r.Kind = "upx";
            r.KindLabel = "Programme compressé avec UPX";
            r.Language = "Natif";
            r.DecompileQuality = "Le programme est compressé : il faut d'abord le décompresser (upx.exe), puis c'est un programme natif.";
            return;
        }
        if (Has("AU3!EA06") || Has(">>>AUTOIT SCRIPT<<<") || Has("AutoIt v3"))
        {
            r.Kind = "autoit";
            r.KindLabel = "Script AutoIt compilé";
            r.Language = "AutoIt";
            r.DecompileQuality = "Le script AutoIt est caché dans le programme : utilisez un extracteur AutoIt (ex. AutoIt-Ripper) pour le récupérer.";
            return;
        }
        if (Has("Nullsoft Install System") || Has("NullsoftInst"))
        {
            r.Kind = "installer-nsis"; r.KindLabel = "Installateur NSIS"; r.Language = "Installateur";
            r.DecompileQuality = "C'est un installateur : son contenu s'ouvre avec 7-Zip (clic droit > 7-Zip > Ouvrir l'archive).";
            return;
        }
        if (Has("Inno Setup") || strings.Any(s => s.StartsWith("Inno Setup", StringComparison.Ordinal)))
        {
            r.Kind = "installer-inno"; r.KindLabel = "Installateur Inno Setup"; r.Language = "Installateur";
            r.DecompileQuality = "C'est un installateur : son contenu s'extrait avec « innoextract » ou « innounp ».";
            return;
        }
        if (r.Pe.OverlayType == "zip") { r.Kind = "sfx-zip"; r.KindLabel = "Archive ZIP auto-extractible"; r.Language = "Archive"; r.DecompileQuality = "Le contenu de l'archive est extrait."; return; }
        if (r.Pe.OverlayType == "7z") { r.Kind = "sfx-7z"; r.KindLabel = "Archive 7-Zip auto-extractible"; r.Language = "Archive"; r.DecompileQuality = "Ouvrez-le avec 7-Zip pour voir son contenu."; return; }
        if (Has("NUITKA") || Has("nuitka") || Has("__nuitka"))
        {
            r.Kind = "nuitka"; r.KindLabel = "Programme Python compilé avec Nuitka"; r.Language = "Python → C";
            r.DecompileQuality = "Limitée : Nuitka transforme le Python en C, le code Python d'origine n'existe plus dans le fichier.";
            return;
        }
        if (Has("Go build ID:") || Has("runtime.goexit") || Has("go.buildid"))
        {
            r.Kind = "go"; r.KindLabel = "Programme natif écrit en Go"; r.Language = "Go";
            r.DecompileQuality = "Limitée : assembleur intégré + pseudo-C avec Ghidra. Les noms des fonctions Go sont souvent conservés.";
            return;
        }
        if (Has("rustc/") || Has("/rustc/") || Has("RUST_BACKTRACE"))
        {
            r.Kind = "rust"; r.KindLabel = "Programme natif écrit en Rust"; r.Language = "Rust";
            r.DecompileQuality = "Limitée : assembleur intégré + pseudo-C avec Ghidra.";
            return;
        }
        if (HasImport("MSVBVM60.DLL") || HasImport("MSVBVM50.DLL"))
        {
            r.Kind = "vb6"; r.KindLabel = "Programme Visual Basic 6"; r.Language = "Visual Basic 6";
            r.DecompileQuality = "Partielle : un outil spécialisé (VB Decompiler) récupère les formulaires et une partie du code.";
            return;
        }
        if (Has("Embarcadero") || Has("Borland") || (Has("TObject") && Has("SysUtils")))
        {
            r.Kind = "delphi"; r.KindLabel = "Programme natif écrit en Delphi"; r.Language = "Delphi (Pascal)";
            r.DecompileQuality = "Limitée : assembleur + pseudo-C. Un outil spécialisé (IDR) retrouve les formulaires et noms de fonctions.";
            return;
        }
        r.Kind = "native";
        string lang = "C / C++";
        if (Has("Mingw-w64 runtime failure") || Has("GCC: (")) { lang = "C / C++ (MinGW / GCC)"; }
        else if (r.Pe.HasRichHeader || r.Pe.Imports.Any(i => i.Dll.StartsWith("VCRUNTIME", StringComparison.OrdinalIgnoreCase) || i.Dll.StartsWith("MSVCP", StringComparison.OrdinalIgnoreCase))) lang = "C / C++ (Visual Studio)";
        if (Has("electron") && Has("app.asar")) { r.KindDetails.Add("Ressemble à une application Electron : le code JavaScript est dans « resources\\app.asar » à côté du .exe, pas dans le .exe."); lang = "JavaScript (Electron)"; }
        r.KindLabel = "Programme natif (" + lang + ")";
        r.Language = lang;
        r.DecompileQuality = "Limitée : un programme natif ne contient plus son code source. Loupe donne l'assembleur ; Ghidra (gratuit) peut reconstruire un pseudo-code C approximatif.";
    }

    // ================= .NET =================
    static void ScanMeta(DotNetExtractor.MetaInfo meta, Scanner scanner, string label)
    {
        scanner.AddLines("Fonctions .NET utilisées" + label, meta.ApiNames.Distinct());
        scanner.AddLines("Textes du code .NET" + label, meta.UserStrings.Select(s => s.Replace('\n', ' ').Replace('\r', ' ')));
    }

    static void DoDotNet(AnalysisResult r, byte[] data, string path, string codeDir, Scanner scanner, AnalyzeOptions opt, Action<int, string> P, CancellationToken ct)
    {
        P(22, "Lecture des métadonnées .NET");
        var meta = DotNetExtractor.ReadMetadata(data);
        NoteMeta(r, meta);
        ScanMeta(meta, scanner, "");
        if (!opt.Decompile) return;
        P(30, "Décompilation en C# (peut prendre une minute)");
        var res = DotNetExtractor.Decompile(Path.GetFileName(path), data, codeDir, ct, Path.GetDirectoryName(path));
        if (res.Ok) r.Notes.Add($"Décompilé en C# : {res.Files} fichiers .cs dans « code-source ».");
        else r.Warnings.Add("La décompilation C# a échoué : " + res.Error);
    }

    static void NoteMeta(AnalysisResult r, DotNetExtractor.MetaInfo meta)
    {
        if (meta.AssemblyName != "") r.KindDetails.Add("Assembly : " + meta.AssemblyName);
        r.KindDetails.Add($"{meta.TypeCount} classes, {meta.MethodCount} méthodes");
        if (meta.References.Any(x => x.StartsWith("Microsoft.VisualBasic"))) { r.Language = "VB.NET (retraduit en C#)"; }
        if (meta.References.Any(x => x.StartsWith("FSharp.Core"))) { r.Language = "F# (retraduit en C#)"; }
        if (meta.References.Any(x => x.StartsWith("PresentationFramework"))) r.KindDetails.Add("Interface WPF");
        if (meta.References.Any(x => x.StartsWith("System.Windows.Forms"))) r.KindDetails.Add("Interface Windows Forms");
        if (meta.References.Any(x => x.Contains("WebView2"))) r.KindDetails.Add("Interface web (WebView2)");
        if (meta.ResourceNames.Count > 0) r.KindDetails.Add(meta.ResourceNames.Count + " ressources intégrées");
        if (meta.Obfuscator != null)
        {
            r.KindDetails.Add("Obfusqué avec " + meta.Obfuscator);
            r.Indicators.Add(ObfIndicator("Le code est brouillé avec " + meta.Obfuscator + " : les noms sont rendus illisibles pour empêcher de comprendre le programme."));
        }
        else if (meta.TypeCount + meta.MethodCount > 20 && meta.UnreadableNames > (meta.TypeCount + meta.MethodCount) / 5)
            r.Indicators.Add(ObfIndicator("Une grande partie des noms de classes et de méthodes est illisible : le code a été volontairement brouillé."));
    }

    static Indicator ObfIndicator(string expl) => new()
    {
        Id = "obfuscated", Severity = Severity.Moyen, Weight = 10, Category = "Dissimulation", Title = "Code .NET obfusqué",
        Explanation = expl + " C'est utilisé contre le piratage, mais aussi par presque tous les malwares .NET.",
    };

    static void DoBundle(AnalysisResult r, byte[] data, string path, string outDir, string codeDir, Scanner scanner, AnalyzeOptions opt, Action<int, string> P, CancellationToken ct)
    {
        if (!DotNetExtractor.TryGetBundle(path, out var header)) return;
        var dir = Path.Combine(outDir, "fichiers-integres");
        var userAsm = new List<(string Name, byte[] Bytes)>();
        P(22, "Extraction des fichiers intégrés");
        foreach (var e in header.Entries)
        {
            ct.ThrowIfCancellationRequested();
            byte[] bytes;
            try { bytes = DotNetExtractor.ReadBundleEntry(data, e); }
            catch (Exception ex) { r.Warnings.Add("Fichier intégré illisible : " + e.RelativePath + " (" + ex.Message + ")"); continue; }
            Util.WriteFile(Util.SafeJoin(dir, e.RelativePath), bytes);
            if (e.Type == ICSharpCode.Decompiler.SingleFileBundle.FileType.Assembly && !DotNetExtractor.IsFrameworkAssembly(e.RelativePath, bytes))
                userAsm.Add((e.RelativePath, bytes));
            if (e.Type is ICSharpCode.Decompiler.SingleFileBundle.FileType.DepsJson or ICSharpCode.Decompiler.SingleFileBundle.FileType.RuntimeConfigJson)
                scanner.Add(e.RelativePath, Encoding.UTF8.GetString(bytes));
        }
        r.Notes.Add($"{header.Entries.Length} fichiers intégrés extraits dans « fichiers-integres » ({userAsm.Count} DLL propres au programme).");
        // textes du lanceur natif (avant le premier fichier intégré) et des DLL propres au programme
        // le lanceur (« apphost ») est fourni par Microsoft et contient tout le moteur .NET : il n'est pas examiné
        foreach (var (n, b) in userAsm) scanner.AddLines("Textes de " + n, StringsExtractor.Extract(b));

        int i = 0;
        var main = Path.GetFileNameWithoutExtension(path);
        foreach (var (name, bytes) in userAsm.OrderByDescending(a => Path.GetFileNameWithoutExtension(a.Name).Equals(main, StringComparison.OrdinalIgnoreCase)).Take(12))
        {
            ct.ThrowIfCancellationRequested();
            var meta = DotNetExtractor.ReadMetadata(bytes);
            if (i == 0) NoteMeta(r, meta);
            ScanMeta(meta, scanner, " (" + name + ")");
            if (!opt.Decompile) { i++; continue; }
            P(30 + i * 4, "Décompilation de " + name);
            var res = DotNetExtractor.Decompile(name, bytes, Path.Combine(codeDir, Util.SafeName(Path.GetFileNameWithoutExtension(name))), ct, dir);
            if (res.Ok) r.Notes.Add($"{name} décompilé : {res.Files} fichiers .cs.");
            else r.Warnings.Add($"Décompilation de {name} impossible : {res.Error}");
            i++;
        }
        if (userAsm.Count > 12) r.Notes.Add("Seules les 12 premières DLL ont été décompilées ; les autres sont dans « fichiers-integres ».");
    }

    // ================= Python =================
    static readonly HashSet<string> CommonPyPackages = new(StringComparer.OrdinalIgnoreCase)
    {
        "abc","argparse","ast","asyncio","base64","bisect","bz2","calendar","codecs","collections","concurrent","configparser","contextlib","copy","csv","ctypes",
        "dataclasses","datetime","decimal","difflib","dis","email","encodings","enum","fnmatch","fractions","ftplib","functools","getopt","gettext","glob","gzip",
        "hashlib","heapq","hmac","html","http","imaplib","importlib","inspect","io","ipaddress","itertools","json","keyword","linecache","locale","logging","lzma",
        "mailbox","mimetypes","multiprocessing","numbers","opcode","operator","optparse","os","pathlib","pickle","pkgutil","platform","plistlib","poplib","posixpath",
        "pprint","py_compile","queue","quopri","random","re","reprlib","runpy","sched","secrets","selectors","shlex","shutil","signal","site","smtplib","socket",
        "socketserver","sqlite3","ssl","stat","statistics","string","stringprep","struct","subprocess","sysconfig","tarfile","tempfile","textwrap","threading","token",
        "tokenize","traceback","tracemalloc","tkinter","types","typing","unittest","urllib","uu","uuid","warnings","weakref","webbrowser","xml","xmlrpc","zipfile",
        "zipimport","zoneinfo","ntpath","genericpath","nturl2path","_pyi_rth_utils","pyimod01_archive","pyimod02_importers","pyimod03_ctypes","pyimod04_pywin32",
        "_strptime","_threading_local","_weakrefset","_collections_abc","_compat_pickle","_compression","_markupbase","_osx_support","_py_abc","_pydecimal","_pyio",
        "_sitebuiltins","__future__","colorsys","contextvars","copyreg","cProfile","pstats","profile","timeit","trace","wave","chunk","imghdr","sndhdr","netrc",
        "pdb","bdb","cmd","code","codeop","doctest","pydoc","pydoc_data","lib2to3","distutils","setuptools","pkg_resources","pip","wheel","_distutils_hack",
        "certifi","charset_normalizer","idna","urllib3","requests","chardet","six","typing_extensions","attr","attrs","yaml","dateutil","pytz","numpy","pandas",
        "PIL","cryptography","cffi","pycparser","win32com","win32","pythoncom","pywintypes","psutil","packaging","jaraco","more_itertools","zipp","importlib_metadata",
        "colorama","tqdm","websocket","websockets","aiohttp","multidict","yarl","async_timeout","frozenlist","aiosignal","pygame","PyQt5","PyQt6","PySide2","PySide6",
        "customtkinter","darkdetect","matplotlib","cv2","scipy","sklearn","Crypto","Cryptodome","nacl","OpenSSL","bs4","soupsieve","lxml","selenium","pynput","keyboard","mouse",
        "pyautogui","pyscreeze","pymsgbox","pytweening","mouseinfo","pygetwindow","pyrect","pyperclip","discord","telebot","telegram","httpx","httpcore","anyio","sniffio","h11",
        "rich","pygments","markdown_it","mdurl","click","flask","werkzeug","jinja2","markupsafe","itsdangerous","_cffi_backend","google","grpc","proto","comtypes","wmi",
    };

    static void DoPython(AnalysisResult r, byte[] data, string outDir, string codeDir, Scanner scanner, AnalyzeOptions opt, Action<int, string> P, CancellationToken ct)
    {
        P(25, "Extraction de l'archive PyInstaller");
        var py = PyInstallerExtractor.Extract(data, outDir, ct);
        if (!py.Found) return;
        r.Language = "Python " + py.PythonVersion;
        r.KindDetails.Add("Python " + py.PythonVersion);
        r.KindDetails.Add(py.EntryScripts.Count + " script(s) principal(aux), " + py.Modules.Count + " modules");
        r.Notes.Add($"{py.Extracted} fichiers extraits dans « python-extrait ». Les scripts du développeur sont dans « python-extrait/scripts-principaux ».");
        r.Notes.AddRange(py.Notes);
        if (py.Encrypted) r.KindDetails.Add("Modules chiffrés");

        // fichiers à examiner : scripts principaux + modules qui ne viennent pas de Python lui-même ou d'une bibliothèque connue
        var userModules = py.PycFiles.Where(f =>
        {
            if (py.EntryScripts.Contains(f)) return true;
            var rel = Path.GetRelativePath(Path.Combine(outDir, "python-extrait"), f).Replace('\\', '/');
            if (!rel.StartsWith("modules/")) return false;
            var top = rel["modules/".Length..].Split('/')[0];
            top = Path.GetFileNameWithoutExtension(top);
            return !CommonPyPackages.Contains(top) && !top.StartsWith("_");
        }).Take(400).ToList();
        foreach (var f in userModules)
        {
            var name = Path.GetRelativePath(outDir, f);
            scanner.AddLines("Textes de " + name, StringsExtractor.Extract(File.ReadAllBytes(f), 4));
        }
        r.KindDetails.Add(userModules.Count + " fichier(s) de code propre(s) au programme");

        var pycdc = FindTool(opt.ToolsDir, "pycdc");
        if (pycdc == null)
        {
            P(45, "Désassemblage du bytecode Python");
            int nd = DisassemblePython(py.PythonVersion, userModules, Path.Combine(outDir, "python-extrait"), codeDir, ct);
            if (nd > 0)
            {
                r.Notes.Add($"{nd} fichier(s) .pyc désassemblé(s) avec Python {py.PythonVersion} dans « code-source » (instructions Python, pas encore du code Python normal).");
                r.Notes.Add("Pour retraduire les .pyc en vrai code Python, placez « pycdc.exe » dans le dossier « outils » à côté de Loupe.");
            }
            else r.Notes.Add($"Pour lire le code : installez Python {py.PythonVersion} (python.org) pour obtenir le désassemblage, ou placez « pycdc.exe » dans le dossier « outils » à côté de Loupe pour retrouver le code Python.");
            return;
        }
        int ok = 0, n = 0;
        foreach (var f in userModules)
        {
            ct.ThrowIfCancellationRequested();
            P(40 + (int)(35.0 * n++ / Math.Max(1, userModules.Count)), "Retraduction en Python : " + Path.GetFileName(f));
            var rel = Path.GetRelativePath(Path.Combine(outDir, "python-extrait"), f);
            rel = rel.StartsWith("scripts-principaux") ? rel["scripts-principaux".Length..].TrimStart('/', '\\') : rel["modules".Length..].TrimStart('/', '\\');
            var target = Util.SafeJoin(codeDir, Path.ChangeExtension(rel, ".py"));
            var (code, outText, err) = RunTool(pycdc, new[] { f }, 30, ct);
            if (outText.Length > 0)
            {
                Directory.CreateDirectory(Path.GetDirectoryName(target)!);
                File.WriteAllText(target, outText + (err.Length > 0 ? "\n# --- pycdc : " + err.Replace("\n", "\n# ") : ""), new UTF8Encoding(false));
                ok++;
            }
        }
        r.Notes.Add($"{ok} fichier(s) retraduit(s) en Python dans « code-source » (pycdc). Certaines parties peuvent être incomplètes avec les versions récentes de Python.");
    }

    const string DisScript = """
        import sys, marshal, dis, io
        want = tuple(int(x) for x in sys.argv[1].split("."))
        if sys.version_info[:2] != want:
            sys.exit(3)
        hdr = 16 if want >= (3, 7) else (12 if want >= (3, 3) else 8)
        lines = open(sys.argv[2], encoding="utf-8").read().splitlines()
        ok = 0
        for i in range(0, len(lines) - 1, 2):
            src, dst = lines[i], lines[i + 1]
            try:
                code = marshal.loads(open(src, "rb").read()[hdr:])
                out = io.StringIO()
                out.write("# Désassemblage du bytecode Python (Python %d.%d)\n" % want)
                out.write("# Chaque bloc correspond à une fonction ; LOAD_CONST / LOAD_GLOBAL / CALL montrent les valeurs et les appels.\n\n")
                dis.dis(code, file=out)
                open(dst, "w", encoding="utf-8").write(out.getvalue())
                ok += 1
            except Exception as e:
                open(dst, "w", encoding="utf-8").write("# Désassemblage impossible : %r\n" % (e,))
        print("LOUPE_OK", ok)
        """;

    /// <summary>Désassemble les .pyc avec un Python installé de la même version (marshal.loads ne lance pas le code).</summary>
    static int DisassemblePython(string version, List<string> files, string pyRoot, string codeDir, CancellationToken ct)
    {
        if (files.Count == 0) return 0;
        var parts = version.Split('.');
        var candidates = new List<string[]>();
        if (OperatingSystem.IsWindows())
        {
            candidates.Add(new[] { "py", "-" + version });
            candidates.Add(new[] { "python" });
            candidates.Add(new[] { "python3" });
            var local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            var pf = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
            foreach (var d in new[] { Path.Combine(local, "Programs", "Python", "Python" + parts[0] + parts[1], "python.exe"), Path.Combine(pf, "Python" + parts[0] + parts[1], "python.exe") })
                if (File.Exists(d)) candidates.Insert(0, new[] { d });
        }
        else
        {
            candidates.Add(new[] { "python" + version });
            candidates.Add(new[] { "python3" });
        }
        var work = Path.Combine(Path.GetTempPath(), "loupe-py-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(work);
        try
        {
            var script = Path.Combine(work, "loupe_dis.py");
            File.WriteAllText(script, DisScript, new UTF8Encoding(false));
            var list = new StringBuilder();
            foreach (var f in files)
            {
                var rel = Path.GetRelativePath(pyRoot, f);
                rel = rel.StartsWith("scripts-principaux") ? rel["scripts-principaux".Length..].TrimStart('/', '\\') : rel.StartsWith("modules") ? rel["modules".Length..].TrimStart('/', '\\') : rel;
                var target = Util.SafeJoin(codeDir, Path.ChangeExtension(rel, null) + ".dis.txt");
                Directory.CreateDirectory(Path.GetDirectoryName(target)!);
                list.Append(f).Append('\n').Append(target).Append('\n');
            }
            var listFile = Path.Combine(work, "liste.txt");
            File.WriteAllText(listFile, list.ToString(), new UTF8Encoding(false));
            foreach (var c in candidates)
            {
                ct.ThrowIfCancellationRequested();
                try
                {
                    var args = c.Skip(1).Concat(new[] { "-I", script, version, listFile }).ToArray();
                    var (code, o, _) = RunTool(c[0], args, 180, ct);
                    var m = System.Text.RegularExpressions.Regex.Match(o, @"LOUPE_OK (\d+)");
                    if (code == 0 && m.Success) return int.Parse(m.Groups[1].Value);
                }
                catch (System.ComponentModel.Win32Exception) { /* pas installé */ }
            }
            return 0;
        }
        finally { try { Directory.Delete(work, true); } catch { } }
    }

    // ================= UPX / natif =================
    static void DoUpx(AnalysisResult r, byte[] data, string path, string outDir, string codeDir, Scanner scanner, AnalyzeOptions opt, Action<int, string> P, CancellationToken ct)
    {
        var upx = FindTool(opt.ToolsDir, "upx");
        if (upx == null)
        {
            r.Notes.Add("Programme compressé avec UPX. Placez « upx.exe » dans le dossier « outils » pour que Loupe le décompresse et l'analyse en entier.");
            return;
        }
        P(25, "Décompression UPX");
        var dir = Path.Combine(outDir, "decompresse");
        Directory.CreateDirectory(dir);
        var tmpIn = Path.Combine(dir, "original.tmp");
        var tmpOut = Path.Combine(dir, Path.GetFileName(path) + ".decompresse.bin");
        File.Copy(path, tmpIn, true);
        var (code, o, e) = RunTool(upx, new[] { "-d", "-q", "-o", tmpOut, tmpIn }, 120, ct);
        try { File.Delete(tmpIn); } catch { }
        if (!File.Exists(tmpOut)) { r.Warnings.Add("UPX n'a pas pu décompresser le fichier (il a peut-être été modifié pour l'empêcher) : " + (e + o).Trim()); return; }
        var unpacked = File.ReadAllBytes(tmpOut);
        var pe2 = new PeFile(unpacked);
        r.Notes.Add("Décompressé avec UPX : « decompresse/" + Path.GetFileName(tmpOut) + " ».");
        scanner.AddLines("Textes du programme décompressé", StringsExtractor.Extract(unpacked));
        if (pe2.Valid)
        {
            var imps = pe2.ReadImports();
            scanner.AddLines("Fonctions importées (décompressé)", imps.SelectMany(i => i.Funcs.Select(f => i.Dll + "!" + f)).Concat(imps.SelectMany(i => i.Funcs)));
            r.Pe.Imports = imps.Select(i => new ImportDll { Dll = i.Dll, Functions = i.Funcs }).ToList();
            if (pe2.IsDotNet) { r.Kind = "dotnet"; DoDotNet(r, unpacked, tmpOut, codeDir, scanner, opt, P, ct); return; }
            DoNative(r, pe2, tmpOut, outDir, codeDir, opt, P, ct);
        }
    }

    static void DoNative(AnalysisResult r, PeFile pe, string path, string outDir, string codeDir, AnalyzeOptions opt, Action<int, string> P, CancellationToken ct)
    {
        P(30, "Désassemblage du point d'entrée");
        var asm = NativeExtractor.DisassembleEntry(pe);
        if (asm.Length > 0)
        {
            var asmDir = Path.Combine(outDir, "assembleur");
            Directory.CreateDirectory(asmDir);
            File.WriteAllText(Path.Combine(asmDir, "point-entree.asm"), asm, new UTF8Encoding(false));
            r.Notes.Add("Assembleur du point d'entrée dans « assembleur/point-entree.asm ».");
        }
        if (!opt.Decompile) return;
        var headless = NativeExtractor.FindGhidraHeadless(opt.GhidraDir);
        if (headless == null)
        {
            r.Notes.Add("Pour obtenir du pseudo-code C, installez Ghidra (gratuit, ghidra-sre.org) puis indiquez son dossier dans les réglages de Loupe.");
            return;
        }
        P(35, "Ghidra reconstruit le pseudo-C (plusieurs minutes possibles)");
        Directory.CreateDirectory(codeDir);
        var outFile = Path.Combine(codeDir, "pseudo-code.c");
        var (ok, msg) = NativeExtractor.RunGhidra(headless, path, outFile, opt.GhidraTimeoutSeconds, ct, l => P(50, "Ghidra : " + Util.Truncate(l, 80)));
        if (ok) r.Notes.Add("Pseudo-code C généré par Ghidra dans « code-source/pseudo-code.c ».");
        else r.Warnings.Add("Ghidra : " + msg);
    }

    static void DoZipOverlay(AnalysisResult r, byte[] data, PeFile pe, string outDir, CancellationToken ct)
    {
        var (off, size) = pe.Overlay;
        if (size <= 0) return;
        var dir = Path.Combine(outDir, "contenu-archive");
        try
        {
            using var zip = new ZipArchive(new MemoryStream(data, (int)off, (int)size), ZipArchiveMode.Read);
            long total = 0; int n = 0;
            foreach (var e in zip.Entries)
            {
                ct.ThrowIfCancellationRequested();
                if (e.FullName.EndsWith('/')) continue;
                total += e.Length;
                if (total > 2L * 1024 * 1024 * 1024 || n > 20000) { r.Warnings.Add("Archive trop grosse : extraction arrêtée."); break; }
                var target = Util.SafeJoin(dir, e.FullName);
                Directory.CreateDirectory(Path.GetDirectoryName(target)!);
                e.ExtractToFile(target, true);
                n++;
            }
            r.Notes.Add($"{n} fichiers extraits de l'archive dans « contenu-archive ».");
        }
        catch (Exception ex) { r.Warnings.Add("Archive ZIP illisible : " + ex.Message); }
    }

    // ================= ressources & overlay =================
    static bool DumpResources(AnalysisResult r, PeFile pe, List<PeFile.RawResource> resources, string outDir)
    {
        bool embeddedExe = false;
        var dir = Path.Combine(outDir, "ressources");
        int n = 0;
        foreach (var x in resources)
        {
            if (x.Size == 0 || n > 3000) continue;
            var span = pe.Data.AsSpan((int)x.Offset, (int)x.Size);
            var kind = Util.Sniff(span);
            if (kind == "exe" && x.Type != "ICON") embeddedExe = true;
            string ext = x.Type switch
            {
                "MANIFEST" => ".xml", "HTML" => ".html", "ICON" => ".ico-brut", "BITMAP" => ".bmp-brut", "VERSION" => ".bin", "STRING" => ".bin",
                _ => kind switch { "" => ".bin", "txt" or "txt-utf16" => ".txt", "exe" => ".exe", _ => "." + kind },
            };
            var name = Util.SafeName(x.Type) + "/" + Util.SafeName(x.Name.TrimStart('#')) + (x.Lang != 0 ? "_" + x.Lang : "") + ext;
            try { Util.WriteFile(Util.SafeJoin(dir, name), span); n++; } catch { }
        }
        if (n > 0) r.Notes.Add($"{n} ressources Windows extraites dans « ressources ».");
        return embeddedExe;
    }

    static bool DumpOverlay(AnalysisResult r, PeFile pe, string outDir)
    {
        var (off, size) = pe.Overlay;
        if (size <= 0 || r.Kind is "pyinstaller" or "dotnet-bundle") return false;
        var span = pe.Data.AsSpan((int)off, (int)size);
        var kind = Util.Sniff(span);
        var name = "donnees-ajoutees" + (kind == "" ? ".bin" : kind == "exe" ? ".exe" : "." + kind);
        try { Util.WriteFile(Util.SafeJoin(Path.Combine(outDir, "donnees-ajoutees"), name), span); } catch { }
        r.Notes.Add($"{Util.HumanSize(size)} de données ajoutées après la fin du programme (« overlay »){(kind != "" ? ", type : " + kind : "")}.");
        return kind == "exe";
    }

    static void DefangTree(string root)
    {
        foreach (var f in Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories).ToList())
        {
            var name = Path.GetFileName(f);
            var safe = Util.Defang(name);
            if (safe == name) continue;
            var target = Path.Combine(Path.GetDirectoryName(f)!, safe);
            try { if (File.Exists(target)) File.Delete(target); File.Move(f, target); } catch { }
        }
    }

    static readonly HashSet<string> TextExt = new(StringComparer.OrdinalIgnoreCase)
    {
        ".cs", ".vb", ".fs", ".py", ".js", ".ts", ".json", ".xml", ".html", ".htm", ".css", ".txt", ".config", ".ini", ".ps1", ".psm1", ".bat", ".cmd",
        ".vbs", ".resx", ".xaml", ".c", ".h", ".cpp", ".asm", ".au3", ".csproj", ".manifest", ".sql", ".yaml", ".yml", ".md", ".lua", ".reg", ".hta", ".wsf", ".sh",
    };

    static void ScanTextFiles(string outDir, Scanner scanner, CancellationToken ct)
    {
        long total = 0;
        foreach (var f in Directory.EnumerateFiles(outDir, "*", SearchOption.AllDirectories))
        {
            ct.ThrowIfCancellationRequested();
            var rel = Path.GetRelativePath(outDir, f).Replace('\\', '/');
            if (rel == "textes-trouves.txt" || rel.StartsWith("rapport.")) continue;
            Util.IsDefanged(f, out var ext);
            if (!TextExt.Contains(ext)) continue;
            var len = new FileInfo(f).Length;
            if (len > 8 * 1024 * 1024 || total > 300L * 1024 * 1024) continue;
            total += len;
            try { scanner.Add(rel, File.ReadAllText(f)); } catch { }
        }
    }

    // ================= indicateurs structurels =================
    static IEnumerable<Indicator> StructuralIndicators(AnalysisResult r, PeFile pe, byte[] data, bool embeddedExe)
    {
        var list = new List<Indicator>(r.Indicators); // ceux ajoutés pendant l'extraction (obfuscation)
        r.Indicators.Clear();
        if (!pe.Valid) return list;

        string[] packerNames = { ".vmp0", ".vmp1", ".themida", ".winlice", ".enigma1", ".enigma2", ".aspack", ".adata", ".petite", ".MPRESS1", ".MPRESS2", ".nsp0", ".nsp1", ".packed", ".boom", "PEC2", ".yP", "pebundle" };
        var packer = r.Pe.Sections.FirstOrDefault(s => packerNames.Any(n => s.Name.Equals(n, StringComparison.OrdinalIgnoreCase)));
        var hot = r.Pe.Sections.Where(s => s.Flags.Contains('X') && s.Entropy >= 7.2 && s.RawSize > 4096).ToList();
        if (r.Kind == "upx" || packer != null || hot.Count > 0)
        {
            string who = r.Kind == "upx" ? "UPX" : packer?.Name switch
            {
                ".vmp0" or ".vmp1" => "VMProtect", ".themida" or ".winlice" => "Themida / WinLicense", ".enigma1" or ".enigma2" => "Enigma Protector",
                ".aspack" or ".adata" => "ASPack", ".MPRESS1" or ".MPRESS2" => "MPRESS", ".petite" => "Petite", null => "", _ => packer.Name,
            };
            bool strongProtect = who is "VMProtect" or "Themida / WinLicense" or "Enigma Protector";
            list.Add(new Indicator
            {
                Id = "packed", Severity = Severity.Moyen, Weight = strongProtect ? 12 : 8, Category = "Dissimulation",
                Title = who != "" ? "Programme compressé / protégé (" + who + ")" : "Code compressé ou chiffré",
                Explanation = "Le code du programme est compressé ou chiffré, donc illisible tant qu'il ne tourne pas. Ça sert contre le piratage, mais c'est aussi la façon dont les malwares échappent aux antivirus."
                    + (strongProtect ? " " + who + " empêche aussi la décompilation." : ""),
                Evidence = hot.Select(s => new Evidence { Where = "Section " + s.Name, Text = "entropie " + s.Entropy.ToString("0.00") + " / 8 (au-delà de 7,2 = compressé ou chiffré)" })
                    .Concat(packer != null ? new[] { new Evidence { Where = "Section", Text = packer.Name } } : Array.Empty<Evidence>()).ToList(),
            });
        }

        if (!r.Pe.Signature.Present)
            list.Add(new Indicator
            {
                Id = "unsigned", Severity = Severity.Info, Weight = 1, Category = "Identité", Title = "Pas de signature numérique",
                Explanation = "Personne n'a signé ce programme avec un certificat : impossible de savoir qui l'a fait ni s'il a été modifié. Très courant pour les petits développeurs, mais les grands éditeurs signent toujours.",
            });
        else if (r.Pe.Signature.Status.StartsWith("invalide") || r.Pe.Signature.Status.Contains("révoqué"))
            list.Add(new Indicator
            {
                Id = "bad_signature", Severity = Severity.Eleve, Weight = 25, Category = "Identité", Title = "Signature numérique invalide",
                Explanation = "Le programme porte une signature, mais Windows la refuse (" + r.Pe.Signature.Status + "). Le fichier a peut-être été modifié après sa signature, ou la signature est volée/copiée.",
                Evidence = new() { new Evidence { Where = "Signataire", Text = r.Pe.Signature.Signer } },
            });

        if (pe.TimeDateStamp != 0)
        {
            var date = DateTimeOffset.FromUnixTimeSeconds(pe.TimeDateStamp).UtcDateTime;
            var age = DateTime.UtcNow - date;
            if (age.TotalDays >= 0 && age.TotalDays < 30)
                list.Add(new Indicator
                {
                    Id = "recent", Severity = Severity.Info, Weight = 1, Category = "Identité", Title = "Compilé très récemment",
                    Explanation = "Le programme a été fabriqué il y a " + Math.Max(0, (int)age.TotalDays) + " jour(s) (" + date.ToString("dd/MM/yyyy") + "). Les antivirus le connaissent donc peu. Ce n'est pas suspect en soi.",
                });
        }

        if (r.Pe.RequiresAdmin)
            list.Add(new Indicator
            {
                Id = "admin", Severity = Severity.Info, Weight = 1, Category = "Identité", Title = "Demande les droits administrateur",
                Explanation = "Le programme exige d'être lancé en administrateur : il pourra modifier tout le système.",
                Evidence = new() { new Evidence { Where = "Manifeste", Text = "requireAdministrator" } },
            });

        if (embeddedExe)
        {
            bool expected = r.Kind is "pyinstaller" or "installer-nsis" or "installer-inno" or "sfx-zip" or "sfx-7z" or "dotnet-bundle";
            list.Add(new Indicator
            {
                Id = "embedded_exe", Severity = expected ? Severity.Info : Severity.Moyen, Weight = expected ? 0 : 8, Category = "Dissimulation", Title = "Contient un autre programme",
                Explanation = expected
                    ? "Normal pour ce type de fichier (installateur / programme empaqueté)."
                    : "Un autre .exe ou .dll est caché dans les ressources ou à la fin du fichier. C'est le fonctionnement d'un « dropper » qui dépose un second programme.",
            });
        }

        if (r.Kind == "native" && r.Pe.Imports.Sum(i => i.Functions.Count) < 6)
            list.Add(new Indicator
            {
                Id = "few_imports", Severity = Severity.Moyen, Weight = 6, Category = "Dissimulation", Title = "Cache les fonctions Windows qu'il utilise",
                Explanation = "Le programme n'annonce presque aucune fonction Windows : il les cherche probablement au dernier moment pour cacher ce qu'il fait.",
            });

        return list;
    }

    // ================= score et verdict =================
    static void Score(AnalysisResult r)
    {
        int crit = r.Indicators.Count(i => i.Severity == Severity.Critique);
        int high = r.Indicators.Count(i => i.Severity == Severity.Eleve);
        int med = r.Indicators.Count(i => i.Severity == Severity.Moyen);
        r.Score = Math.Min(100, r.Indicators.Sum(i => i.Weight));
        if (crit > 0 || high >= 3)
        {
            r.VerdictLevel = "danger"; r.Verdict = "Très suspect";
            r.VerdictText = "Ce programme contient des comportements typiques des malwares. Ne le lancez pas. Si vous l'avez déjà lancé : changez vos mots de passe depuis un autre appareil et faites une analyse antivirus complète.";
            r.Score = Math.Max(r.Score, 80);
        }
        else if (high > 0)
        {
            r.VerdictLevel = "suspect"; r.Verdict = "Suspect";
            r.VerdictText = "Au moins un comportement dangereux a été trouvé. Il peut avoir une raison légitime, mais lisez les détails avant de lancer ce programme.";
            r.Score = Math.Max(r.Score, 55);
        }
        else if (med >= 3 || r.Score >= 25)
        {
            r.VerdictLevel = "attention"; r.Verdict = "À vérifier";
            r.VerdictText = "Rien de clairement malveillant, mais le programme a beaucoup de pouvoir sur le système ou utilise des techniques qu'emploient aussi les malwares. Faites-le seulement si vous avez confiance en son auteur.";
            r.Score = Math.Clamp(r.Score, 25, 54);
        }
        else
        {
            r.VerdictLevel = "ok"; r.Verdict = "Rien de suspect trouvé";
            r.VerdictText = "Aucun comportement dangereux n'a été repéré. Une analyse sans exécution ne garantit jamais 100 % : vérifiez aussi l'empreinte SHA-256 sur VirusTotal.";
            r.Score = Math.Min(r.Score, 24);
        }
    }

    // ================= divers =================
    static List<ExtractedFile> ListFiles(string root)
    {
        var list = new List<ExtractedFile>();
        foreach (var f in Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories))
        {
            var rel = Path.GetRelativePath(root, f).Replace('\\', '/');
            Util.IsDefanged(f, out var ext);
            list.Add(new ExtractedFile { Path = rel, Size = new FileInfo(f).Length, Kind = ext.TrimStart('.').ToLowerInvariant() });
            if (list.Count >= 50000) break;
        }
        return list.OrderBy(f => f.Path.Count(c => c == '/') == 0 ? 0 : 1).ThenBy(f => f.Path, StringComparer.OrdinalIgnoreCase).ToList();
    }

    public static string? FindTool(string? toolsDir, string name)
    {
        var dirs = new List<string>();
        if (!string.IsNullOrEmpty(toolsDir)) dirs.Add(toolsDir);
        dirs.Add(Path.Combine(AppContext.BaseDirectory, "outils"));
        dirs.Add(AppContext.BaseDirectory);
        foreach (var d in dirs)
            foreach (var n in new[] { name + ".exe", name })
            {
                var p = Path.Combine(d, n);
                if (File.Exists(p)) return p;
            }
        return null;
    }

    static (int Code, string Out, string Err) RunTool(string exe, string[] args, int timeoutSec, CancellationToken ct)
    {
        var psi = new ProcessStartInfo(exe)
        {
            UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true,
            StandardOutputEncoding = Encoding.UTF8, StandardErrorEncoding = Encoding.UTF8,
        };
        foreach (var a in args) psi.ArgumentList.Add(a);
        using var p = Process.Start(psi)!;
        var o = p.StandardOutput.ReadToEndAsync();
        var e = p.StandardError.ReadToEndAsync();
        if (!p.WaitForExit(timeoutSec * 1000) || ct.IsCancellationRequested)
        {
            try { p.Kill(true); } catch { }
            return (-1, o.IsCompleted ? o.Result : "", "délai dépassé");
        }
        p.WaitForExit();
        return (p.ExitCode, o.Result, e.Result);
    }

    static string ReadMe(AnalysisResult r) => $"""
        LOUPE {Version} - analyse de {r.FileName}
        Date : {r.AnalyzedAt}
        SHA-256 : {r.Hashes.Sha256}

        Verdict : {r.Verdict} (niveau de risque {r.Score}/100)
        {r.VerdictText}

        Type : {r.KindLabel}
        Qualité de la décompilation : {r.DecompileQuality}

        Contenu de ce dossier :
          rapport.html         le rapport complet, à ouvrir dans un navigateur
          rapport.json         le même rapport, pour les programmes
          textes-trouves.txt   tous les textes lisibles trouvés dans le fichier
          code-source/         le code décompilé (C#, Python, pseudo-C…)
          assembleur/          le code machine traduit en assembleur (programmes natifs)
          ressources/          les ressources Windows (icônes, manifeste, données…)
          python-extrait/      le contenu d'un programme PyInstaller
          fichiers-integres/   les fichiers d'un programme .NET « fichier unique »

        SÉCURITÉ : les fichiers extraits qui pourraient se lancer d'un double-clic ont été renommés
        (ex. « setup.exe » devient « setup.exe.bin », « script.js » devient « script.js.txt »).
        Ne les renommez pas pour les lancer.
        """;
}
