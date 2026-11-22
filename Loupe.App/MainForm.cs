using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Loupe.Core;
using Microsoft.Web.WebView2.Core;
using Microsoft.Web.WebView2.WinForms;
using Microsoft.Win32;

namespace Loupe.App;

/// <summary>Fenêtre principale : héberge l'interface HTML (WebView2) et fait le lien avec le moteur d'analyse.</summary>
sealed class MainForm : Form
{
    readonly WebView2 web = new() { Dock = DockStyle.Fill };
    readonly Settings settings = Settings.Load();
    readonly string? startFile;
    CancellationTokenSource? cts;
    AnalysisResult? current;
    bool pageLoaded, busy;

    public MainForm(string? file)
    {
        startFile = file;
        Text = "Loupe";
        Width = 1320; Height = 860;
        MinimumSize = new Size(900, 600);
        StartPosition = FormStartPosition.CenterScreen;
        BackColor = Color.FromArgb(12, 14, 19);
        try { Icon = Icon.ExtractAssociatedIcon(Application.ExecutablePath); } catch { }
        web.DefaultBackgroundColor = BackColor;
        Controls.Add(web);
        Load += async (_, _) => await InitAsync();
        FormClosing += (_, _) => cts?.Cancel();
    }

    // ---------- barre de titre sombre (Windows 10/11) ----------
    [DllImport("dwmapi.dll")] static extern int DwmSetWindowAttribute(IntPtr hwnd, int attr, ref int value, int size);

    protected override void OnHandleCreated(EventArgs e)
    {
        base.OnHandleCreated(e);
        try
        {
            using var k = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize");
            bool dark = k?.GetValue("AppsUseLightTheme") is int v && v == 0;
            if (!dark) BackColor = Color.FromArgb(243, 244, 247);
            int on = dark ? 1 : 0;
            if (DwmSetWindowAttribute(Handle, 20, ref on, 4) != 0) DwmSetWindowAttribute(Handle, 19, ref on, 4);
        }
        catch { }
    }

    async Task InitAsync()
    {
        try
        {
            var udf = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Loupe", "WebView2");
            var env = await CoreWebView2Environment.CreateAsync(null, udf);
            await web.EnsureCoreWebView2Async(env);
        }
        catch (WebView2RuntimeNotFoundException)
        {
            var r = MessageBox.Show(this,
                "Loupe a besoin de « Microsoft Edge WebView2 », un composant gratuit de Windows (déjà présent sur Windows 11).\n\nOuvrir la page de téléchargement de Microsoft ?",
                "Composant manquant", MessageBoxButtons.YesNo, MessageBoxIcon.Information);
            if (r == DialogResult.Yes) OpenUrl("https://go.microsoft.com/fwlink/p/?LinkId=2124703");
            Close();
            return;
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, "Impossible d'afficher l'interface : " + ex.Message, "Loupe", MessageBoxButtons.OK, MessageBoxIcon.Error);
            Close();
            return;
        }

        var cw = web.CoreWebView2;
        var s = cw.Settings;
#if DEBUG
        s.AreDevToolsEnabled = true;
#else
        s.AreDevToolsEnabled = false;
#endif
        s.IsStatusBarEnabled = false;
        s.AreBrowserAcceleratorKeysEnabled = false;
        s.IsPasswordAutosaveEnabled = false;
        s.IsGeneralAutofillEnabled = false;
        s.AreHostObjectsAllowed = false;
        s.IsWebMessageEnabled = true;
        s.IsZoomControlEnabled = true;

        // l'interface ne doit jamais naviguer ailleurs (ex. un fichier glissé à côté de la zone)
        cw.NavigationStarting += (_, e) => { if (pageLoaded) e.Cancel = true; };
        cw.NavigationCompleted += (_, _) => pageLoaded = true;
        cw.NewWindowRequested += (_, e) => e.Handled = true;
        cw.DownloadStarting += (_, e) => e.Cancel = true;
        cw.WebMessageReceived += OnWebMessage;
        cw.NavigateToString(LoadUi());
    }

    static string LoadUi()
    {
        using var st = typeof(MainForm).Assembly.GetManifestResourceStream("ui.index.html")!;
        using var rd = new StreamReader(st, Encoding.UTF8);
        return rd.ReadToEnd();
    }

    void Send(object msg)
    {
        try { web.CoreWebView2?.PostWebMessageAsJson(JsonSerializer.Serialize(msg, Analyzer.Json)); } catch { }
    }

    void Toast(string message, bool error = false) => Send(new { type = "toast", message, error });

    // ================= messages de l'interface =================
    void OnWebMessage(object? sender, CoreWebView2WebMessageReceivedEventArgs e)
    {
        string? str = null;
        try { str = e.TryGetWebMessageAsString(); } catch { }
        if (str == "drop")
        {
            var file = e.AdditionalObjects?.OfType<CoreWebView2File>().FirstOrDefault();
            if (file != null) _ = AnalyzeAsync(file.Path);
            return;
        }
        JsonNode? m;
        try { m = JsonNode.Parse(e.WebMessageAsJson); } catch { return; }
        if (m is not JsonObject o) return;
        string cmd = o["cmd"]?.GetValue<string>() ?? "";
        try { HandleCommand(cmd, o); }
        catch (Exception ex) { Toast("Erreur : " + ex.Message, true); }
    }

    void HandleCommand(string cmd, JsonObject o)
    {
        switch (cmd)
        {
            case "init":
                Send(new { type = "init", version = Analyzer.Version, settings = settings.ToUi(), recents = settings.Recents });
                if (startFile != null && current == null && !busy) _ = AnalyzeAsync(startFile);
                break;
            case "pick": Pick(); break;
            case "dropName": Toast("Glissez le fichier depuis l'explorateur Windows, ou utilisez « Choisir un fichier ».", true); break;
            case "cancel": cts?.Cancel(); break;
            case "readFile": ReadFile(o["path"]?.GetValue<string>() ?? ""); break;
            case "readStrings": ReadStrings(); break;
            case "openFolder": OpenFolder(o["path"]?.GetValue<string>()); break;
            case "openReport":
                if (current != null) OpenWithShell(Path.Combine(current.OutputDir, "rapport.html"));
                break;
            case "virustotal":
                if (current != null) OpenUrl("https://www.virustotal.com/gui/file/" + current.Hashes.Sha256);
                break;
            case "copy":
                var t = o["text"]?.GetValue<string>() ?? "";
                if (t.Length > 0) Clipboard.SetText(t);
                break;
            case "browseFolder":
                {
                    using var d = new FolderBrowserDialog { UseDescriptionForTitle = true, Description = "Choisir un dossier" };
                    var cur = o["current"]?.GetValue<string>();
                    if (!string.IsNullOrWhiteSpace(cur) && Directory.Exists(cur)) d.InitialDirectory = cur;
                    if (d.ShowDialog(this) == DialogResult.OK) Send(new { type = "folder", field = o["field"]?.GetValue<string>(), path = d.SelectedPath });
                    break;
                }
            case "saveSettings":
                if (o["settings"] is JsonObject so)
                {
                    settings.OutputRoot = so["outputRoot"]?.GetValue<string>() ?? "";
                    settings.GhidraDir = so["ghidraDir"]?.GetValue<string>() ?? "";
                    settings.ToolsDir = so["toolsDir"]?.GetValue<string>() ?? "";
                    settings.Decompile = so["decompile"]?.GetValue<bool>() ?? true;
                    settings.Save();
                    if (settings.GhidraDir != "" && NativeExtractor.FindGhidraHeadless(settings.GhidraDir) == null)
                        Toast("Ghidra introuvable dans ce dossier (il faut le dossier qui contient « support\\analyzeHeadless.bat »).", true);
                }
                break;
            case "openRecent": OpenRecent(o["index"]?.GetValue<int>() ?? -1); break;
            case "removeRecent":
                {
                    int i = o["index"]?.GetValue<int>() ?? -1;
                    if (i >= 0 && i < settings.Recents.Count) { settings.Recents.RemoveAt(i); settings.Save(); }
                    Send(new { type = "recents", recents = settings.Recents });
                    break;
                }
        }
    }

    void Pick()
    {
        if (busy) return;
        using var d = new OpenFileDialog
        {
            Title = "Choisir le programme à analyser (il ne sera pas lancé)",
            Filter = "Programmes (*.exe;*.dll;*.scr;*.com;*.sys;*.ocx;*.cpl;*.msi)|*.exe;*.dll;*.scr;*.com;*.sys;*.ocx;*.cpl;*.msi|Tous les fichiers (*.*)|*.*",
            CheckFileExists = true,
            DereferenceLinks = false,
        };
        if (d.ShowDialog(this) == DialogResult.OK) _ = AnalyzeAsync(d.FileName);
    }

    // ================= analyse =================
    async Task AnalyzeAsync(string path)
    {
        if (busy) return;
        if (!File.Exists(path)) { Toast(Directory.Exists(path) ? "C'est un dossier : choisissez un fichier." : "Fichier introuvable.", true); return; }
        busy = true;
        cts = new CancellationTokenSource();
        var root = string.IsNullOrWhiteSpace(settings.OutputRoot) ? Settings.DefaultOutputRoot : settings.OutputRoot;
        var outDir = Path.Combine(root, Util.SafeName(Path.GetFileNameWithoutExtension(path), 60) + "_" + DateTime.Now.ToString("yyyyMMdd-HHmmss"));
        var opt = new AnalyzeOptions
        {
            OutputDir = outDir,
            GhidraDir = settings.GhidraDir,
            ToolsDir = string.IsNullOrWhiteSpace(settings.ToolsDir) ? null : settings.ToolsDir,
            Decompile = settings.Decompile,
        };
        Send(new { type = "start", name = Path.GetFileName(path) });
        var progress = new Progress<Core.Progress>(p => Send(new { type = "progress", pct = p.Percent, step = p.Step }));
        try
        {
            var token = cts.Token;
            var r = await Task.Run(() => Analyzer.Run(path, opt, progress, token), token);
            current = r;
            settings.AddRecent(r);
            Send(new { type = "result", result = r });
            Send(new { type = "recents", recents = settings.Recents });
        }
        catch (OperationCanceledException)
        {
            Send(new { type = "cancelled" });
            try { if (Directory.Exists(outDir)) Directory.Delete(outDir, true); } catch { }
        }
        catch (Exception ex)
        {
            Send(new { type = "error", message = "L'analyse a échoué : " + ex.Message });
        }
        finally
        {
            busy = false;
            cts.Dispose(); cts = null;
        }
    }

    void OpenRecent(int i)
    {
        if (busy || i < 0 || i >= settings.Recents.Count) return;
        var rc = settings.Recents[i];
        var json = Path.Combine(rc.OutputDir, "rapport.json");
        if (!File.Exists(json))
        {
            settings.Recents.RemoveAt(i); settings.Save();
            Send(new { type = "recents", recents = settings.Recents });
            Toast("Le dossier de cette analyse a été supprimé ou déplacé.", true);
            return;
        }
        var r = JsonSerializer.Deserialize<AnalysisResult>(File.ReadAllText(json), Analyzer.Json);
        if (r == null) return;
        r.OutputDir = rc.OutputDir;
        current = r;
        Send(new { type = "result", result = r });
    }

    // ================= fichiers produits =================
    string? Resolve(string rel)
    {
        if (current == null) return null;
        var root = Path.GetFullPath(current.OutputDir);
        var full = Path.GetFullPath(Path.Combine(root, rel.Replace('/', Path.DirectorySeparatorChar)));
        return full.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase) ? full : null;
    }

    void ReadFile(string rel)
    {
        var full = Resolve(rel);
        if (full == null || !File.Exists(full)) { Send(new { type = "file", path = rel, error = "Fichier introuvable." }); return; }
        const int max = 2 * 1024 * 1024;
        long size = new FileInfo(full).Length;
        byte[] buf;
        using (var fs = new FileStream(full, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
        {
            buf = new byte[(int)Math.Min(size, max)];
            fs.ReadExactly(buf);
        }
        bool binary = LooksBinary(buf);
        string content;
        int shown = buf.Length;
        if (binary)
        {
            shown = Math.Min(buf.Length, 64 * 1024);
            content = HexDump(buf, shown);
        }
        else content = DecodeText(buf);
        Send(new { type = "file", path = rel, content, size, shown, truncated = size > max, binary });
    }

    static bool LooksBinary(byte[] b)
    {
        int n = Math.Min(b.Length, 8192);
        if (n >= 2 && (b[0] == 0xFF && b[1] == 0xFE || b[0] == 0xFE && b[1] == 0xFF)) return false;
        int bad = 0;
        for (int i = 0; i < n; i++) { if (b[i] == 0) return true; if (b[i] < 8) bad++; }
        return bad > n / 20;
    }

    static string DecodeText(byte[] b)
    {
        if (b.Length >= 2 && b[0] == 0xFF && b[1] == 0xFE) return Encoding.Unicode.GetString(b, 2, b.Length - 2);
        if (b.Length >= 2 && b[0] == 0xFE && b[1] == 0xFF) return Encoding.BigEndianUnicode.GetString(b, 2, b.Length - 2);
        try { return new UTF8Encoding(false, true).GetString(b).TrimStart('﻿'); }
        catch { return Encoding.Latin1.GetString(b); }
    }

    static string HexDump(byte[] b, int len)
    {
        var sb = new StringBuilder();
        for (int i = 0; i < len; i += 16)
        {
            sb.Append(i.ToString("X8")).Append("  ");
            for (int j = 0; j < 16; j++) sb.Append(i + j < len ? b[i + j].ToString("x2") + " " : "   ").Append(j == 7 ? " " : "");
            sb.Append(' ');
            for (int j = 0; j < 16 && i + j < len; j++) { byte c = b[i + j]; sb.Append(c >= 32 && c < 127 ? (char)c : '.'); }
            sb.Append('\n');
        }
        return sb.ToString();
    }

    void ReadStrings()
    {
        if (current == null) return;
        var p = Path.Combine(current.OutputDir, "textes-trouves.txt");
        var list = File.Exists(p) ? File.ReadLines(p).Take(400_000).ToList() : new List<string>();
        Send(new { type = "strings", list });
    }

    void OpenFolder(string? rel)
    {
        if (current == null) return;
        if (!string.IsNullOrEmpty(rel))
        {
            var full = Resolve(rel);
            if (full != null && File.Exists(full)) { Process.Start("explorer.exe", "/select,\"" + full + "\"")?.Dispose(); return; }
        }
        if (Directory.Exists(current.OutputDir)) Process.Start("explorer.exe", "\"" + current.OutputDir + "\"")?.Dispose();
    }

    static void OpenWithShell(string path)
    {
        if (!File.Exists(path)) return;
        Process.Start(new ProcessStartInfo(path) { UseShellExecute = true })?.Dispose();
    }

    static void OpenUrl(string url)
    {
        if (!url.StartsWith("https://", StringComparison.OrdinalIgnoreCase)) return;
        Process.Start(new ProcessStartInfo(url) { UseShellExecute = true })?.Dispose();
    }
}
