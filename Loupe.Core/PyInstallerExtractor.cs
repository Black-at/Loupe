using System.Buffers.Binary;
using System.IO.Compression;
using System.Text;

namespace Loupe.Core;

/// <summary>Extraction des programmes Python empaquetés avec PyInstaller (archive "CArchive" + "PYZ").</summary>
public static class PyInstallerExtractor
{
    static readonly byte[] Magic = { (byte)'M', (byte)'E', (byte)'I', 0x0C, 0x0B, 0x0A, 0x0B, 0x0E };

    public sealed class Result
    {
        public bool Found;
        public string PythonVersion = "";
        public List<string> EntryScripts = new();   // chemins des .pyc principaux (le code du développeur)
        public List<string> Modules = new();        // modules extraits du PYZ
        public List<string> PycFiles = new();
        public int Extracted;
        public bool Encrypted;
        public List<string> Notes = new();
    }

    public static bool IsPyInstaller(byte[] data) => PeFile.LastIndexOf(data, Magic) >= 0;

    public static Result Extract(byte[] data, string outDir, CancellationToken ct)
    {
        var r = new Result();
        int cookie = PeFile.LastIndexOf(data, Magic);
        if (cookie < 0) return r;
        r.Found = true;

        // Cookie : magic(8) lenPackage(4) tocOffset(4) tocLen(4) pyver(4) [pylibname(64) pour PyInstaller >= 2.1]
        bool v21 = cookie + 88 <= data.Length && LooksLikeLibName(data, cookie + 24);
        int cookieSize = v21 ? 88 : 24;
        uint lenPackage = BinaryPrimitives.ReadUInt32BigEndian(data.AsSpan(cookie + 8));
        uint tocOff = BinaryPrimitives.ReadUInt32BigEndian(data.AsSpan(cookie + 12));
        int tocLen = BinaryPrimitives.ReadInt32BigEndian(data.AsSpan(cookie + 16));
        int pyver = BinaryPrimitives.ReadInt32BigEndian(data.AsSpan(cookie + 20));
        int major = pyver >= 100 ? pyver / 100 : pyver / 10;
        int minor = pyver >= 100 ? pyver % 100 : pyver % 10;
        r.PythonVersion = major + "." + minor;

        long pkgStart = (long)cookie + cookieSize - lenPackage;
        if (pkgStart < 0) { r.Notes.Add("Archive PyInstaller abîmée (début introuvable)."); return r; }
        long toc = pkgStart + tocOff;

        byte[]? pycMagic = null;
        var scripts = new List<(string Name, byte[] Code)>();
        var root = Path.Combine(outDir, "python-extrait");
        Directory.CreateDirectory(root);

        long p = toc, end = toc + tocLen;
        while (p + 18 <= end && p + 18 <= data.Length)
        {
            ct.ThrowIfCancellationRequested();
            int entrySize = BinaryPrimitives.ReadInt32BigEndian(data.AsSpan((int)p));
            uint pos = BinaryPrimitives.ReadUInt32BigEndian(data.AsSpan((int)p + 4));
            uint csize = BinaryPrimitives.ReadUInt32BigEndian(data.AsSpan((int)p + 8));
            uint usize = BinaryPrimitives.ReadUInt32BigEndian(data.AsSpan((int)p + 12));
            byte compressed = data[p + 16];
            char type = (char)data[p + 17];
            if (entrySize < 18 || p + entrySize > data.Length) break;
            string name = Encoding.UTF8.GetString(data, (int)p + 18, entrySize - 18).TrimEnd('\0');
            p += entrySize;

            long dataPos = pkgStart + pos;
            if (dataPos < 0 || dataPos + csize > data.Length) continue;
            byte[] blob = data.AsSpan((int)dataPos, (int)csize).ToArray();
            if (compressed == 1)
            {
                try { blob = Zlib(blob, (int)Math.Min(usize, 512_000_000)); }
                catch { r.Notes.Add("Entrée illisible : " + name); continue; }
            }

            if (type == 's')
            {
                // script principal (code du développeur), sans en-tête .pyc
                scripts.Add((name, blob));
                continue;
            }
            if (type == 'z' || type == 'Z')
            {
                if (blob.Length > 8 && blob[0] == 'P' && blob[1] == 'Y' && blob[2] == 'Z' && blob[3] == 0)
                {
                    pycMagic ??= blob.AsSpan(4, 4).ToArray();
                    ExtractPyz(blob, Path.Combine(root, "modules"), r, ct);
                }
                Save(root, name, blob, r);
                continue;
            }
            if (type == 'm' || type == 'M')
            {
                // module déjà au format .pyc (avec en-tête)
                if (blob.Length >= 4) pycMagic ??= blob.AsSpan(0, 4).ToArray();
                var path = Save(root, name.EndsWith(".pyc") ? name : name + ".pyc", blob, r);
                r.PycFiles.Add(path);
                continue;
            }
            // binaires, DLL, données, options…
            if (type == 'o') continue;
            Save(root, name, blob, r);
        }

        pycMagic ??= GuessMagic(major, minor);
        foreach (var (name, code) in scripts)
        {
            var header = PycHeader(pycMagic, major, minor);
            var full = new byte[header.Length + code.Length];
            header.CopyTo(full, 0);
            code.CopyTo(full, header.Length);
            var path = Save(Path.Combine(root, "scripts-principaux"), name + ".pyc", full, r);
            bool internalBoot = name.StartsWith("pyi_rth_") || name.StartsWith("pyiboot") || name == "struct" || name.StartsWith("pyimod");
            if (!internalBoot) r.EntryScripts.Add(path);
            r.PycFiles.Add(path);
        }
        return r;
    }

    static bool LooksLikeLibName(byte[] d, int off)
    {
        // "python3X.dll" ou "libpython3.X.so"
        var s = Encoding.ASCII.GetString(d, off, 64).TrimEnd('\0');
        return s.Contains("python", StringComparison.OrdinalIgnoreCase);
    }

    static string Save(string root, string name, byte[] blob, Result r)
    {
        var path = Util.SafeJoin(root, name);
        Util.WriteFile(path, blob);
        r.Extracted++;
        return path;
    }

    static byte[] Zlib(byte[] blob, int expected)
    {
        using var ms = new MemoryStream(blob);
        using var z = new ZLibStream(ms, CompressionMode.Decompress);
        var o = new MemoryStream(Math.Max(16, expected));
        z.CopyTo(o);
        return o.ToArray();
    }

    static byte[] PycHeader(byte[] magic, int major, int minor)
    {
        if (major >= 3 && minor >= 7) { var h = new byte[16]; magic.CopyTo(h, 0); return h; }
        if (major >= 3 && minor >= 3) { var h = new byte[12]; magic.CopyTo(h, 0); return h; }
        { var h = new byte[8]; magic.CopyTo(h, 0); return h; }
    }

    static byte[] GuessMagic(int major, int minor)
    {
        // nombres magiques .pyc officiels (2 octets + \r\n)
        int n = (major, minor) switch
        {
            (3, 6) => 3379, (3, 7) => 3394, (3, 8) => 3413, (3, 9) => 3425, (3, 10) => 3439,
            (3, 11) => 3495, (3, 12) => 3531, (3, 13) => 3571, (3, 14) => 3627, (2, 7) => 62211, _ => 3531,
        };
        return new[] { (byte)(n & 0xFF), (byte)(n >> 8), (byte)'\r', (byte)'\n' };
    }

    static void ExtractPyz(byte[] pyz, string outDir, Result r, CancellationToken ct)
    {
        var magic = pyz.AsSpan(4, 4).ToArray();
        int tocPos = BinaryPrimitives.ReadInt32BigEndian(pyz.AsSpan(8));
        if (tocPos <= 0 || tocPos >= pyz.Length) return;
        object? toc;
        try { toc = new Marshal(pyz, tocPos).Read(); }
        catch (Exception ex) { r.Notes.Add("Table des modules PYZ illisible : " + ex.Message); return; }

        var entries = new List<(string, object?)>();
        if (toc is List<object?> list)
        {
            foreach (var it in list)
                if (it is List<object?> t && t.Count == 2 && t[0] is string n) entries.Add((n, t[1]));
        }
        else if (toc is Dictionary<object, object?> dict)
        {
            foreach (var kv in dict) if (kv.Key is string n) entries.Add((n, kv.Value));
        }
        foreach (var (name, val) in entries)
        {
            ct.ThrowIfCancellationRequested();
            if (val is not List<object?> v || v.Count < 3) continue;
            long ispkg = Convert.ToInt64(v[0]), pos = Convert.ToInt64(v[1]), len = Convert.ToInt64(v[2]);
            if (pos < 0 || len <= 0 || pos + len > pyz.Length) continue;
            var blob = pyz.AsSpan((int)pos, (int)len).ToArray();
            byte[] code;
            try { code = Zlib(blob, blob.Length * 3); }
            catch { r.Encrypted = true; continue; }
            var rel = name.Replace('.', '/') + (ispkg == 1 ? "/__init__" : "") + ".pyc";
            var header = magic.Length == 4 ? new byte[16] : new byte[16];
            magic.CopyTo(header, 0);
            var full = new byte[header.Length + code.Length];
            header.CopyTo(full, 0); code.CopyTo(full, header.Length);
            var path = Save(outDir, rel, full, r);
            r.Modules.Add(name);
            r.PycFiles.Add(path);
        }
        if (r.Encrypted) r.Notes.Add("Certains modules sont chiffrés (option --key de PyInstaller) : ils n'ont pas été extraits.");
    }

    /// <summary>Lecteur minimal du format "marshal" de Python, suffisant pour la table des modules PYZ.</summary>
    sealed class Marshal
    {
        readonly byte[] d; int p;
        readonly List<object?> refs = new();
        public Marshal(byte[] data, int pos) { d = data; p = pos; }

        int I32() { int v = BinaryPrimitives.ReadInt32LittleEndian(d.AsSpan(p)); p += 4; return v; }

        public object? Read(int depth = 0)
        {
            if (depth > 64 || p >= d.Length) throw new InvalidDataException("marshal");
            byte code = d[p++];
            bool flag = (code & 0x80) != 0;
            char t = (char)(code & 0x7F);
            int slot = -1;
            if (flag) { slot = refs.Count; refs.Add(null); }
            object? v;
            switch (t)
            {
                case '0': case 'N': v = null; break;
                case 'F': v = false; break;
                case 'T': v = true; break;
                case 'i': v = (long)I32(); break;
                case 'l':
                    {
                        int n = I32(); long val = 0; int shift = 0;
                        for (int i = 0; i < Math.Abs(n); i++) { val |= (long)BinaryPrimitives.ReadUInt16LittleEndian(d.AsSpan(p)) << shift; p += 2; shift += 15; }
                        v = n < 0 ? -val : val; break;
                    }
                case 's': case 't': case 'u':
                    { int n = I32(); v = Encoding.UTF8.GetString(d, p, n); p += n; break; }
                case 'a': case 'A':
                    { int n = I32(); v = Encoding.Latin1.GetString(d, p, n); p += n; break; }
                case 'z': case 'Z':
                    { int n = d[p++]; v = Encoding.Latin1.GetString(d, p, n); p += n; break; }
                case ')':
                    { int n = d[p++]; var l = new List<object?>(n); if (slot >= 0) refs[slot] = l; for (int i = 0; i < n; i++) l.Add(Read(depth + 1)); v = l; break; }
                case '(': case '[':
                    { int n = I32(); if (n < 0 || n > 1_000_000) throw new InvalidDataException("taille"); var l = new List<object?>(Math.Min(n, 4096)); if (slot >= 0) refs[slot] = l; for (int i = 0; i < n; i++) l.Add(Read(depth + 1)); v = l; break; }
                case '{':
                    {
                        var dict = new Dictionary<object, object?>(); if (slot >= 0) refs[slot] = dict;
                        while (p < d.Length && d[p] != (byte)'0') { var k = Read(depth + 1); var val = Read(depth + 1); if (k != null) dict[k] = val; }
                        p++; v = dict; break;
                    }
                case 'r':
                    { int i = I32(); v = i >= 0 && i < refs.Count ? refs[i] : null; break; }
                default: throw new InvalidDataException("type marshal non géré : " + t);
            }
            if (slot >= 0 && t != ')' && t != '(' && t != '[' && t != '{') refs[slot] = v;
            return v;
        }
    }
}
