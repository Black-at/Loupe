using System.Security.Cryptography;
using System.Text;

namespace Loupe.Core;

public static class Util
{
    public static double Entropy(ReadOnlySpan<byte> data)
    {
        if (data.Length == 0) return 0;
        Span<int> counts = stackalloc int[256];
        foreach (var b in data) counts[b]++;
        double e = 0, n = data.Length;
        foreach (var c in counts)
        {
            if (c == 0) continue;
            double p = c / n;
            e -= p * Math.Log2(p);
        }
        return Math.Round(e, 2);
    }

    public static Hashes ComputeHashes(byte[] data) => new()
    {
        Md5 = Convert.ToHexString(MD5.HashData(data)).ToLowerInvariant(),
        Sha1 = Convert.ToHexString(SHA1.HashData(data)).ToLowerInvariant(),
        Sha256 = Convert.ToHexString(SHA256.HashData(data)).ToLowerInvariant(),
    };

    /// <summary>Devine le type de données à partir des premiers octets.</summary>
    public static string Sniff(ReadOnlySpan<byte> d)
    {
        if (d.Length < 4) return "";
        var head = d[..Math.Min(d.Length, 16)].ToArray();
        bool S(string sig) => head.Length >= sig.Length && head.AsSpan(0, sig.Length).SequenceEqual(Encoding.Latin1.GetBytes(sig));
        if (S("MZ")) return "exe";
        if (S("PK\x03\x04")) return "zip";
        if (S("7z\xBC\xAF\x27\x1C")) return "7z";
        if (S("Rar!")) return "rar";
        if (S("\x89PNG")) return "png";
        if (S("\xFF\xD8\xFF")) return "jpg";
        if (S("GIF8")) return "gif";
        if (S("BM")) return "bmp";
        if (S("%PDF")) return "pdf";
        if (S("\xD0\xCF\x11\xE0")) return "msi";
        if (S("MSCF")) return "cab";
        if (S("\x1F\x8B")) return "gz";
        if (S("wOFF")) return "woff";
        if (S("wOF2")) return "woff2";
        if (S("RIFF")) return "riff";
        if (S("OggS")) return "ogg";
        if (S("ID3")) return "mp3";
        if (S("\x00\x00\x01\x00")) return "ico";
        if (S("<?xml")) return "xml";
        if (S("\xEF\xBB\xBF")) return "txt";
        if (S("\xFF\xFE")) return "txt-utf16";
        if (S("\xCA\xFE\xBA\xBE")) return "class";
        if (S("PYZ\0")) return "pyz";
        if (S("MEI\x0C\x0B\x0A\x0B\x0E")) return "pyinstaller";
        int printable = 0, n = Math.Min(d.Length, 512);
        for (int i = 0; i < n; i++) if (d[i] == 9 || d[i] == 10 || d[i] == 13 || (d[i] >= 32 && d[i] < 127)) printable++;
        if (printable > n * 0.95) return "txt";
        return "";
    }

    static readonly HashSet<string> BinaryRunnable = new(StringComparer.OrdinalIgnoreCase)
    { ".exe", ".dll", ".scr", ".com", ".pif", ".cpl", ".msi", ".sys", ".ocx", ".lnk", ".jar", ".msp", ".appx", ".msix" };
    static readonly HashSet<string> ScriptRunnable = new(StringComparer.OrdinalIgnoreCase)
    { ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".ps1", ".psm1", ".hta", ".reg", ".py", ".pyw", ".au3", ".url" };

    /// <summary>Rend un nom de fichier extrait inoffensif au double-clic :
    /// "x.exe" → "x.exe.bin", "x.js" → "x.js.txt". Le contenu n'est pas modifié.</summary>
    public static string Defang(string fileName)
    {
        var ext = Path.GetExtension(fileName);
        if (BinaryRunnable.Contains(ext)) return fileName + ".bin";
        if (ScriptRunnable.Contains(ext)) return fileName + ".txt";
        return fileName;
    }

    public static bool IsDefanged(string path, out string realExt)
    {
        realExt = Path.GetExtension(path);
        var inner = Path.GetExtension(Path.GetFileNameWithoutExtension(path));
        if ((realExt.Equals(".bin", StringComparison.OrdinalIgnoreCase) && BinaryRunnable.Contains(inner)) ||
            (realExt.Equals(".txt", StringComparison.OrdinalIgnoreCase) && ScriptRunnable.Contains(inner)))
        { realExt = inner; return true; }
        return false;
    }

    static readonly char[] Bad = Path.GetInvalidFileNameChars().Concat(new[] { '<', '>', ':', '"', '|', '?', '*', '\\', '/' }).Distinct().ToArray();

    public static string SafeName(string name, int max = 120)
    {
        if (string.IsNullOrWhiteSpace(name)) name = "sans_nom";
        var sb = new StringBuilder();
        foreach (var c in name) sb.Append(c < 32 || Bad.Contains(c) ? '_' : c);
        var s = sb.ToString().Trim().TrimEnd('.');
        if (s is "" or "." or "..") s = "sans_nom";
        var upper = Path.GetFileNameWithoutExtension(s).ToUpperInvariant();
        if (upper is "CON" or "PRN" or "AUX" or "NUL" || (upper.Length == 4 && (upper.StartsWith("COM") || upper.StartsWith("LPT")) && char.IsDigit(upper[3]))) s = "_" + s;
        return s.Length > max ? s[..max] : s;
    }

    /// <summary>Transforme un chemin interne d'archive ("a/b/../c.py") en chemin sûr sous root (anti "zip slip").</summary>
    public static string SafeJoin(string root, string relative)
    {
        var parts = relative.Replace('\\', '/').Split('/', StringSplitOptions.RemoveEmptyEntries)
            .Where(p => p != "." && p != "..").Select(p => SafeName(p)).ToArray();
        if (parts.Length == 0) parts = new[] { "sans_nom" };
        parts[^1] = Defang(parts[^1]);
        var full = Path.GetFullPath(Path.Combine(new[] { root }.Concat(parts).ToArray()));
        var rootFull = Path.GetFullPath(root);
        if (!full.StartsWith(rootFull, StringComparison.OrdinalIgnoreCase)) throw new IOException("chemin refusé : " + relative);
        return full;
    }

    public static void WriteFile(string path, ReadOnlySpan<byte> data)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        using var fs = new FileStream(path, FileMode.Create, FileAccess.Write);
        fs.Write(data);
    }

    public static string HumanSize(long n)
    {
        string[] u = { "o", "Ko", "Mo", "Go" };
        double v = n; int i = 0;
        while (v >= 1024 && i < u.Length - 1) { v /= 1024; i++; }
        return (i == 0 ? v.ToString("0") : v.ToString("0.#")) + " " + u[i];
    }

    public static string Truncate(string s, int max) => s.Length <= max ? s : s[..max] + "…";
}
