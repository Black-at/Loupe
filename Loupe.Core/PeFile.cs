using System.Buffers.Binary;
using System.Text;

namespace Loupe.Core;

/// <summary>Lecteur de fichiers PE (Windows .exe/.dll) écrit à la main, tolérant aux fichiers abîmés.
/// Il ne fait que LIRE des octets : rien n'est jamais exécuté.</summary>
public sealed class PeFile
{
    public sealed class Section
    {
        public string Name = "";
        public uint VirtualAddress, VirtualSize, RawOffset, RawSize, Characteristics;
    }

    public sealed class RawResource
    {
        public string Type = "";
        public string Name = "";
        public uint Lang;
        public uint Offset;
        public uint Size;
    }

    public readonly byte[] Data;
    public bool Valid { get; private set; }
    public string Error { get; private set; } = "";
    public ushort Machine { get; private set; }
    public ushort Characteristics { get; private set; }
    public uint TimeDateStamp { get; private set; }
    public bool Is64 { get; private set; }
    public ushort Subsystem { get; private set; }
    public uint EntryPointRva { get; private set; }
    public ulong ImageBase { get; private set; }
    public List<Section> Sections { get; } = new();
    public (uint Rva, uint Size)[] Directories { get; private set; } = Array.Empty<(uint, uint)>();
    public bool HasRichHeader { get; private set; }

    public bool IsDll => (Characteristics & 0x2000) != 0;
    public bool IsDotNet => Directories.Length > 14 && Directories[14].Rva != 0 && Directories[14].Size != 0;

    public PeFile(byte[] data)
    {
        Data = data;
        try { Parse(); }
        catch (Exception ex) { Valid = false; Error = ex.Message; }
    }

    ushort U16(long o) => o >= 0 && o + 2 <= Data.Length ? BinaryPrimitives.ReadUInt16LittleEndian(Data.AsSpan((int)o)) : (ushort)0;
    uint U32(long o) => o >= 0 && o + 4 <= Data.Length ? BinaryPrimitives.ReadUInt32LittleEndian(Data.AsSpan((int)o)) : 0u;
    ulong U64(long o) => o >= 0 && o + 8 <= Data.Length ? BinaryPrimitives.ReadUInt64LittleEndian(Data.AsSpan((int)o)) : 0ul;

    void Parse()
    {
        if (Data.Length < 0x40 || Data[0] != 'M' || Data[1] != 'Z') { Error = "pas d'en-tête MZ"; return; }
        uint peOff = U32(0x3C);
        if (peOff == 0 || peOff + 24 > Data.Length || U32(peOff) != 0x00004550) { Error = "pas de signature PE"; return; }
        HasRichHeader = IndexOf(Data, Encoding.ASCII.GetBytes("Rich"), 0x40, (int)Math.Min(peOff, Data.Length)) >= 0;

        long coff = peOff + 4;
        Machine = U16(coff);
        ushort nSections = U16(coff + 2);
        TimeDateStamp = U32(coff + 4);
        ushort optSize = U16(coff + 16);
        Characteristics = U16(coff + 18);

        long opt = coff + 20;
        ushort magic = U16(opt);
        Is64 = magic == 0x20B;
        EntryPointRva = U32(opt + 16);
        ImageBase = Is64 ? U64(opt + 24) : U32(opt + 28);
        Subsystem = U16(opt + 68);
        long ddStart = opt + (Is64 ? 112 : 96);
        uint nDirs = U32(opt + (Is64 ? 108 : 92));
        nDirs = Math.Min(nDirs, 16);
        Directories = new (uint, uint)[16];
        for (int i = 0; i < nDirs; i++)
            Directories[i] = (U32(ddStart + i * 8), U32(ddStart + i * 8 + 4));

        long sec = opt + optSize;
        for (int i = 0; i < nSections && i < 96; i++)
        {
            long s = sec + i * 40;
            if (s + 40 > Data.Length) break;
            var name = Encoding.ASCII.GetString(Data, (int)s, 8).TrimEnd('\0');
            Sections.Add(new Section
            {
                Name = Clean(name),
                VirtualSize = U32(s + 8),
                VirtualAddress = U32(s + 12),
                RawSize = U32(s + 16),
                RawOffset = U32(s + 20),
                Characteristics = U32(s + 36),
            });
        }
        Valid = true;
    }

    static string Clean(string s)
    {
        var sb = new StringBuilder();
        foreach (var c in s) sb.Append(c >= 32 && c < 127 ? c : '?');
        return sb.ToString();
    }

    public long RvaToOffset(uint rva)
    {
        foreach (var s in Sections)
        {
            uint size = Math.Max(s.VirtualSize, s.RawSize);
            if (rva >= s.VirtualAddress && rva < s.VirtualAddress + size)
            {
                long off = (long)s.RawOffset + (rva - s.VirtualAddress);
                return off < Data.Length ? off : -1;
            }
        }
        // en-têtes
        if (Sections.Count > 0 && rva < Sections.Min(x => x.RawOffset == 0 ? uint.MaxValue : x.RawOffset)) return rva;
        return -1;
    }

    string ReadAsciiZ(long off, int max = 512)
    {
        if (off < 0 || off >= Data.Length) return "";
        int end = (int)off;
        while (end < Data.Length && end - off < max && Data[end] != 0) end++;
        return Clean(Encoding.ASCII.GetString(Data, (int)off, end - (int)off));
    }

    /// <summary>Fin des données décrites par les sections : au-delà, c'est l'"overlay" (données ajoutées).</summary>
    public long EndOfImage
    {
        get
        {
            long end = 0;
            foreach (var s in Sections)
                if (s.RawSize > 0) end = Math.Max(end, (long)s.RawOffset + s.RawSize);
            // la signature Authenticode est placée à la fin, ce n'est pas un overlay suspect
            return Math.Min(end, Data.Length);
        }
    }

    public (long Offset, long Size) Overlay
    {
        get
        {
            long end = EndOfImage;
            if (end <= 0 || end >= Data.Length) return (0, 0);
            long size = Data.Length - end;
            var sec = Directories.Length > 4 ? Directories[4] : (0u, 0u);
            // la table de certificats utilise un offset fichier, pas un RVA
            if (sec.Item1 != 0 && sec.Item1 >= end)
            {
                long certEnd = (long)sec.Item1 + sec.Item2;
                if (sec.Item1 == end && certEnd >= Data.Length - 8) return (0, 0);
                if (sec.Item1 > end) size = sec.Item1 - end;
            }
            return size > 0 ? (end, size) : (0, 0);
        }
    }

    public List<(string Dll, List<string> Funcs)> ReadImports()
    {
        var list = new List<(string, List<string>)>();
        void ReadTable(uint dirRva, bool delay)
        {
            long off = RvaToOffset(dirRva);
            if (off < 0) return;
            for (int i = 0; i < 2048; i++)
            {
                long d = off + i * (delay ? 32 : 20);
                if (d + 20 > Data.Length) break;
                uint nameRva, thunkRva;
                if (delay)
                {
                    uint attrs = U32(d);
                    nameRva = U32(d + 4);
                    thunkRva = U32(d + 16);
                    if (nameRva == 0) break;
                    if ((attrs & 1) == 0 && ImageBase != 0) { /* ancien format en VA */ nameRva = (uint)(nameRva - ImageBase); thunkRva = (uint)(thunkRva - ImageBase); }
                }
                else
                {
                    uint oft = U32(d), ft = U32(d + 16);
                    nameRva = U32(d + 12);
                    if (nameRva == 0 && oft == 0 && ft == 0) break;
                    thunkRva = oft != 0 ? oft : ft;
                }
                string dll = ReadAsciiZ(RvaToOffset(nameRva), 256);
                if (dll.Length == 0) continue;
                var funcs = new List<string>();
                long t = RvaToOffset(thunkRva);
                for (int k = 0; t >= 0 && k < 4096; k++)
                {
                    ulong v = Is64 ? U64(t + k * 8L) : U32(t + k * 4L);
                    if (v == 0) break;
                    bool ordinal = Is64 ? (v & 0x8000000000000000UL) != 0 : (v & 0x80000000UL) != 0;
                    if (ordinal) funcs.Add("#" + (v & 0xFFFF));
                    else
                    {
                        long h = RvaToOffset((uint)(v & 0x7FFFFFFF));
                        if (h < 0) break;
                        funcs.Add(ReadAsciiZ(h + 2, 256));
                    }
                }
                list.Add((dll, funcs));
            }
        }
        if (Directories.Length > 1 && Directories[1].Rva != 0) ReadTable(Directories[1].Rva, false);
        if (Directories.Length > 13 && Directories[13].Rva != 0) ReadTable(Directories[13].Rva, true);
        return list;
    }

    public List<string> ReadExports()
    {
        var res = new List<string>();
        if (Directories.Length < 1 || Directories[0].Rva == 0) return res;
        long off = RvaToOffset(Directories[0].Rva);
        if (off < 0) return res;
        uint nNames = Math.Min(U32(off + 24), 20000u);
        long names = RvaToOffset(U32(off + 32));
        if (names < 0) return res;
        for (int i = 0; i < nNames; i++)
            res.Add(ReadAsciiZ(RvaToOffset(U32(names + i * 4L)), 256));
        return res;
    }

    static readonly Dictionary<uint, string> ResTypes = new()
    {
        [1] = "CURSOR", [2] = "BITMAP", [3] = "ICON", [4] = "MENU", [5] = "DIALOG", [6] = "STRING",
        [7] = "FONTDIR", [8] = "FONT", [9] = "ACCELERATOR", [10] = "RCDATA", [11] = "MESSAGETABLE",
        [12] = "GROUP_CURSOR", [14] = "GROUP_ICON", [16] = "VERSION", [17] = "DLGINCLUDE", [19] = "PLUGPLAY",
        [20] = "VXD", [21] = "ANICURSOR", [22] = "ANIICON", [23] = "HTML", [24] = "MANIFEST",
    };

    public List<RawResource> ReadResources()
    {
        var res = new List<RawResource>();
        if (Directories.Length < 3 || Directories[2].Rva == 0) return res;
        long root = RvaToOffset(Directories[2].Rva);
        if (root < 0) return res;

        string EntryName(uint nameField, int level)
        {
            if ((nameField & 0x80000000) != 0)
            {
                long p = root + (nameField & 0x7FFFFFFF);
                int len = U16(p);
                if (p + 2 + len * 2 > Data.Length) return "?";
                return Clean(Encoding.Unicode.GetString(Data, (int)p + 2, len * 2));
            }
            if (level == 0 && ResTypes.TryGetValue(nameField, out var t)) return t;
            return "#" + nameField;
        }

        var seen = new HashSet<long>();
        void Walk(long dir, int level, string type, string name)
        {
            if (level > 2 || dir < 0 || dir + 16 > Data.Length || !seen.Add(dir) || res.Count > 5000) return;
            int n = U16(dir + 12) + U16(dir + 14);
            for (int i = 0; i < n && i < 4096; i++)
            {
                long e = dir + 16 + i * 8L;
                uint nameField = U32(e), target = U32(e + 4);
                string label = EntryName(nameField, level);
                if ((target & 0x80000000) != 0)
                {
                    long sub = root + (target & 0x7FFFFFFF);
                    if (level == 0) Walk(sub, 1, label, "");
                    else Walk(sub, 2, type, label);
                }
                else
                {
                    long de = root + target;
                    uint dataRva = U32(de), size = U32(de + 4);
                    long dataOff = RvaToOffset(dataRva);
                    if (dataOff < 0) continue;
                    res.Add(new RawResource
                    {
                        Type = level == 0 ? label : type,
                        Name = level == 2 ? name : label,
                        Lang = level == 2 ? (nameField & 0xFFFF) : 0,
                        Offset = (uint)dataOff,
                        Size = (uint)Math.Min(size, Math.Max(0, Data.Length - dataOff)),
                    });
                }
            }
        }
        Walk(root, 0, "", "");
        return res;
    }

    /// <summary>Lit la ressource VERSION (CompanyName, FileDescription…).</summary>
    public Dictionary<string, string> ReadVersionInfo(List<RawResource> resources)
    {
        var dict = new Dictionary<string, string>();
        var v = resources.FirstOrDefault(r => r.Type == "VERSION");
        if (v == null) return dict;
        try
        {
            var blob = Data.AsSpan((int)v.Offset, (int)v.Size).ToArray();
            ParseVersionBlock(blob, 0, blob.Length, dict, 0);
        }
        catch { }
        return dict;
    }

    static void ParseVersionBlock(byte[] b, int start, int end, Dictionary<string, string> dict, int depth)
    {
        int p = start;
        while (p + 6 <= end && depth < 6)
        {
            int len = BinaryPrimitives.ReadUInt16LittleEndian(b.AsSpan(p));
            int valLen = BinaryPrimitives.ReadUInt16LittleEndian(b.AsSpan(p + 2));
            int type = BinaryPrimitives.ReadUInt16LittleEndian(b.AsSpan(p + 4));
            if (len < 6 || p + len > end) break;
            int k = p + 6, kEnd = k;
            while (kEnd + 1 < p + len && (b[kEnd] != 0 || b[kEnd + 1] != 0)) kEnd += 2;
            string key = Encoding.Unicode.GetString(b, k, kEnd - k);
            int valStart = (kEnd + 2 + 3) & ~3;
            int valBytes = type == 1 ? valLen * 2 : valLen;
            int childStart = (valStart + valBytes + 3) & ~3;
            if (depth >= 2 && type == 1 && valLen > 0 && valStart + valBytes <= p + len)
            {
                string val = Encoding.Unicode.GetString(b, valStart, Math.Max(0, valBytes - 2)).TrimEnd('\0');
                if (key.Length > 0 && key.Length < 64) dict[key] = val;
            }
            if (key == "VS_VERSION_INFO" || key == "StringFileInfo" || depth == 2)
                ParseVersionBlock(b, childStart, p + len, dict, depth + 1);
            p = (p + len + 3) & ~3;
        }
    }

    public byte[]? ReadCertificateBlob()
    {
        if (Directories.Length < 5) return null;
        var (off, size) = Directories[4];
        if (off == 0 || size < 8 || off + size > Data.Length) return null;
        uint len = U32(off);
        ushort certType = U16(off + 6);
        if (certType != 2 || len < 8 || len > size) return null; // PKCS#7 SignedData
        return Data.AsSpan((int)off + 8, (int)len - 8).ToArray();
    }

    public static int IndexOf(byte[] hay, byte[] needle, int start = 0, int end = -1)
    {
        if (end < 0 || end > hay.Length) end = hay.Length;
        if (needle.Length == 0) return -1;
        return hay.AsSpan(start, Math.Max(0, end - start)).IndexOf(needle) is int i && i >= 0 ? i + start : -1;
    }

    public static int LastIndexOf(byte[] hay, byte[] needle)
        => hay.AsSpan().LastIndexOf(needle);

    public string MachineName => Machine switch
    {
        0x14c => "x86 (32 bits)",
        0x8664 => "x64 (64 bits)",
        0xAA64 => "ARM64",
        0x1c0 or 0x1c4 => "ARM",
        0x200 => "Itanium",
        _ => "0x" + Machine.ToString("X4"),
    };

    public string SubsystemName => Subsystem switch
    {
        1 => "Pilote / natif",
        2 => "Fenêtre (GUI)",
        3 => "Console",
        9 => "Windows CE",
        10 or 11 or 12 => "EFI",
        _ => "Autre (" + Subsystem + ")",
    };

    public static string SectionFlags(uint c)
    {
        var sb = new StringBuilder();
        if ((c & 0x20000000) != 0) sb.Append('X');
        if ((c & 0x40000000) != 0) sb.Append('R');
        if ((c & 0x80000000) != 0) sb.Append('W');
        return sb.ToString();
    }
}
