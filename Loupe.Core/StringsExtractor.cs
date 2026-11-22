using System.Text;

namespace Loupe.Core;

/// <summary>Extrait les textes lisibles d'un fichier binaire (ASCII et UTF-16), comme l'outil "strings".</summary>
public static class StringsExtractor
{
    public static List<string> Extract(byte[] data, int minLen = 5, int maxCount = 300_000)
    {
        var result = new List<string>();
        var seen = new HashSet<string>();
        void Add(string s)
        {
            if (result.Count >= maxCount) return;
            if (seen.Add(s)) result.Add(s);
        }

        // ASCII / Latin-1 imprimable
        var sb = new StringBuilder();
        for (int i = 0; i < data.Length && result.Count < maxCount; i++)
        {
            byte b = data[i];
            if (b >= 32 && b < 127 || b == 9) sb.Append((char)b);
            else
            {
                if (sb.Length >= minLen) Add(Util.Truncate(sb.ToString(), 2000));
                sb.Clear();
            }
        }
        if (sb.Length >= minLen) Add(sb.ToString());
        sb.Clear();

        // UTF-16LE (deux alignements)
        for (int align = 0; align < 2; align++)
        {
            for (int i = align; i + 1 < data.Length && result.Count < maxCount; i += 2)
            {
                char c = (char)(data[i] | (data[i + 1] << 8));
                bool ok = (c >= 32 && c < 127) || c == 9 || (c >= 0xC0 && c <= 0x17F) || c == 'é' || c == '€';
                if (ok) sb.Append(c);
                else
                {
                    if (sb.Length >= minLen) Add(Util.Truncate(sb.ToString(), 2000));
                    sb.Clear();
                }
            }
            if (sb.Length >= minLen) Add(sb.ToString());
            sb.Clear();
        }
        return result;
    }
}
