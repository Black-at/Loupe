using System.Text;
using System.Text.RegularExpressions;

namespace Loupe.Core;

/// <summary>Applique les règles sur tous les textes collectés (chaînes, imports, code décompilé…).</summary>
public sealed class Scanner
{
    public sealed class Blob
    {
        public string Where = "";
        public string Text = "";
        /// <summary>vrai si chaque ligne est une entrée indépendante (chaînes, imports) : pas de numéro de ligne affiché</summary>
        public bool LineIsItem;
    }

    readonly List<Blob> blobs = new();

    public void Add(string where, string text, bool lineIsItem = false)
    {
        if (string.IsNullOrEmpty(text)) return;
        // gros textes : découpés pour éviter les expressions trop lentes
        const int chunk = 4_000_000;
        if (text.Length <= chunk) { blobs.Add(new Blob { Where = where, Text = text, LineIsItem = lineIsItem }); return; }
        int pos = 0;
        while (pos < text.Length)
        {
            int end = Math.Min(text.Length, pos + chunk);
            if (end < text.Length)
            {
                int nl = text.LastIndexOf('\n', end - 1, Math.Min(10000, end - pos));
                if (nl > pos) end = nl + 1;
            }
            blobs.Add(new Blob { Where = where, Text = text[pos..end], LineIsItem = lineIsItem });
            pos = end;
        }
    }

    public void AddLines(string where, IEnumerable<string> lines) => Add(where, string.Join("\n", lines), true);

    public List<Indicator> Run(CancellationToken ct)
    {
        var found = new List<Indicator>();
        foreach (var rule in Rules.All)
        {
            ct.ThrowIfCancellationRequested();
            var ind = Evaluate(rule, ct);
            if (ind != null) found.Add(ind);
        }
        return found;
    }

    Indicator? Evaluate(Rule rule, CancellationToken ct)
    {
        var evidence = new List<Evidence>();
        var listEvidence = new List<Evidence>();
        var distinct = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var distinctAll = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        int hits = 0;
        bool allGroupsReal = true;
        // les fichiers de code (avec numéro de ligne, ouvrables) d'abord : ce sont les meilleures preuves
        var ordered = blobs.Where(b => !b.LineIsItem).Concat(blobs.Where(b => b.LineIsItem)).ToList();
        foreach (var g in rule.Groups)
        {
            bool groupHit = false, groupReal = false;
            foreach (var b in ordered)
            {
                ct.ThrowIfCancellationRequested();
                MatchCollection ms;
                try { ms = g.Matches(b.Text); }
                catch (RegexMatchTimeoutException) { continue; }
                int perBlob = 0;
                try
                {
                    foreach (Match m in ms)
                    {
                        groupHit = true; hits++;
                        var key = m.Value.Length > 60 ? m.Value[..60] : m.Value;
                        distinctAll.Add(key);
                        bool inList = InDetectionList(b.Text, m, rule.Id is "discord_token" or "clipper");
                        if (!inList) { groupReal = true; distinct.Add(key); }
                        var target = inList ? listEvidence : evidence;
                        if (target.Count < 12 && perBlob < 3 && !target.Any(e => e.Where == b.Where && e.Text.Contains(m.Value)))
                        {
                            var ev = MakeEvidence(b, m);
                            if (!target.Any(e => e.Text == ev.Text)) { target.Add(ev); perBlob++; }
                        }
                        if (hits > 5000) break;
                    }
                }
                catch (RegexMatchTimeoutException) { }
            }
            if (!groupHit) return null;
            if (!groupReal) allGroupsReal = false;
        }
        if (distinctAll.Count < rule.MinDistinct) return null;
        if (allGroupsReal && distinct.Count >= rule.MinDistinct)
            return new Indicator
            {
                Id = rule.Id, Severity = rule.Severity, Weight = rule.Weight, Category = rule.Category,
                Title = rule.Title, Explanation = rule.Explanation, Evidence = evidence.Concat(listEvidence).Take(12).ToList(), Hits = hits,
            };
        // seulement cité dans des listes de détection (antivirus, outil de sécurité, optimiseur…) : signalé mais sans poids
        if (rule.Severity < Severity.Moyen) return null;
        return new Indicator
        {
            Id = rule.Id + "_liste", Severity = Severity.Info, Weight = 0, Category = rule.Category,
            Title = "Cité dans une liste : " + LowerFirst(rule.Title),
            Explanation = "Ces éléments apparaissent seulement dans une liste de noms ou de motifs (comme dans un antivirus ou un outil qui recherche ces menaces), pas dans du code qui s'en sert directement. Ce n'est probablement pas un comportement du programme. Pour rappel : " + LowerFirst(rule.Explanation),
            Evidence = listEvidence.Concat(evidence).Take(8).ToList(), Hits = hits,
        };
    }

    static string LowerFirst(string s) => s.Length > 0 ? char.ToLowerInvariant(s[0]) + s[1..] : s;

    /// <summary>Le motif est-il dans une longue alternative « a|b|c|d… » (liste de détection, expression régulière) ?</summary>
    static bool InDetectionList(string t, Match m, bool regexIsTarget)
    {
        int ls = m.Index == 0 ? 0 : t.LastIndexOf('\n', m.Index - 1) + 1;
        int le = t.IndexOf('\n', m.Index + m.Length);
        if (le < 0) le = t.Length;
        int a = Math.Max(ls, m.Index - 160), z = Math.Min(le, m.Index + m.Length + 160);
        int pipes = 0;
        for (int i = a; i < z; i++) if (t[i] == '|') pipes++;
        if (pipes >= 4) return true;
        if (regexIsTarget) return false;
        // texte d'une expression régulière (règle de détection) plutôt que du code qui agit
        var w = t.AsSpan(Math.Max(ls, m.Index - 100), Math.Min(le, m.Index + m.Length + 100) - Math.Max(ls, m.Index - 100));
        int rx = 0;
        foreach (var tok in RegexTokens) { int k = 0; var sp = w; while ((k = sp.IndexOf(tok)) >= 0) { rx++; sp = sp[(k + tok.Length)..]; if (rx >= 2) return true; } }
        return false;
    }

    static readonly string[] RegexTokens = { "\\s+", "\\s*", "\\b", "\\.", "[^", "(?:", "(?i)", "{0,", "{1,", "\\d", "\\w" };

    static Evidence MakeEvidence(Blob b, Match m)
    {
        var t = b.Text;
        int ls = t.LastIndexOf('\n', Math.Max(0, m.Index - 1)) + 1;
        if (m.Index == 0) ls = 0;
        int le = t.IndexOf('\n', m.Index + m.Length);
        if (le < 0) le = t.Length;
        string line = t[ls..le].Trim();
        // centre l'extrait autour du motif trouvé
        if (line.Length > 220)
        {
            int rel = m.Index - ls - (t[ls..le].Length - t[ls..le].TrimStart().Length);
            int start = Math.Clamp(rel - 90, 0, Math.Max(0, line.Length - 220));
            line = (start > 0 ? "…" : "") + line.Substring(start, Math.Min(220, line.Length - start)) + (start + 220 < line.Length ? "…" : "");
        }
        string where = b.Where;
        if (!b.LineIsItem)
        {
            int lineNo = 1;
            for (int i = 0; i < ls; i++) if (t[i] == '\n') lineNo++;
            where += " (ligne " + lineNo + ")";
        }
        return new Evidence { Where = where, Text = line };
    }

    // ---------- réseau ----------
    static readonly Regex UrlRe = new(@"\b(?:https?|ftp|wss?)://[A-Za-z0-9\-._~%]+(?::\d{1,5})?(?:/[^\s""'<>\\^`{|}]*)?", RegexOptions.Compiled | RegexOptions.IgnoreCase);
    static readonly Regex IpRe = new(@"(?<![\d.])((?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d))(?::\d{2,5})?(?![\d.])", RegexOptions.Compiled);
    static readonly Regex RegRe = new(@"\b(?:HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_CLASSES_ROOT|HKLM|HKCU|HKCR)\\{1,2}[A-Za-z0-9_ .\\{}\-]{3,200}", RegexOptions.Compiled | RegexOptions.IgnoreCase);
    static readonly Regex CmdRe = new(@"(?:\b(?:cmd(?:\.exe)?\s+/[ck]|powershell(?:\.exe)?\s+-|schtasks(?:\.exe)?\s+/|reg(?:\.exe)?\s+(?:add|delete)\s|netsh\s|bcdedit\s|vssadmin\s|wmic\s|sc(?:\.exe)?\s+(?:create|config|stop|delete)\s|taskkill\s|certutil\s|bitsadmin\s|mshta\s|rundll32\s|regsvr32\s)[^\r\n""]{2,300})", RegexOptions.Compiled | RegexOptions.IgnoreCase);

    public (List<string> Urls, List<string> Domains, List<string> Ips, List<string> Reg, List<string> Cmds) Network()
    {
        var urls = new SortedSet<string>(StringComparer.OrdinalIgnoreCase);
        var ips = new SortedSet<string>();
        var reg = new SortedSet<string>(StringComparer.OrdinalIgnoreCase);
        var cmds = new SortedSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var b in blobs)
        {
            foreach (Match m in UrlRe.Matches(b.Text))
            {
                var u = m.Value.TrimEnd('.', ',', ';', ')', ']', '\'', '"');
                if (u.Length > 12 && urls.Count < 3000 && !IsSchemaNoise(u)) urls.Add(u);
            }
            foreach (Match m in IpRe.Matches(b.Text))
            {
                var ip = m.Groups[1].Value;
                if (IsPublicIp(ip) && ips.Count < 1000 && !LooksLikeVersion(b.Text, m)) ips.Add(m.Value);
            }
            foreach (Match m in RegRe.Matches(b.Text)) if (reg.Count < 2000) reg.Add(m.Value.TrimEnd('\\', ' ', '.'));
            foreach (Match m in CmdRe.Matches(b.Text)) if (cmds.Count < 1000) cmds.Add(Util.Truncate(m.Value.Trim(), 300));
        }
        var domains = new SortedSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var u in urls)
        {
            try
            {
                var host = new Uri(u).Host.ToLowerInvariant();
                if (host.Contains('.') && !System.Net.IPAddress.TryParse(host, out _) && PlausibleHost(host)) domains.Add(host);
            }
            catch { }
        }
        return (urls.ToList(), domains.ToList(), ips.ToList(), reg.ToList(), cmds.ToList());
    }

    static readonly HashSet<string> Tlds = new(StringComparer.OrdinalIgnoreCase)
    {
        "com","net","org","io","gg","dev","app","info","biz","xyz","me","co","tv","cc","ru","fr","de","uk","us","eu","be","ch","ca","nl","it","es","pl","br","cn","jp",
        "kr","in","au","su","ws","to","sh","ai","online","site","store","tech","cloud","live","link","top","club","pro","shop","space","website","fun","icu","vip","one",
        "lol","win","bid","men","work","click","download","stream","xxx","gov","edu","mil","int","moe","ninja","host","press","digital","network","systems","tools","zone",
        "services","software","games","game","email","world","today","life","rocks","run","page","blog","media","news","art","bot","chat","social","exposed","su","onion",
        "ly","gl","am","fm","ms","nu","tk","ml","ga","cf","gq","pw","top","rest","cyou","sbs","buzz","monster","quest","bar","mom","hair","beauty","skin","cfd","asia"
    };

    static bool PlausibleHost(string host)
    {
        var labels = host.TrimEnd('.').Split('.');
        if (labels.Length < 2 || labels.Any(l => l.Length == 0 || l.Length > 63)) return false;
        var tld = labels[^1];
        if (!tld.All(char.IsAsciiLetterLower)) return false;
        if (!(tld.Length == 2 || Tlds.Contains(tld))) return false;
        return labels[^2].Length >= 2 || labels.Length > 2;
    }

    static bool IsSchemaNoise(string u)
    {
        string l = u.ToLowerInvariant();
        return l.StartsWith("http://www.w3.org/") || l.StartsWith("http://schemas.microsoft.com/") || l.StartsWith("http://schemas.xmlsoap.org/")
            || l.StartsWith("http://ns.adobe.com/") || l.StartsWith("http://purl.org/") || l.StartsWith("http://www.apache.org/licenses")
            || l.StartsWith("https://www.apache.org/licenses") || l.StartsWith("http://crl.") || l.StartsWith("http://ocsp.")
            || l.StartsWith("http://cacerts.") || l.StartsWith("http://www.digicert.com/cps") || l.StartsWith("https://www.digicert.com/cps")
            || l.Contains("sectigo.com/cps") || l.StartsWith("http://crl3.") || l.StartsWith("http://crl4.") || l.StartsWith("http://pki.")
            || l.StartsWith("http://www.microsoft.com/pki") || l.StartsWith("http://www.microsoft.com/pkiops");
    }

    static bool LooksLikeVersion(string text, Match m)
    {
        int i = m.Index - 1;
        while (i >= 0 && text[i] == ' ') i--;
        if (i >= 0 && (char.IsLetter(text[i]) || text[i] == 'v' || text[i] == '=')) return true;
        int j = m.Index - 8;
        if (j >= 0 && text.Substring(j, 8).Contains("ersion", StringComparison.OrdinalIgnoreCase)) return true;
        return false;
    }

    public static bool IsPublicIp(string s)
    {
        var p = s.Split('.');
        if (p.Length != 4 || !p.All(x => int.TryParse(x, out _))) return false;
        int a = int.Parse(p[0]), b = int.Parse(p[1]);
        if (a == 0 || a == 10 || a == 127 || a >= 224) return false;
        if (a == 169 && b == 254) return false;
        if (a == 172 && b >= 16 && b <= 31) return false;
        if (a == 192 && b == 168) return false;
        if (a == 100 && b >= 64 && b <= 127) return false;
        // serveurs DNS publics connus (Cloudflare, Google, Quad9, OpenDNS, AdGuard, CleanBrowsing, Control D)
        if (s is "1.1.1.1" or "1.0.0.1" or "1.1.1.2" or "1.0.0.2" or "1.1.1.3" or "1.0.0.3" or "8.8.8.8" or "8.8.4.4" or "9.9.9.9" or "149.112.112.112"
            or "208.67.222.222" or "208.67.220.220" or "94.140.14.14" or "94.140.15.15" or "185.228.168.9" or "185.228.169.9" or "76.76.2.0" or "76.76.10.0" or "255.255.255.255") return false;
        // numéros de version du style 1.2.3.4 / 6.0.0.0 / 4.0.0.23
        int zeros = p.Count(x => x == "0");
        if (zeros >= 2) return false;
        if (p.All(x => x.Length == 1)) return false;
        return true;
    }

    public static string Summarize(IEnumerable<string> lines, int max)
    {
        var sb = new StringBuilder();
        int n = 0;
        foreach (var l in lines) { if (n++ >= max) break; sb.AppendLine(l); }
        return sb.ToString();
    }
}
