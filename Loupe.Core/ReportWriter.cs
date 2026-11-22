using System.Net;
using System.Text;

namespace Loupe.Core;

/// <summary>Rapport HTML autonome (un seul fichier, aucun script, à partager ou imprimer).</summary>
public static class ReportWriter
{
    static string E(string? s) => WebUtility.HtmlEncode(s ?? "");

    static string SevLabel(Severity s) => s switch
    {
        Severity.Critique => "Critique", Severity.Eleve => "Élevé", Severity.Moyen => "Moyen", Severity.Faible => "Faible", _ => "Info",
    };

    public static string Html(AnalysisResult r)
    {
        var sb = new StringBuilder();
        string sig = r.Pe.Signature.Present ? r.Pe.Signature.Signer + " – " + r.Pe.Signature.Status : "aucune";
        string color = r.VerdictLevel switch { "danger" => "#e5484d", "suspect" => "#f76b15", "attention" => "#e2a336", _ => "#30a46c" };
        sb.Append($$"""
        <!doctype html><html lang="fr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
        <title>Rapport Loupe – {{E(r.FileName)}}</title>
        <style>
        :root{--bg:#0f1115;--card:#171a21;--line:#262b36;--tx:#e8eaf0;--tx2:#9aa3b5;--acc:{{color}};}
        @media (prefers-color-scheme:light){:root{--bg:#f5f6f8;--card:#fff;--line:#e2e5ea;--tx:#161a22;--tx2:#5b6475;} }
        *{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--tx);font:14px/1.55 "Segoe UI",system-ui,sans-serif}
        main{max-width:1000px;margin:0 auto;padding:28px 16px 60px}h1{font-size:22px;margin:0 0 4px}h2{font-size:16px;margin:28px 0 10px}
        .sub{color:var(--tx2)}.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:16px 18px;margin:10px 0}
        .verdict{border-left:5px solid var(--acc)}.verdict b{color:var(--acc);font-size:20px}
        table{width:100%;border-collapse:collapse}td,th{padding:6px 8px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}th{color:var(--tx2);font-weight:600}
        code,.mono{font-family:Consolas,"Cascadia Mono",monospace;font-size:12.5px;word-break:break-all}
        .sev{display:inline-block;padding:1px 8px;border-radius:99px;font-size:12px;font-weight:600;color:#fff}
        .s4{background:#e5484d}.s3{background:#f76b15}.s2{background:#c08a1a}.s1{background:#3e63dd}.s0{background:#6b7280}
        .ev{margin:6px 0 0;padding:6px 10px;background:var(--bg);border-radius:8px}.ev div{color:var(--tx2);font-size:12px}
        ul{margin:6px 0;padding-left:20px}
        </style></head><body><main>
        <h1>Rapport d'analyse : {{E(r.FileName)}}</h1>
        <div class="sub">Loupe {{E(r.ToolVersion)}} · {{E(r.AnalyzedAt)}} · analyse sans exécution du programme</div>
        <div class="card verdict"><b>{{E(r.Verdict)}}</b> <span class="sub">– niveau de risque {{r.Score}}/100</span><p>{{E(r.VerdictText)}}</p></div>
        <h2>Identité du fichier</h2><div class="card"><table>
        <tr><th>Type</th><td>{{E(r.KindLabel)}}</td></tr>
        <tr><th>Langage</th><td>{{E(r.Language)}}</td></tr>
        <tr><th>Taille</th><td>{{E(Util.HumanSize(r.FileSize))}} ({{r.FileSize}} octets)</td></tr>
        <tr><th>SHA-256</th><td class="mono">{{E(r.Hashes.Sha256)}}</td></tr>
        <tr><th>MD5</th><td class="mono">{{E(r.Hashes.Md5)}}</td></tr>
        <tr><th>Signature</th><td>{{E(sig)}}</td></tr>
        <tr><th>Compilé le</th><td>{{E(r.Pe.CompiledAt)}}</td></tr>
        """);
        foreach (var kv in r.Pe.VersionInfo) sb.Append($"<tr><th>{E(kv.Key)}</th><td>{E(kv.Value)}</td></tr>");
        sb.Append("</table></div>");

        sb.Append($"<h2>Comportements repérés ({r.Indicators.Count})</h2>");
        if (r.Indicators.Count == 0) sb.Append("<div class=\"card\">Aucun.</div>");
        foreach (var i in r.Indicators)
        {
            sb.Append($"<div class=\"card\"><span class=\"sev s{(int)i.Severity}\">{SevLabel(i.Severity)}</span> <b>{E(i.Title)}</b> <span class=\"sub\">· {E(i.Category)}</span><p>{E(i.Explanation)}</p>");
            foreach (var ev in i.Evidence.Take(6)) sb.Append($"<div class=\"ev\"><div>{E(ev.Where)}</div><code>{E(ev.Text)}</code></div>");
            sb.Append("</div>");
        }

        void List(string title, List<string> items, int max = 200)
        {
            if (items.Count == 0) return;
            sb.Append($"<h2>{E(title)} ({items.Count})</h2><div class=\"card\"><ul>");
            foreach (var s in items.Take(max)) sb.Append($"<li><code>{E(s)}</code></li>");
            if (items.Count > max) sb.Append($"<li class=\"sub\">… et {items.Count - max} autres</li>");
            sb.Append("</ul></div>");
        }
        List("Domaines contactés possibles", r.Domains);
        List("Adresses IP", r.Ips);
        List("Commandes système", r.Commands, 100);
        List("Clés de registre", r.RegistryKeys, 100);

        if (r.Pe.Sections.Count > 0)
        {
            sb.Append("<h2>Sections</h2><div class=\"card\"><table><tr><th>Nom</th><th>Taille</th><th>Droits</th><th>Entropie</th></tr>");
            foreach (var s in r.Pe.Sections) sb.Append($"<tr><td class=\"mono\">{E(s.Name)}</td><td>{E(Util.HumanSize(s.RawSize))}</td><td>{E(s.Flags)}</td><td>{s.Entropy:0.00}</td></tr>");
            sb.Append("</table></div>");
        }
        if (r.Pe.Imports.Count > 0)
        {
            sb.Append("<h2>Fonctions Windows importées</h2><div class=\"card\">");
            foreach (var d in r.Pe.Imports) sb.Append($"<p><b class=\"mono\">{E(d.Dll)}</b> <span class=\"sub\">({d.Functions.Count})</span><br><code>{E(string.Join(", ", d.Functions.Take(300)))}</code></p>");
            sb.Append("</div>");
        }
        List("Notes", r.Notes);
        List("Avertissements", r.Warnings);
        sb.Append("<p class=\"sub\">Ce rapport vient d'une analyse statique : le programme a été lu, jamais lancé. Aucune analyse de ce type ne garantit 100 % ; en cas de doute, vérifiez l'empreinte SHA-256 sur virustotal.com.</p>");
        sb.Append("</main></body></html>");
        return sb.ToString();
    }
}
