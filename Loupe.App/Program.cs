namespace Loupe.App;

static class Program
{
    /// <summary>Loupe.exe [fichier] : ouvre Loupe et analyse directement le fichier donné (ex. « Ouvrir avec »).</summary>
    [STAThread]
    static void Main(string[] args)
    {
        Application.SetHighDpiMode(HighDpiMode.PerMonitorV2);
        Application.EnableVisualStyles();
        Application.SetCompatibleTextRenderingDefault(false);
        Application.ThreadException += (_, e) =>
            MessageBox.Show("Erreur inattendue : " + e.Exception.Message, "Loupe", MessageBoxButtons.OK, MessageBoxIcon.Error);
        Application.Run(new MainForm(args.FirstOrDefault(a => !a.StartsWith('-'))));
    }
}
