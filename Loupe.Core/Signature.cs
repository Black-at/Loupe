using System.Runtime.InteropServices;
using System.Security.Cryptography.Pkcs;

namespace Loupe.Core;

/// <summary>Signature numérique (Authenticode) : qui a signé le programme, et est-ce que Windows la juge valide.</summary>
public static class Signature
{
    public static SignatureInfo Read(PeFile pe, string path)
    {
        var info = new SignatureInfo();
        var blob = pe.ReadCertificateBlob();
        if (blob == null) { info.Status = "absente"; return info; }
        info.Present = true;
        try
        {
            var cms = new SignedCms();
            cms.Decode(blob);
            var signer = cms.SignerInfos.Count > 0 ? cms.SignerInfos[0].Certificate : null;
            if (signer != null)
            {
                info.Signer = signer.GetNameInfo(System.Security.Cryptography.X509Certificates.X509NameType.SimpleName, false);
                info.Issuer = signer.GetNameInfo(System.Security.Cryptography.X509Certificates.X509NameType.SimpleName, true);
                info.ValidFrom = signer.NotBefore.ToString("yyyy-MM-dd");
                info.ValidTo = signer.NotAfter.ToString("yyyy-MM-dd");
            }
        }
        catch { info.Signer = "(certificat illisible)"; }

        if (OperatingSystem.IsWindows())
        {
            try { info.Status = VerifyWindows(path); }
            catch { info.Status = "non vérifiée"; }
        }
        else info.Status = "non vérifiée (hors Windows)";
        return info;
    }

    // ---- WinVerifyTrust ----
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct WINTRUST_FILE_INFO
    {
        public uint cbStruct;
        public string pcwszFilePath;
        public IntPtr hFile;
        public IntPtr pgKnownSubject;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct WINTRUST_DATA
    {
        public uint cbStruct;
        public IntPtr pPolicyCallbackData;
        public IntPtr pSIPClientData;
        public uint dwUIChoice;
        public uint fdwRevocationChecks;
        public uint dwUnionChoice;
        public IntPtr pFile;
        public uint dwStateAction;
        public IntPtr hWVTStateData;
        public IntPtr pwszURLReference;
        public uint dwProvFlags;
        public uint dwUIContext;
        public IntPtr pSignatureSettings;
    }

    [DllImport("wintrust.dll", CharSet = CharSet.Unicode)]
    static extern int WinVerifyTrust(IntPtr hwnd, ref Guid action, ref WINTRUST_DATA data);

    static string VerifyWindows(string path)
    {
        var fileInfo = new WINTRUST_FILE_INFO { cbStruct = (uint)Marshal.SizeOf<WINTRUST_FILE_INFO>(), pcwszFilePath = path };
        IntPtr pFile = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_FILE_INFO>());
        try
        {
            Marshal.StructureToPtr(fileInfo, pFile, false);
            var data = new WINTRUST_DATA
            {
                cbStruct = (uint)Marshal.SizeOf<WINTRUST_DATA>(),
                dwUIChoice = 2,          // WTD_UI_NONE
                fdwRevocationChecks = 0, // WTD_REVOKE_NONE (pas de réseau)
                dwUnionChoice = 1,       // WTD_CHOICE_FILE
                pFile = pFile,
                dwStateAction = 0,
                dwProvFlags = 0x00001000, // WTD_CACHE_ONLY_URL_RETRIEVAL
            };
            var action = new Guid("00AAC56B-CD44-11d0-8CC2-00C04FC295EE"); // WINTRUST_ACTION_GENERIC_VERIFY_V2
            int r = WinVerifyTrust(new IntPtr(-1), ref action, ref data);
            return r switch
            {
                0 => "valide",
                unchecked((int)0x800B0101) => "certificat expiré",
                unchecked((int)0x800B0109) => "autorité non reconnue",
                unchecked((int)0x80096010) => "invalide (fichier modifié après signature)",
                unchecked((int)0x800B0100) => "absente",
                unchecked((int)0x800B010C) => "certificat révoqué",
                _ => "invalide (code 0x" + r.ToString("X8") + ")",
            };
        }
        finally { Marshal.FreeHGlobal(pFile); }
    }
}
