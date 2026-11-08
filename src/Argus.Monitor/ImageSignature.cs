namespace Argus.Monitor;

using System.ComponentModel;
using System.Runtime.InteropServices;
using Argus.Core.Events;

/// <summary>
/// Authenticode state of an image, established the way Windows itself establishes it.
///
/// Two things had to be got right here, and the first attempt got both wrong.
///
/// **Embedded is not the whole story.** <c>X509Certificate.CreateFromSignedFile</c> reads only an
/// *embedded* certificate. Most of <c>System32</c> carries none: Windows verifies those by hashing the
/// file and looking the hash up in a signed catalog. Measured on this machine,
/// <c>Get-AuthenticodeSignature</c> reports <c>whoami.exe</c> as "Valid, type=Catalog, signer=Microsoft
/// Windows" — including after the file is copied elsewhere — while the certificate API fails on it.
/// A rule built on that API therefore told the analyst a genuine Microsoft binary had "no trusted
/// publisher signature", which is a false fact about provenance.
///
/// **WinVerifyTrust alone still is not enough.** It resolves embedded signatures and nothing else;
/// against catalog-signed files it returns <c>TRUST_E_NOSIGNATURE</c> (0x800B0100), the same code it
/// returns for a file with no signature at all — measured, so "the call said no signature" cannot be
/// read as "this file is unsigned". The catalog has to be located separately, with
/// <c>CryptCATAdminCalcHashFromFileHandle2</c> plus <c>CryptCATAdminEnumCatalogFromHash</c>, and then
/// the catalog file itself verified.
///
/// Revocation is not checked (it needs the network and would stall a capture) and chain retrieval is
/// cache-only for the same reason, so the result means "the chain is trusted", never "the publisher is
/// not revoked". Failures that are not about the signature — an unreadable file, a missing chain
/// element, a failing API — stay <see cref="SignatureStatus.Unknown"/> rather than becoming a claim
/// of "unsigned".
/// </summary>
internal static class ImageSignature
{
    private const uint WtdUiNone = 2;
    private const uint WtdRevokeNone = 0;
    private const uint WtdChoiceFile = 1;
    private const uint WtdStateActionVerify = 0;
    private const uint WtdStateActionClose = 1;
    private const uint WtdCacheOnlyUrlRetrieval = 0x00001000;

    private const uint ErrorSuccess = 0;
    private const uint TrustENoSignature = 0x800B0100;      // no embedded signature (may still be catalogued)
    private const uint TrustESubjectFormUnknown = 0x800B0003;
    private const uint TrustEProviderUnknown = 0x800B0001;
    private const uint TrustEBadDigest = 0x80096010;        // signed, but the file changed
    private const uint CertEUntrustedRoot = 0x800B0109;
    private const uint CertEChaining = 0x800B010A;
    private const uint CertEExpired = 0x800B0101;
    private const uint TrustESubjectNotTrusted = 0x800B010C;
    private const uint TrustEExplicitDistrust = 0x800B0111;
    private const uint CertEUntrustedCert = 0x800B0102;

    private const uint GenericRead = 0x80000000;
    private const uint FileShareAll = 0x7;
    private const uint OpenExisting = 3;
    private const uint InvalidHandleValue = 0xFFFFFFFF;

    private static readonly Guid WinTrustActionGenericVerifyV2 = new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

    public static SignatureStatus Verify(string? imagePath) => VerifyFile(imagePath, allowCatalog: true);

    private static SignatureStatus VerifyFile(string? path, bool allowCatalog)
    {
        if (string.IsNullOrEmpty(path) || !File.Exists(path))
        {
            // Nothing to inspect: a protected process, or a path that vanished before it was read.
            return SignatureStatus.Unknown;
        }

        var result = WinVerifyTrustFile(path);
        if (result == ErrorSuccess)
        {
            return SignatureStatus.Valid;
        }

        if (result != TrustENoSignature)
        {
            // A signature is present but the chain or digest is bad. That is a real finding.
            return Classify(result);
        }

        if (!allowCatalog)
        {
            // We are already verifying a catalog file; a catalog is not itself catalogued.
            return SignatureStatus.Invalid;
        }

        var catalog = FindCatalogForFile(path);
        switch (catalog.Outcome)
        {
            case CatalogLookup.Found:
                var catalogResult = WinVerifyTrustFile(catalog.Path!);
                return catalogResult == ErrorSuccess ? SignatureStatus.Valid : Classify(catalogResult);

            case CatalogLookup.NotFound:
                // No embedded signature and no catalog entry listing this file: genuinely unsigned.
                return SignatureStatus.Invalid;

            default:
                // The lookup could not be performed. Saying "unsigned" here would invent evidence.
                return SignatureStatus.Unknown;
        }
    }

    /// <summary>
    /// Only failure codes that are actually about the signature become "unsigned". Anything else —
    /// a missing chain element that cache-only retrieval could not fetch, a malformed path — stays
    /// <see cref="SignatureStatus.Unknown"/>.
    /// </summary>
    private static SignatureStatus Classify(uint result) => result switch
    {
        TrustENoSignature or TrustESubjectFormUnknown or TrustEProviderUnknown => SignatureStatus.Invalid,
        TrustEBadDigest or CertEUntrustedRoot or CertEChaining or CertEExpired
            or TrustESubjectNotTrusted or TrustEExplicitDistrust or CertEUntrustedCert => SignatureStatus.Invalid,
        _ => SignatureStatus.Unknown,
    };

    private static uint WinVerifyTrustFile(string path)
    {
        var fileInfo = new WinTrustFileInfo
        {
            cbStruct = (uint)Marshal.SizeOf<WinTrustFileInfo>(),
            pcwszFilePath = path,
            hFile = IntPtr.Zero,
            pgKnownSubject = IntPtr.Zero,
        };

        var fileInfoPtr = Marshal.AllocHGlobal(Marshal.SizeOf<WinTrustFileInfo>());
        var trustDataPtr = Marshal.AllocHGlobal(Marshal.SizeOf<WinTrustData>());

        try
        {
            Marshal.StructureToPtr(fileInfo, fileInfoPtr, false);

            var trustData = new WinTrustData
            {
                cbStruct = (uint)Marshal.SizeOf<WinTrustData>(),
                pPolicyCallbackData = IntPtr.Zero,
                pSIPClientData = IntPtr.Zero,
                dwUIChoice = WtdUiNone,
                fdwRevocationChecks = WtdRevokeNone,
                dwUnionChoice = WtdChoiceFile,
                pFile = fileInfoPtr,
                dwStateAction = WtdStateActionVerify,
                hWVTStateData = IntPtr.Zero,
                pwszURLReference = IntPtr.Zero,
                dwProvFlags = WtdCacheOnlyUrlRetrieval,
                dwUIContext = 0,
            };

            Marshal.StructureToPtr(trustData, trustDataPtr, false);
            var result = WinVerifyTrust(IntPtr.Zero, WinTrustActionGenericVerifyV2, trustDataPtr);

            // WinVerifyTrust allocates state the caller owns; the documented way to free it is a
            // second call with WTD_STATEACTION_CLOSE. Skipping it leaks memory per process start.
            var close = Marshal.PtrToStructure<WinTrustData>(trustDataPtr);
            close.dwStateAction = WtdStateActionClose;
            Marshal.StructureToPtr(close, trustDataPtr, false);
            WinVerifyTrust(IntPtr.Zero, WinTrustActionGenericVerifyV2, trustDataPtr);

            return result;
        }
        catch (Exception exception) when (exception is DllNotFoundException or EntryPointNotFoundException or MarshalDirectiveException)
        {
            // Not Windows, or the trust provider is unavailable. Never guess.
            return TrustEProviderUnknown;
        }
        finally
        {
            Marshal.DestroyStructure<WinTrustData>(trustDataPtr);
            Marshal.DestroyStructure<WinTrustFileInfo>(fileInfoPtr);
            Marshal.FreeHGlobal(trustDataPtr);
            Marshal.FreeHGlobal(fileInfoPtr);
        }
    }

    /// <summary>
    /// Hashes the file and asks Windows which signed catalog lists that hash. A catalog that is found
    /// still has to be verified, so only the path travels back to the caller.
    /// </summary>
    private static (string Outcome, string? Path) FindCatalogForFile(string path)
    {
        var handle = CreateFileW(path, GenericRead, FileShareAll, IntPtr.Zero, OpenExisting, 0, IntPtr.Zero);
        if (handle == IntPtr.Zero || handle == new IntPtr(unchecked((int)InvalidHandleValue)))
        {
            return ("unreadable", null);
        }

        var acquired = false;
        var catalogAdmin = IntPtr.Zero;
        try
        {
            if (!CryptCATAdminAcquireContext2(out catalogAdmin, IntPtr.Zero, "SHA256", IntPtr.Zero, 0))
            {
                return ("no-context", null);
            }

            acquired = true;

            // SHA-256 is 32 bytes; the buffer is oversized deliberately rather than assumed.
            var hash = new byte[256];
            var hashSize = (uint)hash.Length;
            if (!CryptCATAdminCalcHashFromFileHandle2(catalogAdmin, handle, ref hashSize, hash, 0))
            {
                return ("hash-failed", null);
            }

            var memberHash = new byte[hashSize];
            Array.Copy(hash, memberHash, hashSize);

            var previous = IntPtr.Zero;
            var catalogInfo = CryptCATAdminEnumCatalogFromHash(catalogAdmin, memberHash, hashSize, 0, ref previous);
            if (catalogInfo == IntPtr.Zero)
            {
                // Not in any catalog. Only call it "absent" when Windows says that is why.
                return (Marshal.GetLastWin32Error() == 1168 /* ERROR_NOT_FOUND */ || Marshal.GetLastWin32Error() == 0)
                    ? ("not-found", null)
                    : ("enum-failed", null);
            }

            try
            {
                var info = new CatalogInfo { cbStruct = (uint)Marshal.SizeOf<CatalogInfo>() };
                if (!CryptCATCatalogInfoFromContext(catalogInfo, ref info, 0))
                {
                    return ("info-failed", null);
                }

                return info.wszCatalogFile is { Length: > 0 } catalogPath
                    ? ("found", catalogPath)
                    : ("info-failed", null);
            }
            finally
            {
                CryptCATAdminReleaseCatalogContext(catalogAdmin, catalogInfo, 0);
            }
        }
        catch (Exception exception) when (exception is DllNotFoundException or EntryPointNotFoundException or MarshalDirectiveException)
        {
            return ("unavailable", null);
        }
        finally
        {
            if (acquired)
            {
                CryptCATAdminReleaseContext(catalogAdmin, 0);
            }

            CloseHandle(handle);
        }
    }

    /// <summary>Named outcomes so a failed lookup is never mistaken for an absent catalog entry.</summary>
    private static class CatalogLookup
    {
        public const string Found = "found";
        public const string NotFound = "not-found";
    }

    [DllImport("wintrust.dll", ExactSpelling = true, PreserveSig = true, SetLastError = false)]
    private static extern uint WinVerifyTrust(
        IntPtr hwnd,
        [MarshalAs(UnmanagedType.LPStruct)] Guid pgActionID,
        IntPtr pWVTData);

    [DllImport("wintrust.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptCATAdminAcquireContext2(
        out IntPtr phCatAdmin,
        IntPtr pgSubsystem,
        string pwszHashAlgorithm,
        IntPtr pStrongHashPolicy,
        uint dwFlags);

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptCATAdminCalcHashFromFileHandle2(
        IntPtr hCatAdmin,
        IntPtr hFile,
        ref uint pcbHash,
        [Out] byte[] pbHash,
        uint dwFlags);

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = true)]
    private static extern IntPtr CryptCATAdminEnumCatalogFromHash(
        IntPtr hCatAdmin,
        byte[] pbHash,
        uint cbHash,
        uint dwFlags,
        ref IntPtr phPrevCatInfo);

    [DllImport("wintrust.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptCATCatalogInfoFromContext(
        IntPtr hCatInfo,
        ref CatalogInfo psCatInfo,
        uint dwFlags);

    [DllImport("wintrust.dll", ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptCATAdminReleaseCatalogContext(IntPtr hCatAdmin, IntPtr hCatInfo, uint dwFlags);

    [DllImport("wintrust.dll", ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptCATAdminReleaseContext(IntPtr hCatAdmin, uint dwFlags);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
    private static extern IntPtr CreateFileW(
        string lpFileName,
        uint dwDesiredAccess,
        uint dwShareMode,
        IntPtr lpSecurityAttributes,
        uint dwCreationDisposition,
        uint dwFlagsAndAttributes,
        IntPtr hTemplateFile);

    [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr hObject);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WinTrustFileInfo
    {
        public uint cbStruct;
        [MarshalAs(UnmanagedType.LPWStr)] public string? pcwszFilePath;
        public IntPtr hFile;
        public IntPtr pgKnownSubject;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WinTrustData
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
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct CatalogInfo
    {
        public uint cbStruct;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string wszCatalogFile;
    }
}
