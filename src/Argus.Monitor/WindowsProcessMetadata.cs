namespace Argus.Monitor;

using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Argus.Core.Events;
using Argus.Core.Monitoring;

/// <summary>
/// Best-effort live process facts. The command-line path uses
/// <c>ProcessCommandLineInformation</c> (Windows 8.1+) so no PEB walking or
/// ReadProcessMemory is needed; protected processes simply return null.
/// </summary>
public static class WindowsProcessMetadata
{
    private const int ProcessCommandLineInformation = 60;
    private const int ProcessBasicInformation = 0;

    public static ProcessMetadata? TryGet(int pid, int? parentPid = null)
    {
        if (pid <= 0)
        {
            return null;
        }

        var handle = NativeMethods.OpenProcess(NativeMethods.ProcessQueryLimitedInformation, false, pid);
        if (handle == IntPtr.Zero)
        {
            return parentPid is null ? null : new ProcessMetadata(pid, ParentPid: parentPid);
        }

        try
        {
            var imagePath = QueryImagePath(handle);
            var commandLine = QueryCommandLine(handle);
            var parent = parentPid ?? QueryParentPid(handle);

            if (imagePath is null && commandLine is null && parent is null)
            {
                return null;
            }

            return new ProcessMetadata(pid, imagePath, commandLine, parent, Signature: VerifySignature(imagePath));
        }
        finally
        {
            NativeMethods.CloseHandle(handle);
        }
    }

    /// <summary>
    /// Authenticode state of the installed image. <see cref="X509Certificate.CreateFromSignedFile"/> only
    /// reports that a certificate is attached, so a revoked or self-signed binary would read as signed.
    /// The chain is therefore built explicitly and the result is three-way: <c>Valid</c> when it chains to
    /// a trusted root, <c>Invalid</c> when a signature exists but does not verify, and <c>Unknown</c> when
    /// there is no file to inspect (protected process, deleted path).
    /// </summary>
    private static SignatureStatus VerifySignature(string? imagePath)
    {
        if (string.IsNullOrEmpty(imagePath) || !File.Exists(imagePath))
        {
            return SignatureStatus.Unknown;
        }

        try
        {
            using var certificate = X509Certificate.CreateFromSignedFile(imagePath);
            using var chain = new X509Chain
            {
                // Revocation lookups need the network and would stall a capture; this reports
                // chain trust, and the reason text never claims revocation was checked.
                ChainPolicy =
                {
                    RevocationMode = X509RevocationMode.NoCheck,
                    VerificationFlags = X509VerificationFlags.NoFlag,
                },
            };

            return chain.Build(new X509Certificate2(certificate))
                ? SignatureStatus.Valid
                : SignatureStatus.Invalid;
        }
        catch (CryptographicException)
        {
            // No signature, or one that cannot be parsed. This is the unsigned case.
            return SignatureStatus.Invalid;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return SignatureStatus.Unknown;
        }
    }

    private static string? QueryImagePath(IntPtr handle)
    {
        var buffer = new StringBuilder(32_768);
        var size = buffer.Capacity;
        return NativeMethods.QueryFullProcessImageNameW(handle, 0, buffer, ref size)
            ? buffer.ToString()
            : null;
    }

    private static string? QueryCommandLine(IntPtr handle)
    {
        var status = NativeMethods.NtQueryInformationProcess(
            handle,
            ProcessCommandLineInformation,
            IntPtr.Zero,
            0,
            out var required);

        if (required <= 0)
        {
            required = 4096;
        }

        var buffer = Marshal.AllocHGlobal(required);
        try
        {
            status = NativeMethods.NtQueryInformationProcess(
                handle,
                ProcessCommandLineInformation,
                buffer,
                required,
                out _);

            if (status != NativeMethods.StatusSuccess)
            {
                return null;
            }

            var unicode = Marshal.PtrToStructure<NativeMethods.UnicodeString>(buffer);
            if (unicode.Buffer == IntPtr.Zero || unicode.Length == 0)
            {
                return null;
            }

            return Marshal.PtrToStringUni(unicode.Buffer, unicode.Length / 2);
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private static int? QueryParentPid(IntPtr handle)
    {
        var size = Marshal.SizeOf<NativeMethods.ProcessBasicInformation>();
        var buffer = Marshal.AllocHGlobal(size);
        try
        {
            var status = NativeMethods.NtQueryInformationProcess(
                handle,
                ProcessBasicInformation,
                buffer,
                size,
                out _);

            if (status != NativeMethods.StatusSuccess)
            {
                return null;
            }

            var information = Marshal.PtrToStructure<NativeMethods.ProcessBasicInformation>(buffer);
            var parent = information.InheritedFromUniqueProcessId.ToInt64();
            return parent is > 0 and <= int.MaxValue ? (int)parent : null;
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }
}
