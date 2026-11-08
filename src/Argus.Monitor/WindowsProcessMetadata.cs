namespace Argus.Monitor;

using System.Runtime.InteropServices;
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
    /// Authenticode state of the installed image, delegated to <see cref="ImageSignature"/>, which uses
    /// WinVerifyTrust. The previous implementation read the embedded certificate only, so every
    /// catalog-signed binary in System32 (whoami, ping, most of the OS) came back as unsigned —
    /// measured, and a false statement about a genuine Microsoft file.
    /// </summary>
    private static SignatureStatus VerifySignature(string? imagePath) => ImageSignature.Verify(imagePath);

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
