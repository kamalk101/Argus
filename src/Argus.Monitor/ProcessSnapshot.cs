namespace Argus.Monitor;

using System.Runtime.InteropServices;

public sealed record LiveProcess(int Pid, int ParentPid, string ImageName);

/// <summary>Toolhelp snapshot used by the repair pollers, not as the primary sensor.</summary>
public static class ProcessSnapshot
{
    public static IReadOnlyList<LiveProcess> Read()
    {
        var snapshot = NativeMethods.CreateToolhelp32Snapshot(NativeMethods.Th32csSnapshotProcess, 0);
        if (snapshot == IntPtr.Zero || snapshot == new IntPtr(-1))
        {
            return [];
        }

        try
        {
            var entry = new NativeMethods.ProcessEntry32W
            {
                Size = (uint)Marshal.SizeOf<NativeMethods.ProcessEntry32W>(),
            };

            var results = new List<LiveProcess>(256);
            if (!NativeMethods.Process32FirstW(snapshot, ref entry))
            {
                return results;
            }

            do
            {
                if (entry.ProcessId != 0)
                {
                    results.Add(new LiveProcess(
                        unchecked((int)entry.ProcessId),
                        unchecked((int)entry.ParentProcessId),
                        entry.ExeFile ?? string.Empty));
                }

                entry.Size = (uint)Marshal.SizeOf<NativeMethods.ProcessEntry32W>();
            }
            while (NativeMethods.Process32NextW(snapshot, ref entry));

            return results;
        }
        finally
        {
            NativeMethods.CloseHandle(snapshot);
        }
    }
}
