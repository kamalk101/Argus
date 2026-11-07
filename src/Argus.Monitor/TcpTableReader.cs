namespace Argus.Monitor;

using System.Net;
using System.Runtime.InteropServices;

public sealed record TcpConnection(
    uint State,
    string LocalAddress,
    int LocalPort,
    string RemoteAddress,
    int RemotePort,
    int Pid,
    string AddressFamily)
{
    public bool IsEstablished => State == 5;

    public bool IsConnecting => State == 3;
}

/// <summary>
/// <c>GetExtendedTcpTable</c> is the attribution repair for ETW network events:
/// its owner PID is authoritative for established sockets, including sockets
/// whose ETW completion thread is not the owning process. Polled, so short-lived
/// connections can be missed; those events are marked Partial, never Direct.
/// </summary>
public static class TcpTableReader
{
    public static IReadOnlyList<TcpConnection> Read()
    {
        var results = new List<TcpConnection>();
        ReadIPv4(results);
        ReadIPv6(results);
        return results;
    }

    private static void ReadIPv4(List<TcpConnection> results)
    {
        var rows = ReadTable(NativeMethods.AfInet, Marshal.SizeOf<NativeMethods.MibTcpRowOwnerPid>());
        if (rows == IntPtr.Zero)
        {
            return;
        }

        try
        {
            var count = Marshal.ReadInt32(rows);
            var rowSize = Marshal.SizeOf<NativeMethods.MibTcpRowOwnerPid>();
            var pointer = IntPtr.Add(rows, 4);

            for (var i = 0; i < count; i++)
            {
                var row = Marshal.PtrToStructure<NativeMethods.MibTcpRowOwnerPid>(pointer);
                if (row.State is 3 or 5 && row.OwningPid != 0)
                {
                    results.Add(new TcpConnection(
                        row.State,
                        AddressOf(row.LocalAddress),
                        PortOf(row.LocalPort),
                        AddressOf(row.RemoteAddress),
                        PortOf(row.RemotePort),
                        unchecked((int)row.OwningPid),
                        "ipv4"));
                }

                pointer = IntPtr.Add(pointer, rowSize);
            }
        }
        finally
        {
            Marshal.FreeHGlobal(rows);
        }
    }

    private static void ReadIPv6(List<TcpConnection> results)
    {
        var rows = ReadTable(NativeMethods.AfInet6, Marshal.SizeOf<NativeMethods.MibTcp6RowOwnerPid>());
        if (rows == IntPtr.Zero)
        {
            return;
        }

        try
        {
            var count = Marshal.ReadInt32(rows);
            var rowSize = Marshal.SizeOf<NativeMethods.MibTcp6RowOwnerPid>();
            var pointer = IntPtr.Add(rows, 4);

            for (var i = 0; i < count; i++)
            {
                var row = Marshal.PtrToStructure<NativeMethods.MibTcp6RowOwnerPid>(pointer);
                if (row.State is 3 or 5 && row.OwningPid != 0
                    && row.LocalAddress is { Length: 16 } && row.RemoteAddress is { Length: 16 })
                {
                    results.Add(new TcpConnection(
                        row.State,
                        new IPAddress(row.LocalAddress, row.LocalScopeId).ToString(),
                        PortOf(row.LocalPort),
                        new IPAddress(row.RemoteAddress, row.RemoteScopeId).ToString(),
                        PortOf(row.RemotePort),
                        unchecked((int)row.OwningPid),
                        "ipv6"));
                }

                pointer = IntPtr.Add(pointer, rowSize);
            }
        }
        finally
        {
            Marshal.FreeHGlobal(rows);
        }
    }

    private static IntPtr ReadTable(int addressFamily, int rowSize)
    {
        var size = 0;
        var result = NativeMethods.GetExtendedTcpTable(
            IntPtr.Zero,
            ref size,
            false,
            addressFamily,
            NativeMethods.TcpTableOwnerPidAll,
            0);

        if (result != NativeMethods.ErrorInsufficientBuffer || size <= 0)
        {
            return IntPtr.Zero;
        }

        // Leave room for a table that grows between the two calls.
        size += rowSize * 4;
        var buffer = Marshal.AllocHGlobal(size);
        result = NativeMethods.GetExtendedTcpTable(
            buffer,
            ref size,
            false,
            addressFamily,
            NativeMethods.TcpTableOwnerPidAll,
            0);

        if (result == 0)
        {
            return buffer;
        }

        Marshal.FreeHGlobal(buffer);
        return IntPtr.Zero;
    }

    private static string AddressOf(uint address)
    {
        var bytes = BitConverter.GetBytes(address);
        return new IPAddress(bytes).ToString();
    }

    private static int PortOf(uint port) =>
        (ushort)IPAddress.NetworkToHostOrder((short)(port & 0xffff));
}
