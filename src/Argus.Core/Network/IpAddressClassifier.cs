namespace Argus.Core.Network;

using System.Net;
using System.Net.Sockets;

public enum IpScope
{
    Invalid,
    Loopback,
    Private,
    LinkLocal,
    Cgnat,
    Public,
}

/// <summary>
/// Offline-only IP classification. No reputation lookups: they would leak the
/// monitored application's traffic and make a demo depend on the network.
/// </summary>
public static class IpAddressClassifier
{
    public static IpScope Classify(string? value)
    {
        if (!IPAddress.TryParse(value, out var address))
        {
            return IpScope.Invalid;
        }

        if (IPAddress.IsLoopback(address))
        {
            return IpScope.Loopback;
        }

        if (address.AddressFamily == AddressFamily.InterNetwork)
        {
            var bytes = address.GetAddressBytes();
            if (bytes[0] == 10)
            {
                return IpScope.Private;
            }

            if (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31)
            {
                return IpScope.Private;
            }

            if (bytes[0] == 192 && bytes[1] == 168)
            {
                return IpScope.Private;
            }

            if (bytes[0] == 169 && bytes[1] == 254)
            {
                return IpScope.LinkLocal;
            }

            if (bytes[0] == 100 && bytes[1] >= 64 && bytes[1] <= 127)
            {
                return IpScope.Cgnat;
            }

            return IpScope.Public;
        }

        if (address.AddressFamily == AddressFamily.InterNetworkV6)
        {
            if (address.IsIPv6LinkLocal)
            {
                return IpScope.LinkLocal;
            }

            var bytes = address.GetAddressBytes();
            if ((bytes[0] & 0xFE) == 0xFC)
            {
                return IpScope.Private;
            }

            return IpScope.Public;
        }

        return IpScope.Invalid;
    }

    public static bool IsExternal(string? value) => Classify(value) is IpScope.Public;
}
