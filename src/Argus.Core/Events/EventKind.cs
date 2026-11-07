namespace Argus.Core.Events;

/// <summary>
/// Kinds of behaviour this system records. Kinds are deliberately coarse: the
/// analysis layer, not the transport, decides what a kind means.
/// </summary>
public enum EventKind
{
    SessionStart,
    SessionStop,
    ProcessStart,
    ProcessStop,
    ImageLoad,
    FileCreate,
    FileWrite,
    FileRead,
    FileDelete,
    FileRename,
    RegistrySetValue,
    RegistryDeleteValue,
    NetConnect,
    NetAccept,
    NetClose,
    NetFlow,
    DnsQuery,
    DnsResponse,
    MonitorGap,
}
