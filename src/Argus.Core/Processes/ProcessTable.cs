namespace Argus.Core.Processes;

using Argus.Core.Sessions;

public sealed record ProcessRecord(
    int Pid,
    int? ParentPid,
    string? ImageName,
    string? ImagePath,
    string? CommandLine,
    DateTimeOffset StartedUtc,
    ProcessScopeState Scope,
    string? ScopeReason = null);

/// <summary>
/// Reconstructed view of the monitored tree. Ancestry is rebuilt from recorded
/// rows, so a process whose parent already exited still renders correctly.
/// Keyed by PID: the live sensor resolves PID reuse before it reaches here.
/// </summary>
public sealed class ProcessTable
{
    private readonly Dictionary<int, ProcessRecord> _byPid = [];

    public int Count => _byPid.Count;

    public IReadOnlyCollection<ProcessRecord> All => _byPid.Values;

    public void Record(ProcessRecord record)
    {
        ArgumentNullException.ThrowIfNull(record);
        _byPid[record.Pid] = record;
    }

    public bool TryGet(int pid, out ProcessRecord record) => _byPid.TryGetValue(pid, out record!);

    public string? ImageNameOf(int? pid) =>
        pid is { } value && _byPid.TryGetValue(value, out var record) ? record.ImageName : null;

    public IEnumerable<ProcessRecord> ChildrenOf(int pid) =>
        _byPid.Values.Where(p => p.ParentPid == pid).OrderBy(p => p.StartedUtc).ThenBy(p => p.Pid);

    /// <summary>Number of ancestors between this process and the root (root = 0, unknown = -1).</summary>
    public int DepthOf(int pid)
    {
        var depth = 0;
        var current = pid;
        var guard = 0;

        while (_byPid.TryGetValue(current, out var record) && guard++ < 64)
        {
            if (record.ParentPid is not { } parent || parent == current)
            {
                break;
            }

            depth++;
            current = parent;
        }

        return _byPid.ContainsKey(pid) ? depth : -1;
    }
}
