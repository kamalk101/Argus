namespace Argus.Monitor;

using Argus.Core.Events;

/// <summary>
/// Repair path for process events. ETW is the primary source; this poller only
/// fills gaps when the kernel provider is unavailable or an event was lost. It
/// never becomes the only sensor silently: polled events are marked Partial.
/// </summary>
public sealed class ProcessPollingCollector
{
    private readonly int _rootPid;
    private readonly Func<int, bool> _isInScope;
    private readonly Action<RawEvent> _emit;
    private readonly TimeSpan _interval;
    private readonly HashSet<int> _known = [];
    private readonly object _gate = new();

    public ProcessPollingCollector(
        int rootPid,
        Func<int, bool> isInScope,
        Action<RawEvent> emit,
        TimeSpan interval)
    {
        _rootPid = rootPid;
        _isInScope = isInScope;
        _emit = emit;
        _interval = interval;
        _known.Add(rootPid);
    }

    public async Task RunAsync(CancellationToken cancellationToken)
    {
        using var timer = new PeriodicTimer(_interval);
        while (await timer.WaitForNextTickAsync(cancellationToken).ConfigureAwait(false))
        {
            try
            {
                Poll();
            }
            catch (Exception exception) when (exception is InvalidOperationException or ArgumentException)
            {
                // The snapshot can race with process exit; try again next tick.
            }
        }
    }

    public void Poll()
    {
        var snapshot = ProcessSnapshot.Read();
        var byPid = snapshot.ToDictionary(process => process.Pid);
        var now = DateTimeOffset.UtcNow;

        lock (_gate)
        {
            // A few passes so a child discovered in this pass can reveal its own
            // children without waiting for the next tick.
            for (var pass = 0; pass < 4; pass++)
            {
                var added = false;
                foreach (var process in snapshot)
                {
                    if (_known.Contains(process.Pid))
                    {
                        continue;
                    }

                    var parentKnown = process.ParentPid == _rootPid
                        || _known.Contains(process.ParentPid)
                        || _isInScope(process.ParentPid);

                    if (!parentKnown)
                    {
                        continue;
                    }

                    _known.Add(process.Pid);
                    added = true;
                    EmitStart(process, now);
                }

                if (!added)
                {
                    break;
                }
            }

            foreach (var pid in _known.ToArray())
            {
                if (pid == _rootPid || byPid.ContainsKey(pid))
                {
                    continue;
                }

                _known.Remove(pid);
                _emit(new RawEvent
                {
                    Ts = now,
                    Kind = EventKind.ProcessStop,
                    Pid = pid,
                    Observability = Observability.Partial,
                    Source = EventSourceKind.Polling,
                    Detail = "poll-repair",
                });
            }
        }
    }

    private void EmitStart(LiveProcess process, DateTimeOffset now)
    {
        var metadata = WindowsProcessMetadata.TryGet(process.Pid, process.ParentPid);
        _emit(new RawEvent
        {
            Ts = now,
            Kind = EventKind.ProcessStart,
            Pid = process.Pid,
            ParentPid = process.ParentPid,
            ImageName = string.IsNullOrEmpty(process.ImageName)
                ? metadata is null ? null : Argus.Core.Monitoring.EtwEventMapper.FileNameOf(metadata.ImagePath)
                : process.ImageName,
            ImagePath = metadata?.ImagePath,
            CommandLine = metadata?.CommandLine,
            Observability = Observability.Partial,
            Source = EventSourceKind.Polling,
            Detail = "poll-repair",
        });
    }
}
