namespace Argus.Core.Processes;

using Argus.Core.Events;
using Argus.Core.Paths;
using Argus.Core.Sessions;

public sealed record ScopeDecision(ProcessScopeState State, bool InScope, string Reason);

/// <summary>
/// Decides whether an event belongs to the monitored process tree.
///
/// This is the most consequential judgement in the system: too strict and real
/// child processes vanish; too loose and every unrelated process on the machine
/// is attributed to the target. The rules are explicit and labelled so the UI can
/// show "scope uncertain" instead of silently guessing.
/// </summary>
public sealed class ProcessScopeTracker
{
    /// <summary>Window used only when a parent is unknown and the image path is missing.</summary>
    public static readonly TimeSpan OrphanWindow = TimeSpan.FromMilliseconds(1500);

    private readonly Dictionary<int, Entry> _byPid = [];

    public ProcessScopeTracker(int rootPid, string? rootImagePath = null)
    {
        RootPid = rootPid;
        RootDirectory = rootImagePath is null ? null : PathKey.DirectoryName(PathKey.Canonicalize(rootImagePath));
    }

    public int RootPid { get; }

    public string? RootDirectory { get; }

    /// <summary>Records the event if it is a process lifecycle event, then classifies it.</summary>
    public ScopeDecision Observe(BehaviorEvent behaviorEvent)
    {
        ArgumentNullException.ThrowIfNull(behaviorEvent);

        if (behaviorEvent.Kind == EventKind.ProcessStart)
        {
            var decision = ClassifyStart(behaviorEvent);
            _byPid[behaviorEvent.Pid] = new Entry(
                behaviorEvent.Pid,
                behaviorEvent.ParentPid,
                decision.State,
                behaviorEvent.TimestampUtc);
            return decision;
        }

        if (behaviorEvent.Kind == EventKind.ProcessStop)
        {
            return ClassifyPid(behaviorEvent.Pid);
        }

        return ClassifyPid(behaviorEvent.Pid);
    }

    public ScopeDecision ClassifyPid(int pid)
    {
        if (pid == RootPid)
        {
            return new ScopeDecision(ProcessScopeState.Root, true, "root");
        }

        if (_byPid.TryGetValue(pid, out var entry))
        {
            var inScope = entry.State is ProcessScopeState.Root
                or ProcessScopeState.Confirmed
                or ProcessScopeState.Unconfirmed;

            return new ScopeDecision(entry.State, inScope, inScope ? "recorded" : "parent-outside-scope");
        }

        return new ScopeDecision(ProcessScopeState.Excluded, false, "pid-not-seen");
    }

    private ScopeDecision ClassifyStart(BehaviorEvent start)
    {
        if (start.Pid == RootPid)
        {
            return new ScopeDecision(ProcessScopeState.Root, true, "root");
        }

        if (start.ParentPid is { } parentPid && parentPid != start.Pid && _byPid.TryGetValue(parentPid, out var parent))
        {
            var parentInScope = parent.State is ProcessScopeState.Root
                or ProcessScopeState.Confirmed
                or ProcessScopeState.Unconfirmed;

            return parentInScope
                ? new ScopeDecision(ProcessScopeState.Confirmed, true, "parent-confirmed")
                : new ScopeDecision(ProcessScopeState.Excluded, false, "parent-outside-scope");
        }

        // No parent record. Prefer structural evidence over timing.
        if (RootDirectory is not null && start.ImagePath is not null
            && PathKey.IsUnder(PathKey.Canonicalize(start.ImagePath), RootDirectory))
        {
            return new ScopeDecision(ProcessScopeState.Unconfirmed, true, "image-under-root-directory");
        }

        if (string.IsNullOrEmpty(start.ImagePath) && RecentlyStarted(start.TimestampUtc))
        {
            return new ScopeDecision(ProcessScopeState.Unconfirmed, true, "orphan-window");
        }

        return new ScopeDecision(ProcessScopeState.Excluded, false, "parent-not-in-scope");
    }

    private bool RecentlyStarted(DateTimeOffset timestamp) =>
        _byPid.Values.Any(e =>
            e.State is ProcessScopeState.Root or ProcessScopeState.Confirmed
            && (e.StartedUtc - timestamp).Duration() <= OrphanWindow);

    private sealed record Entry(int Pid, int? ParentPid, ProcessScopeState State, DateTimeOffset StartedUtc);
}
