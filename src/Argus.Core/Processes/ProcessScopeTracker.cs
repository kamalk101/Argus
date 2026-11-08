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
    // Directories shared by unrelated software. A notepad.exe under System32 must
    // not make every process in System32 look like a possible child of notepad.
    private static readonly string[] SharedRootDirectories =
    [
        @"c:\windows",
        @"c:\program files",
        @"c:\program files (x86)",
        @"c:\programdata",
    ];

    private readonly Dictionary<int, Entry> _byPid = [];

    // Observe is called from the ETW pump and from the two repair pollers, and the root can
    // be attached from the launch thread while all of them are running. A plain dictionary
    // is not safe for that, so every read and write takes this lock.
    private readonly object _gate = new();

    public ProcessScopeTracker(int rootPid, string? rootImagePath = null)
    {
        RootPid = rootPid;
        RootDirectory = rootImagePath is null ? null : PathKey.DirectoryName(PathKey.Canonicalize(rootImagePath));
        if (rootPid > 0)
        {
            _byPid[rootPid] = new Entry(rootPid, null, ProcessScopeState.Root);
        }
    }

    public int RootPid { get; private set; }

    public string? RootDirectory { get; private set; }

    /// <summary>True once a root pid is known. Before that, nothing can be in scope.</summary>
    public bool HasRoot => RootPid > 0;

    /// <summary>
    /// Names the root after the fact.
    ///
    /// The monitor now enables ETW before launching the target, so it starts without a root
    /// pid and attaches it the moment the process exists. Until then nothing is in scope,
    /// which is correct: the only thing running is the machine's own activity.
    /// </summary>
    public void AttachRoot(int rootPid, string? rootImagePath = null)
    {
        if (rootPid <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(rootPid), rootPid, "A root pid must be a real process id.");
        }

        lock (_gate)
        {
            if (HasRoot)
            {
                throw new InvalidOperationException("The scope tracker already has a root pid.");
            }

            RootPid = rootPid;
            RootDirectory = rootImagePath is null ? null : PathKey.DirectoryName(PathKey.Canonicalize(rootImagePath));
            _byPid[rootPid] = new Entry(rootPid, null, ProcessScopeState.Root);
        }
    }

    /// <summary>Records the event if it is a process lifecycle event, then classifies it.</summary>
    public ScopeDecision Observe(BehaviorEvent behaviorEvent)
    {
        ArgumentNullException.ThrowIfNull(behaviorEvent);

        lock (_gate)
        {
            if (behaviorEvent.Kind == EventKind.ProcessStart)
            {
                var decision = ClassifyStart(behaviorEvent);
                _byPid[behaviorEvent.Pid] = new Entry(
                    behaviorEvent.Pid,
                    behaviorEvent.ParentPid,
                    decision.State);
                return decision;
            }

            return ClassifyPidLocked(behaviorEvent.Pid);
        }
    }

    public ScopeDecision ClassifyPid(int pid)
    {
        lock (_gate)
        {
            return ClassifyPidLocked(pid);
        }
    }

    private ScopeDecision ClassifyPidLocked(int pid)
    {
        if (HasRoot && pid == RootPid)
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
        if (HasRoot && start.Pid == RootPid)
        {
            return new ScopeDecision(ProcessScopeState.Root, true, "root");
        }

        // PID 0 (Idle) and PID 4 (System) are not real user-mode processes and can
        // never be descendants of the monitored application. Without this check a
        // pathless PID 0 start is attributed by the orphan heuristic and its child
        // PID 4 then makes the whole system tree look confirmed.
        if (start.Pid is 0 or 4)
        {
            return new ScopeDecision(ProcessScopeState.Excluded, false, "system-pid");
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

        // No parent record. Prefer structural evidence over timing, but only when the root's
        // directory is application-specific. A shared directory such as System32 or Program
        // Files is evidence of nothing: attributing every process there would turn unrelated
        // system activity into session detections. Before a root is attached there is no
        // directory to reason about at all, so nothing qualifies.
        if (HasRoot
            && RootDirectory is not null
            && !IsSharedRootDirectory(RootDirectory)
            && start.ImagePath is not null
            && PathKey.IsUnder(PathKey.Canonicalize(start.ImagePath), RootDirectory))
        {
            return new ScopeDecision(ProcessScopeState.Unconfirmed, true, "image-under-root-directory");
        }

        // No structural evidence (parent record, app-specific directory or an
        // image path) means no attribution. Timing alone is not evidence: every
        // process on a busy machine starts near some other process.
        return new ScopeDecision(ProcessScopeState.Excluded, false, "parent-not-in-scope");
    }

    private static bool IsSharedRootDirectory(string canonicalDirectory)
    {
        // A drive root ("c:") contains everything on that drive.
        if (canonicalDirectory.Length <= 2 && canonicalDirectory.EndsWith(':'))
        {
            return true;
        }

        return SharedRootDirectories.Any(shared => PathKey.IsUnder(canonicalDirectory, shared));
    }

    private sealed record Entry(int Pid, int? ParentPid, ProcessScopeState State);
}
