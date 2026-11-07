namespace Argus.Core.Tests;

using Argus.Core.Events;
using Argus.Core.Processes;
using Argus.Core.Sessions;
using Xunit;

public sealed class ScopeTrackerTests
{
    private static readonly DateTimeOffset Start = new(2026, 5, 1, 10, 0, 0, TimeSpan.Zero);

    private static BehaviorEvent Event(EventKind kind, int pid, int? parentPid = null, string? imagePath = null, int offsetMs = 0) => new()
    {
        SessionId = Guid.Empty,
        Seq = 1,
        TimestampUtc = Start.AddMilliseconds(offsetMs),
        Kind = kind,
        Category = EventKinds.CategoryOf(kind),
        Pid = pid,
        ParentPid = parentPid,
        ImageName = imagePath is null ? null : Path.GetFileName(imagePath),
        ImagePath = imagePath,
        Observability = Observability.Direct,
        Confidence = 0.9,
        Source = EventSourceKind.Replay,
    };

    [Fact]
    public void Root_is_always_in_scope()
    {
        var tracker = new ProcessScopeTracker(4312, @"C:\argus-test\sample.exe");

        Assert.True(tracker.ClassifyPid(4312).InScope);
        Assert.Equal(ProcessScopeState.Root, tracker.ClassifyPid(4312).State);
    }

    [Fact]
    public void Child_of_confirmed_process_is_confirmed()
    {
        var tracker = new ProcessScopeTracker(4312, @"C:\argus-test\sample.exe");
        tracker.Observe(Event(EventKind.ProcessStart, 4312, 9999, @"C:\argus-test\sample.exe"));

        var decision = tracker.Observe(Event(EventKind.ProcessStart, 5000, 4312, @"C:\Windows\System32\cmd.exe", 100));

        Assert.Equal(ProcessScopeState.Confirmed, decision.State);
        Assert.True(decision.InScope);
    }

    [Fact]
    public void Unknown_parent_outside_root_directory_is_excluded()
    {
        var tracker = new ProcessScopeTracker(4312, @"C:\argus-test\sample.exe");
        tracker.Observe(Event(EventKind.ProcessStart, 4312, 9999, @"C:\argus-test\sample.exe"));

        var decision = tracker.Observe(Event(EventKind.ProcessStart, 5000, 777, @"C:\Program Files\Other\other.exe", 100));

        Assert.Equal(ProcessScopeState.Excluded, decision.State);
        Assert.False(decision.InScope);
    }

    [Fact]
    public void Missing_parent_but_image_under_root_directory_is_unconfirmed()
    {
        var tracker = new ProcessScopeTracker(4312, @"C:\argus-test\sample.exe");
        tracker.Observe(Event(EventKind.ProcessStart, 4312, 9999, @"C:\argus-test\sample.exe"));

        var decision = tracker.Observe(Event(EventKind.ProcessStart, 6000, 0, @"C:\argus-test\bin\helper.exe", 400));

        Assert.Equal(ProcessScopeState.Unconfirmed, decision.State);
        Assert.True(decision.InScope);
        Assert.Equal("image-under-root-directory", decision.Reason);
    }

    [Fact]
    public void Missing_parent_under_shared_system_directory_is_excluded()
    {
        // Regression from a live notepad capture: RuntimeBroker.exe starts in
        // System32 with an unknown parent. Sharing notepad's directory is not
        // evidence that it belongs to notepad's tree.
        var tracker = new ProcessScopeTracker(5592, @"C:\Windows\System32\notepad.exe");
        tracker.Observe(Event(EventKind.ProcessStart, 5592, 9999, @"C:\Windows\System32\notepad.exe"));

        var decision = tracker.Observe(Event(EventKind.ProcessStart, 2996, 832, @"C:\Windows\System32\RuntimeBroker.exe", 714));

        Assert.Equal(ProcessScopeState.Excluded, decision.State);
        Assert.False(decision.InScope);
        Assert.Equal("parent-not-in-scope", decision.Reason);
    }

    [Fact]
    public void Orphan_without_path_inside_window_is_unconfirmed()
    {
        var tracker = new ProcessScopeTracker(4312, @"C:\argus-test\sample.exe");
        tracker.Observe(Event(EventKind.ProcessStart, 4312, 9999, @"C:\argus-test\sample.exe"));

        var decision = tracker.Observe(Event(EventKind.ProcessStart, 6100, 0, null, 500));

        Assert.Equal(ProcessScopeState.Unconfirmed, decision.State);
        Assert.Equal("orphan-window", decision.Reason);
    }

    [Fact]
    public void Orphan_without_path_outside_window_is_excluded()
    {
        var tracker = new ProcessScopeTracker(4312, @"C:\argus-test\sample.exe");
        tracker.Observe(Event(EventKind.ProcessStart, 4312, 9999, @"C:\argus-test\sample.exe"));

        var decision = tracker.Observe(Event(EventKind.ProcessStart, 6100, 0, null, 60_000));

        Assert.Equal(ProcessScopeState.Excluded, decision.State);
    }

    [Fact]
    public void Event_from_unseen_pid_is_excluded()
    {
        var tracker = new ProcessScopeTracker(4312, @"C:\argus-test\sample.exe");

        var decision = tracker.ClassifyPid(9999);

        Assert.False(decision.InScope);
        Assert.Equal("pid-not-seen", decision.Reason);
    }
}
