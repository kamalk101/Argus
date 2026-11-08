namespace Argus.Analysis.Rules;

using Argus.Core.Events;

/// <summary>
/// Decides whether a file event proves that a file's content or existence changed,
/// which is the only thing that may back a "write happened here" detection.
///
/// ETW's kernel <c>FileIO/Create</c> covers both opening an existing file and creating
/// one: running <c>PING.EXE</c> produces a <see cref="EventKind.FileCreate"/> for
/// <c>C:\Windows\System32\PING.EXE</c>, exactly like writing a DLL there. Firing
/// F-005/F-001 on that flagged every process start on the machine (measured: opening
/// ping.exe in System32 produced an F-005 "system write").
///
/// The sensor's decoded create disposition settles it (<see cref="FileEffect"/>):
/// <c>OPEN_EXISTING</c> is an open, <c>CREATE_ALWAYS</c>/<c>CREATE_NEW</c>/
/// <c>TRUNCATE_EXISTING</c> changed the content. Where the sensor cannot say — older
/// recordings, sensors with no disposition, or <c>OPEN_ALWAYS</c> — the event counts
/// only if bytes were attributed to it.
///
/// Do not "fix" a missing detection by treating an ambiguous create as a write: that
/// is exactly the false positive this replaced.
/// </summary>
internal static class FileChangeEvidence
{
    public static bool IsContentChange(BehaviorEvent behaviorEvent)
    {
        ArgumentNullException.ThrowIfNull(behaviorEvent);

        return behaviorEvent.Kind switch
        {
            EventKind.FileWrite or EventKind.FileDelete or EventKind.FileRename => true,
            EventKind.FileCreate => behaviorEvent.FileEffect switch
            {
                FileEffect.CreatedOrTruncated => true,
                FileEffect.Opened => false,
                _ => behaviorEvent.BytesOut is > 0,
            },
            _ => false,
        };
    }

    /// <summary>Verb for reason text, matching the evidence that actually fired.</summary>
    public static string Operation(EventKind kind) => kind switch
    {
        EventKind.FileCreate => "created",
        EventKind.FileWrite => "modified",
        EventKind.FileRename => "renamed or moved into",
        EventKind.FileDelete => "deleted",
        _ => "touched",
    };

    /// <summary>Machine-readable evidence label for the finding's factor list.</summary>
    public static string Evidence(BehaviorEvent behaviorEvent) => behaviorEvent.Kind switch
    {
        EventKind.FileCreate => behaviorEvent.FileEffect == FileEffect.CreatedOrTruncated
            ? "create"
            : "create-with-bytes",
        EventKind.FileWrite => "write",
        EventKind.FileRename => "rename",
        EventKind.FileDelete => "delete",
        _ => "unknown",
    };
}
