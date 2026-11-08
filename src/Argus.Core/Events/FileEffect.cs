namespace Argus.Core.Events;

/// <summary>
/// What a file-touching event did to the file, as far as the sensor can tell.
///
/// This exists because ETW's kernel <c>FileIO/Create</c> covers several different
/// dispositions: opening an existing binary to load it and creating a new file are
/// the same record shape. The disposition is available from the sensor (TraceEvent
/// decodes it as <c>OPEN_EXISTING</c>, <c>CREATE_ALWAYS</c>, ...), and without it
/// "the application opened System32\PING.EXE" is indistinguishable from "the
/// application wrote System32\PING.EXE" — the false positive that made F-005 fire
/// on every process start.
///
/// Sensors that cannot report the disposition leave it null. Analysis must treat
/// that as "unknown", never as "written".
/// </summary>
public enum FileEffect
{
    /// <summary>Touched, but the sensor cannot say how (for example <c>OPEN_ALWAYS</c>).</summary>
    Unknown = 0,

    /// <summary>The file already existed and was opened, not created or truncated.</summary>
    Opened = 1,

    /// <summary>The file was created, replaced or truncated, so its content changed.</summary>
    CreatedOrTruncated = 2,
}
