namespace Argus.Core.Sessions;

/// <summary>
/// Three-way classification. <see cref="Benign"/> means "no significant
/// indicators were observed", never "safe".
/// </summary>
public enum RiskBand
{
    Benign,
    Suspicious,
    Malicious,
}

public enum ProcessScopeState
{
    /// <summary>The selected application itself.</summary>
    Root,

    /// <summary>Parent chain reaches a confirmed member of the tree.</summary>
    Confirmed,

    /// <summary>Attributed to the tree by evidence, but the link was not observed.</summary>
    Unconfirmed,

    /// <summary>Outside the monitored tree; events are counted but not analysed.</summary>
    Excluded,

    /// <summary>No process record seen yet.</summary>
    Unknown,
}

public enum DetectionStatus
{
    Open,
    Escalated,
    Closed,
}
