namespace Argus.Core.Diagnostics;

/// <summary>
/// Turns an ETW session-start failure into a sentence an operator can act on.
///
/// Measured while wiring the dashboard launch flow: after three agents had been killed with
/// Task Manager, the next launch failed with <c>0x800705AA</c> ("Insufficient system resources") and
/// the only visible symptom was a 500 from <c>POST /api/sessions</c>. The cause was six dead
/// <c>Argus-*</c> kernel sessions still registered — the machine's ETW session slots were full, not
/// the machine's memory. That error must never be reported as a generic failure.
/// </summary>
public static class EtwStartFailure
{
    /// <summary>ERROR_NO_SYSTEM_RESOURCES — the active ETW session limit has been reached.</summary>
    public const int NoSystemResources = unchecked((int)0x800705AA);

    /// <summary>ERROR_ACCESS_DENIED — administrative rights are required for kernel sessions.</summary>
    public const int AccessDenied = unchecked((int)0x80070005);

    public const string SessionNamePrefix = "Argus-";

    /// <summary>
    /// The explanation for a failed start. Unknown failures keep their own message: inventing a cause
    /// for an error nobody has diagnosed is how a real defect gets buried under a plausible story.
    /// </summary>
    public static string Explain(int? hresult, string? message)
    {
        var detail = string.IsNullOrWhiteSpace(message) ? null : message.Trim();

        switch (hresult)
        {
            case NoSystemResources:
                return "Windows refused a new ETW kernel session: the machine is at its active-session limit. "
                    + "A previous Argus run that was killed rather than stopped still holds a session — "
                    + "`logman query -ets` lists them, `logman stop <name> -ets` frees one. Argus also reclaims "
                    + "its own stale sessions at startup, so restarting the agent is enough in that case.";
            case AccessDenied:
                return "Windows refused a new ETW kernel session: administrator rights are required. "
                    + "Start Argus through UAC (the default) rather than --allow-non-elevated.";
            default:
                return detail ?? "the ETW session could not be started (no error detail was reported).";
        }
    }

    /// <summary>
    /// The sessions an agent may reclaim: names it created itself. Anything else — another product's
    /// session, or the classic "NT Kernel Logger" — belongs to someone else and must be left running.
    /// </summary>
    public static IReadOnlyList<string> Reclaimable(IEnumerable<string>? activeSessionNames)
    {
        if (activeSessionNames is null)
        {
            return Array.Empty<string>();
        }

        return activeSessionNames
            .Where(name => !string.IsNullOrWhiteSpace(name))
            .Where(name => name!.StartsWith(SessionNamePrefix, StringComparison.Ordinal))
            .OrderBy(name => name, StringComparer.Ordinal)
            .ToArray();
    }
}
