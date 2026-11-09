namespace Argus.Core.Tests;

using Argus.Core.Diagnostics;
using Xunit;

/// <summary>
/// The wording here is load-bearing: a full ETW session table looks exactly like a memory problem,
/// and "Insufficient system resources" sends an operator to look at RAM while six dead sessions from
/// a killed agent sit in the table.
/// </summary>
public sealed class EtwStartFailureTests
{
    [Fact]
    public void A_full_session_table_is_explained_as_dead_sessions_not_as_memory()
    {
        var text = EtwStartFailure.Explain(EtwStartFailure.NoSystemResources, "Insufficient system resources exist to complete the requested service. (0x800705AA)");

        Assert.Contains("active-session limit", text);
        Assert.Contains("logman stop", text);
        // The trap: repeating the platform message sends the reader after the wrong cause.
        Assert.DoesNotContain("0x800705AA", text);
        Assert.DoesNotContain("memory", text, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Access_denied_names_elevation_as_the_fix()
    {
        var text = EtwStartFailure.Explain(EtwStartFailure.AccessDenied, "Access is denied.");

        Assert.Contains("administrator", text);
        Assert.Contains("--allow-non-elevated", text);
    }

    [Fact]
    public void An_unrecognised_failure_keeps_its_own_message()
    {
        var text = EtwStartFailure.Explain(unchecked((int)0x80004005), "the provider registration failed");

        Assert.Equal("the provider registration failed", text);
    }

    [Fact]
    public void A_failure_without_a_message_says_so_instead_of_inventing_a_cause()
    {
        var text = EtwStartFailure.Explain(null, null);

        Assert.Contains("could not be started", text);
        Assert.Contains("no error detail", text);
    }

    [Fact]
    public void Only_the_agents_own_sessions_are_reclaimable()
    {
        var names = EtwStartFailure.Reclaimable(new[]
        {
            "Argus-55fdcfabfc7a4930bfa7e0aaeab66cf2",
            "NT Kernel Logger",
            "SimplePerf_abc",
            "Argus-0000",
            "",
            null!,
        });

        Assert.Equal(2, names.Count);
        Assert.Equal("Argus-0000", names[0]);
        Assert.Equal("Argus-55fdcfabfc7a4930bfa7e0aaeab66cf2", names[1]);
    }

    [Fact]
    public void A_reader_with_no_view_of_the_session_table_reclaims_nothing()
    {
        Assert.Empty(EtwStartFailure.Reclaimable(null));
    }
}
