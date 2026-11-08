namespace Argus.Analysis.Rules;

using Argus.Core.Events;

/// <summary>
/// The shipped rule set. Phase 1 ships the rules needed to prove the pipeline
/// end-to-end; the full catalogue (process, file, registry, network, cross-channel)
/// lands in Phase 3 with the same contract.
/// </summary>
public sealed class RuleCatalog
{
    private RuleCatalog(IReadOnlyList<IEventRule> eventRules, IReadOnlyList<ICorrelatedRule> correlatedRules)
    {
        EventRules = eventRules;
        CorrelatedRules = correlatedRules;
    }

    public IReadOnlyList<IEventRule> EventRules { get; }

    public IReadOnlyList<ICorrelatedRule> CorrelatedRules { get; }

    public IEnumerable<IRule> All => EventRules.Cast<IRule>().Concat(CorrelatedRules);

    public static RuleCatalog CreateDefault()
    {
        IEventRule[] eventRules =
        [
            new ShellSpawnRule(),
            new EncodedInterpreterRule(),
            new SensitiveWriteRule(
                new RuleMetadata(
                    "F-001",
                    "Write to an autostart location",
                    80,
                    EvidenceCategory.File,
                    ["T1547.001"],
                    "A file was created or modified in a location Windows executes at sign-in.",
                    BaseConfidence: 0.90),
                "persistence"),
            new SensitiveWriteRule(
                new RuleMetadata(
                    "F-005",
                    "Write to a system location",
                    65,
                    EvidenceCategory.File,
                    ["T1543", "T1574"],
                    "A file was created or modified in a protected system or program directory.",
                    BaseConfidence: 0.85),
                "system"),
            new DroppedExecutableRule(),
            new AutostartKeyRule(),
            new ScheduledTaskRule(),
            new MassFileCreationRule(),
            new DestructiveRenameBurstRule(),
            new CredentialStoreRule(),
            new BeaconingRule(),
            new OutboundVolumeRule(),
            new BarePublicIpRule(),
            new RiskyPortRule(),
        ];

        ICorrelatedRule[] correlatedRules =
        [
            new PersistenceThenNetworkRule(),
        ];

        return new RuleCatalog(eventRules, correlatedRules);
    }
}
