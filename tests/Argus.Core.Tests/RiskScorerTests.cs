namespace Argus.Core.Tests;

using Argus.Core.Events;
using Argus.Core.Risk;
using Argus.Core.Sessions;
using Xunit;

public sealed class RiskScorerTests
{
    private static readonly DateTimeOffset Now = new(2026, 5, 1, 10, 0, 0, TimeSpan.Zero);

    private static DetectionSignal Signal(
        string ruleId = "P-002",
        double severity = 85,
        double confidence = 0.9,
        EvidenceCategory categories = EvidenceCategory.Process,
        int ageMinutes = 0) =>
        new($"{ruleId}#1#1", ruleId, severity, confidence, categories, Now.AddMinutes(-ageMinutes));

    [Fact]
    public void No_signals_is_benign_and_never_claims_safety()
    {
        var assessment = RiskScorer.Evaluate([], Now);

        Assert.Equal(0, assessment.Score);
        Assert.Equal(RiskBand.Benign, assessment.Band);
        Assert.Contains("not proof", assessment.Explanation, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void High_risk_in_one_channel_stays_suspicious()
    {
        var assessment = RiskScorer.Evaluate(
            [Signal(severity: 70, confidence: 0.95, categories: EvidenceCategory.Process)],
            Now);

        Assert.True(assessment.Score >= RiskOptions.Default.MaliciousThreshold);
        Assert.Equal(RiskBand.Suspicious, assessment.Band);
        Assert.Contains("only one evidence category", assessment.Explanation);
    }

    [Fact]
    public void Independent_channels_unlock_the_malicious_band()
    {
        var assessment = RiskScorer.Evaluate(
            [
                Signal("F-001", 80, 0.9, EvidenceCategory.File),
                Signal("N-001", 70, 0.9, EvidenceCategory.Network),
            ],
            Now);

        Assert.Equal(RiskBand.Malicious, assessment.Band);
        Assert.True(assessment.Score >= RiskOptions.Default.MaliciousThreshold);
        Assert.Contains("file, network", assessment.Explanation);
        Assert.Equal(2, EvidenceCategories.DistinctCount(assessment.Categories));
    }

    [Fact]
    public void Critical_rule_satisfies_the_gate_on_its_own()
    {
        var assessment = RiskScorer.Evaluate(
            [Signal("X-001", 95, 0.95, EvidenceCategory.File)],
            Now);

        Assert.Equal(RiskBand.Malicious, assessment.Band);
        Assert.Contains("critical-severity rule", assessment.Explanation);
    }

    [Fact]
    public void Score_is_noisy_or_not_a_sum()
    {
        var one = RiskScorer.Evaluate([Signal(severity: 50, confidence: 0.5)], Now);
        var two = RiskScorer.Evaluate(
            [Signal("A", 50, 0.5), Signal("B", 50, 0.5)],
            Now);

        Assert.True(two.Score < one.Score * 2);
        Assert.True(two.Score > one.Score);
    }

    [Fact]
    public void Old_evidence_decays_to_the_floor()
    {
        var fresh = RiskScorer.Evaluate([Signal(ageMinutes: 0)], Now);
        var old = RiskScorer.Evaluate([Signal(ageMinutes: 240)], Now);

        Assert.True(old.Score < fresh.Score);
        Assert.Equal(RiskOptions.Default.DecayFloor, RiskScorer.Decay(TimeSpan.FromHours(4), RiskOptions.Default), 3);
        Assert.True(old.Score > 0);
    }

    [Fact]
    public void Peak_survives_a_quiet_period()
    {
        var assessment = RiskScorer.Evaluate([Signal(severity: 30, confidence: 0.5)], Now, previousPeak: 88);

        Assert.Equal(88, assessment.PeakScore);
        Assert.True(assessment.Score < 88);
    }

    [Fact]
    public void Corroboration_is_capped()
    {
        var assessment = RiskScorer.Evaluate(
            [
                Signal("A", 60, 0.9, EvidenceCategory.Process),
                Signal("B", 60, 0.9, EvidenceCategory.File),
                Signal("C", 60, 0.9, EvidenceCategory.Registry),
                Signal("D", 60, 0.9, EvidenceCategory.Network),
                Signal("E", 60, 0.9, EvidenceCategory.Dns),
            ],
            Now);

        Assert.Equal(RiskBand.Malicious, assessment.Band);
        Assert.True(assessment.Score <= 100);
        Assert.Equal(5, EvidenceCategories.DistinctCount(assessment.Categories));
    }

    [Fact]
    public void Single_severity_rule_raises_suspicious_below_score_threshold()
    {
        var assessment = RiskScorer.Evaluate([Signal(severity: 45, confidence: 0.25)], Now);

        Assert.True(assessment.Score < RiskOptions.Default.SuspiciousThreshold);
        Assert.Equal(RiskBand.Suspicious, assessment.Band);
        Assert.Contains("severity 45", assessment.Explanation);
    }

    [Fact]
    public void Contributions_expose_the_arithmetic()
    {
        var assessment = RiskScorer.Evaluate([Signal(severity: 80, confidence: 0.5)], Now);

        var contribution = Assert.Single(assessment.Contributions);
        Assert.Equal(80, contribution.Severity);
        Assert.Equal(0.5, contribution.Confidence, 3);
        Assert.Equal(0.4, contribution.Weight, 3);
    }
}
