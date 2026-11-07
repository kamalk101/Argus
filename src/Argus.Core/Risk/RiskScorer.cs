namespace Argus.Core.Risk;

using System.Globalization;
using Argus.Core.Events;
using Argus.Core.Sessions;

/// <summary>
/// The risk model: weighted noisy-OR over independent detections, with a
/// corroboration bonus and a malicious gate that refuses a verdict on a single
/// evidence channel. Deliberately transparent — the explanation quotes the
/// numbers it used.
/// </summary>
public static class RiskScorer
{
    public static RiskAssessment Evaluate(
        IReadOnlyCollection<DetectionSignal>? signals,
        DateTimeOffset now,
        RiskOptions? options = null,
        double previousPeak = 0)
    {
        var opts = options ?? RiskOptions.Default;
        var peak = Math.Max(previousPeak, 0);

        if (signals is null || signals.Count == 0)
        {
            return new RiskAssessment
            {
                Score = 0,
                Band = RiskBand.Benign,
                PeakScore = peak,
                Contributions = [],
                Categories = EvidenceCategory.None,
                Explanation = "No detection rule matched. This is the absence of observed indicators, not proof that the application is safe.",
            };
        }

        var remaining = 1.0;
        var contributions = new List<RiskContribution>(signals.Count);
        var categories = EvidenceCategory.None;

        foreach (var signal in signals)
        {
            var age = now - signal.LastSeenUtc;
            if (age < TimeSpan.Zero)
            {
                age = TimeSpan.Zero;
            }

            var decay = Decay(age, opts);
            var severity = Math.Clamp(signal.Severity, 0, 100);
            var confidence = Math.Clamp(signal.Confidence, 0, 1);
            var weight = Math.Clamp(severity / 100.0 * confidence * decay, 0, 0.999);

            remaining *= 1 - weight;
            categories |= signal.Categories;
            contributions.Add(new RiskContribution(
                signal.Key,
                signal.RuleId,
                severity,
                confidence,
                Math.Round(weight, 3),
                age,
                signal.Categories));
        }

        var baseScore = 1 - remaining;
        var independent = Math.Max(1, EvidenceCategories.DistinctCount(categories));
        var corroboration = Math.Min(opts.CorroborationCap, 1 + (opts.CorroborationStep * (independent - 1)));
        var score = Math.Clamp(
            Math.Round(baseScore * corroboration * 100, 1, MidpointRounding.AwayFromZero),
            0,
            100);

        var critical = signals.Any(s => s.Severity >= opts.CriticalSeverity && s.Confidence >= opts.CriticalConfidence);
        var highestSeverity = signals.Max(s => s.Severity);

        var (band, explanation) = Decide(score, baseScore, corroboration, independent, categories, critical, highestSeverity, opts);
        peak = Math.Max(peak, score);

        return new RiskAssessment
        {
            Score = score,
            Band = band,
            PeakScore = peak,
            Contributions = contributions,
            Categories = categories,
            Explanation = explanation,
        };
    }

    public static double Decay(TimeSpan age, RiskOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        var halfLife = options.DecayHalfLife.TotalSeconds;
        if (halfLife <= 0)
        {
            return 1;
        }

        var halfLives = age.TotalSeconds / halfLife;
        return Math.Max(options.DecayFloor, Math.Pow(0.5, halfLives));
    }

    private static (RiskBand Band, string Explanation) Decide(
        double score,
        double baseScore,
        double corroboration,
        int independent,
        EvidenceCategory categories,
        bool critical,
        double highestSeverity,
        RiskOptions options)
    {
        var channels = EvidenceCategories.Describe(categories);
        var arithmetic = string.Create(
            CultureInfo.InvariantCulture,
            $"base {baseScore * 100:0.0} × corroboration {corroboration:0.00} = {score:0.0}");

        if (score >= options.MaliciousThreshold)
        {
            if (independent >= 2 || critical)
            {
                var reason = critical && independent < 2
                    ? "a critical-severity rule fired"
                    : $"{independent} independent evidence categories ({channels})";

                return (
                    RiskBand.Malicious,
                    string.Create(
                        CultureInfo.InvariantCulture,
                        $"Risk {score:0.0} is at or above the malicious threshold {options.MaliciousThreshold:0.0}, corroborated by {reason}. ({arithmetic}.)"));
            }

            return (
                RiskBand.Suspicious,
                string.Create(
                    CultureInfo.InvariantCulture,
                    $"Risk {score:0.0} exceeds the malicious threshold {options.MaliciousThreshold:0.0}, but only one evidence category ({channels}) is represented and no critical rule fired, so the verdict stays suspicious. ({arithmetic}.)"));
        }

        if (score >= options.SuspiciousThreshold || highestSeverity >= options.CategoryRuleSeverity)
        {
            var trigger = score >= options.SuspiciousThreshold
                ? string.Create(CultureInfo.InvariantCulture, $"risk {score:0.0} is between the suspicious threshold {options.SuspiciousThreshold:0.0} and the malicious threshold {options.MaliciousThreshold:0.0}")
                : string.Create(CultureInfo.InvariantCulture, $"a single rule at severity {highestSeverity:0} fired without enough corroboration to raise the score");

            return (
                RiskBand.Suspicious,
                string.Create(CultureInfo.InvariantCulture, $"Behaviour requires investigation: {trigger}. ({arithmetic}.)"));
        }

        return (
            RiskBand.Benign,
            string.Create(
                CultureInfo.InvariantCulture,
                $"Current risk {score:0.0} is below the suspicious threshold {options.SuspiciousThreshold:0.0}. No significant indicators were observed; that is not proof of safety. ({arithmetic}.)"));
    }
}
