namespace Argus.Analysis.Pipeline;

/// <summary>
/// How much of the session the sensor actually saw.
///
/// This exists because "no detections" and "nothing happened" are different claims, and the report
/// must not let the first read as the second. Collection gaps are already recorded one by one; this
/// is the same information stated once, in the form a verdict rule can consult.
///
/// Deliberately not a penalty on the score. Subtracting a number for missing events would be
/// invented precision: a dropped event is not evidence of anything, and a rule that counted 199
/// of 300 creates did not become *less* of a burst. What gaps do is forbid the reading that a
/// quiet result is a clean one.
/// </summary>
public sealed record CoverageAssessment
{
    public required bool Complete { get; init; }

    public required int Gaps { get; init; }

    /// <summary>Distinct gap reasons, in first-seen order, so the report names what was missing.</summary>
    public required IReadOnlyList<string> Reasons { get; init; }

    /// <summary>One sentence the report can publish verbatim.</summary>
    public required string Statement { get; init; }

    public static CoverageAssessment From(IReadOnlyList<GapEntry> gaps)
    {
        ArgumentNullException.ThrowIfNull(gaps);

        if (gaps.Count == 0)
        {
            return new CoverageAssessment
            {
                Complete = true,
                Gaps = 0,
                Reasons = [],
                Statement = "No collection gaps were reported: every event the sensor produced reached the analysis.",
            };
        }

        var reasons = new List<string>();
        foreach (var gap in gaps)
        {
            if (!reasons.Contains(gap.Reason, StringComparer.Ordinal))
            {
                reasons.Add(gap.Reason);
            }
        }

        return new CoverageAssessment
        {
            Complete = false,
            Gaps = gaps.Count,
            Reasons = reasons,
            Statement = string.Create(
                System.Globalization.CultureInfo.InvariantCulture,
                $"{gaps.Count} collection gap(s) were reported ({string.Join(", ", reasons)}). This report describes what was observed; activity during a gap is missing from it rather than absent from the device, so a quiet result is a lower bound and not an all-clear."),
        };
    }
}
