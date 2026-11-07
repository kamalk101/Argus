namespace Argus.Core.Risk;

/// <summary>
/// Confidence rises with the number of observations but saturates: seeing the
/// same behaviour ten times is not ten times the evidence. This keeps a single
/// strong observation from being dismissed and keeps repetition from inflating a
/// weak one.
/// </summary>
public static class ConfidenceModel
{
    public const double SaturationDivisor = 3.0;

    public static double ForEvidence(double baseConfidence, int evidenceCount, double divisor = SaturationDivisor)
    {
        if (evidenceCount <= 0 || divisor <= 0)
        {
            return 0;
        }

        var saturated = 1 - Math.Exp(-evidenceCount / divisor);
        return Math.Clamp(Math.Clamp(baseConfidence, 0, 1) * saturated, 0, 1);
    }
}
