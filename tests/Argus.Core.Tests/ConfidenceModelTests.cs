namespace Argus.Core.Tests;

using Argus.Core.Risk;
using Xunit;

public sealed class ConfidenceModelTests
{
    [Fact]
    public void First_observation_is_discounted_but_present()
    {
        var confidence = ConfidenceModel.ForEvidence(0.9, 1);

        Assert.InRange(confidence, 0.24, 0.27);
    }

    [Fact]
    public void Repetition_saturates()
    {
        var one = ConfidenceModel.ForEvidence(0.9, 1);
        var three = ConfidenceModel.ForEvidence(0.9, 3);
        var thirty = ConfidenceModel.ForEvidence(0.9, 30);

        Assert.True(one < three);
        Assert.True(three < thirty);
        Assert.True(thirty < 0.9);
        Assert.True(thirty > 0.85);
    }

    [Fact]
    public void Zero_or_negative_evidence_has_zero_confidence()
    {
        Assert.Equal(0, ConfidenceModel.ForEvidence(0.9, 0));
        Assert.Equal(0, ConfidenceModel.ForEvidence(0.9, -3));
    }
}
