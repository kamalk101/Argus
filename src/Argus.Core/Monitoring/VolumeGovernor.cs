namespace Argus.Core.Monitoring;

/// <summary>
/// The volume fuse from the monitoring plan: when the file/network firehose
/// stays above a threshold, read sampling is raised and a gap is recorded so the
/// UI can say "reads were sampled during this window" instead of pretending the
/// session was complete.
/// </summary>
public sealed class VolumeGovernor
{
    private readonly int _thresholdPerSecond;
    private readonly int _sustainedSeconds;
    private readonly int _coolSeconds;
    private readonly int _minSampleEvery;
    private readonly int _maxSampleEvery;
    private int _hotSeconds;
    private int _coolSecondsObserved;
    private DateTimeOffset _windowStart;
    private long _windowCount;
    private bool _initialized;

    public VolumeGovernor(
        int thresholdPerSecond = 8_000,
        int sustainedSeconds = 5,
        int coolSeconds = 10,
        int minSampleEvery = 50,
        int maxSampleEvery = 500)
    {
        _thresholdPerSecond = Math.Max(1, thresholdPerSecond);
        _sustainedSeconds = Math.Max(1, sustainedSeconds);
        _coolSeconds = Math.Max(1, coolSeconds);
        _minSampleEvery = Math.Clamp(minSampleEvery, 1, 10_000);
        _maxSampleEvery = Math.Clamp(maxSampleEvery, _minSampleEvery, 10_000);
    }

    public bool Throttled { get; private set; }

    public int SampleEvery { get; private set; } = 1;

    public long LastEventsPerSecond { get; private set; }

    /// <summary>Returns a change only when the fuse opens or closes.</summary>
    public VolumeChange? Observe(DateTimeOffset now)
    {
        if (!_initialized)
        {
            _windowStart = now;
            _initialized = true;
        }

        _windowCount++;
        var elapsed = now - _windowStart;
        if (elapsed < TimeSpan.FromSeconds(1))
        {
            return null;
        }

        var rate = elapsed.TotalSeconds <= 0
            ? _windowCount
            : (long)(_windowCount / elapsed.TotalSeconds);
        _windowCount = 0;
        _windowStart = now;
        LastEventsPerSecond = rate;

        if (rate >= _thresholdPerSecond)
        {
            _hotSeconds++;
            _coolSecondsObserved = 0;
        }
        else if (rate <= _thresholdPerSecond / 2)
        {
            _coolSecondsObserved++;
            _hotSeconds = 0;
        }
        else
        {
            _hotSeconds = 0;
            _coolSecondsObserved = 0;
        }

        if (!Throttled && _hotSeconds >= _sustainedSeconds)
        {
            Throttled = true;
            var multiplier = Math.Max(2, (int)(rate / _thresholdPerSecond));
            SampleEvery = Math.Clamp(_minSampleEvery * multiplier, _minSampleEvery, _maxSampleEvery);
            return new VolumeChange(true, SampleEvery, rate, "volume-throttle");
        }

        if (Throttled && _coolSecondsObserved >= _coolSeconds)
        {
            Throttled = false;
            SampleEvery = 1;
            return new VolumeChange(false, SampleEvery, rate, "volume-recovered");
        }

        return null;
    }
}

public sealed record VolumeChange(bool Throttled, int SampleEvery, long EventsPerSecond, string Reason);
