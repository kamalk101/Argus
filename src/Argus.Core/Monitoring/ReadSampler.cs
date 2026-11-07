namespace Argus.Core.Monitoring;

using Argus.Core.Events;

/// <summary>
/// Read sampling for the file firehose. Writes, creates, deletes, renames and
/// every first read of a path are always kept; repeated reads are sampled so a
/// build or an editor cannot drown the session.
/// </summary>
public sealed class ReadSampler
{
    private readonly HashSet<(int Pid, string Path)> _firstReads = [];
    private readonly Dictionary<int, long> _readCounts = [];
    private readonly int _maxTrackedPaths;
    private int _sampleEvery;

    public ReadSampler(int sampleEvery = 50, int maxTrackedPaths = 100_000)
    {
        _sampleEvery = Math.Clamp(sampleEvery, 1, 10_000);
        _maxTrackedPaths = Math.Clamp(maxTrackedPaths, 1_000, 1_000_000);
    }

    public int SampleEvery => _sampleEvery;

    public int TrackedPaths => _firstReads.Count;

    public void SetSampleEvery(int sampleEvery) =>
        _sampleEvery = Math.Clamp(sampleEvery, 1, 10_000);

    /// <summary>
    /// True when this read should be recorded. Reads in sensitive locations are
    /// never sampled; an empty path key is kept because it cannot be deduplicated.
    /// </summary>
    public bool ShouldKeep(int pid, string? pathKey, bool sensitive)
    {
        if (sensitive || string.IsNullOrEmpty(pathKey))
        {
            return true;
        }

        if (_firstReads.Count >= _maxTrackedPaths)
        {
            // Bound memory on pathological sessions. Clearing loses the
            // "first read" optimisation but never loses a write.
            _firstReads.Clear();
            _readCounts.Clear();
        }

        if (_firstReads.Add((pid, pathKey)))
        {
            return true;
        }

        _readCounts.TryGetValue(pid, out var count);
        count++;
        _readCounts[pid] = count;
        return count % _sampleEvery == 0;
    }

    public bool IsWriteLike(EventKind kind) => kind != EventKind.FileRead;
}
