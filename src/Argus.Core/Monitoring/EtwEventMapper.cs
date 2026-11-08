namespace Argus.Core.Monitoring;

using System.Globalization;
using System.Net;
using System.Text.Json;
using Argus.Core.Events;

/// <summary>
/// Converts ETW records into the sensor-neutral <see cref="RawEvent"/> contract.
///
/// Kept free of Windows types so the mapping rules can be exercised on Linux.
/// The Windows collector is responsible only for turning a TraceEvent into an
/// <see cref="EtwRecord"/> and for supplying live process metadata.
/// </summary>
public sealed class EtwEventMapper
{
    private const int MaxFileKeyEntries = 100_000;

    private readonly Func<string, string> _resolvePath;
    private readonly Dictionary<ulong, string> _fileKeys = [];
    private readonly Dictionary<(int Pid, ulong Handle), string> _registryKeys = [];

    private const int MaxRegistryKeys = 20_000;
    private readonly Queue<ulong> _fileKeyOrder = [];

    public EtwEventMapper(Func<string, string>? resolvePath = null)
    {
        _resolvePath = resolvePath ?? (path => path);
    }

    public int CachedFileKeys => _fileKeys.Count;

    public RawEvent? Map(EtwRecord record, ProcessMetadata? metadata = null)
    {
        ArgumentNullException.ThrowIfNull(record);

        // No catch-all here on purpose: a record this method cannot understand must be
        // distinguishable from one it deliberately ignores, so the collector counts a
        // malformed payload as a mapping failure and a known-but-uninteresting kind as
        // simply unmapped. The collector is the boundary that keeps a bad record from
        // stopping collection.
        var name = record.EventName;
        if (name.Contains("Process", StringComparison.OrdinalIgnoreCase))
        {
            return MapProcess(record, metadata, name);
        }

        if (name.Contains("FileIO", StringComparison.OrdinalIgnoreCase))
        {
            return MapFile(record, name);
        }

        if (name.Contains("TcpIp", StringComparison.OrdinalIgnoreCase))
        {
            return MapNetwork(record, name);
        }

        if (name.Contains("Registry", StringComparison.OrdinalIgnoreCase))
        {
            return MapRegistry(record, name);
        }

        if (IsDns(record))
        {
            return MapDns(record);
        }

        return null;
    }

    private RawEvent? MapProcess(EtwRecord record, ProcessMetadata? metadata, string name)
    {
        var isStart = name.Contains("Start", StringComparison.OrdinalIgnoreCase)
            || record.EventId is 1 or 3;
        var isStop = name.Contains("Stop", StringComparison.OrdinalIgnoreCase)
            || record.EventId is 2 or 4;

        if (!isStart && !isStop)
        {
            return null;
        }

        if (isStop)
        {
            return new RawEvent
            {
                Ts = record.TimestampUtc,
                Kind = EventKind.ProcessStop,
                Pid = record.Pid,
                Tid = record.Tid,
                ImageName = metadata is null ? null : FileNameOf(metadata.ImagePath),
                ImagePath = metadata?.ImagePath,
                Observability = metadata is null ? Observability.Partial : Observability.Direct,
                Source = EventSourceKind.Etw,
            };
        }

        var imagePath = metadata?.ImagePath ?? FirstString(record, "ImagePath", "ImageName");
        var commandLine = FirstString(record, "CommandLine") ?? metadata?.CommandLine;
        var parent = FirstInt(record, "ParentID", "ParentId", "ParentPid") ?? metadata?.ParentPid;
        var imageName = FirstString(record, "ImageFileName", "ImageName", "ProcessName")
            ?? FileNameOf(imagePath);

        return new RawEvent
        {
            Ts = record.TimestampUtc,
            Kind = EventKind.ProcessStart,
            Pid = record.Pid,
            Tid = record.Tid,
            ParentPid = parent,
            ImageName = imageName,
            ImagePath = imagePath,
            CommandLine = commandLine,
            Observability = string.IsNullOrEmpty(imagePath) ? Observability.Partial : Observability.Direct,
            Source = EventSourceKind.Etw,
        };
    }

    private RawEvent? MapFile(EtwRecord record, string name)
    {
        var kind = KindOfFileEvent(name);
        if (kind is null)
        {
            return null;
        }

        if (kind == EventKind.FileRename)
        {
            var oldPath = Resolve(FirstString(record, "FileName", "OldName", "Path"));
            var newPath = Resolve(FirstString(record, "FileName2", "NewName"));
            if (string.IsNullOrEmpty(newPath))
            {
                newPath = oldPath;
            }

            if (string.IsNullOrEmpty(newPath))
            {
                // A rename whose paths cannot be resolved is lost evidence, not an
                // uninteresting kind: it must reach the session so the gap is visible.
                return UnresolvedPathEvent(record, EventKind.FileRename, null);
            }

            return new RawEvent
            {
                Ts = record.TimestampUtc,
                Kind = EventKind.FileRename,
                Pid = record.Pid,
                Tid = record.Tid,
                Target = newPath,
                Detail = JsonSerializer.Serialize(new Dictionary<string, string?>
                {
                    ["oldPath"] = string.IsNullOrEmpty(oldPath) ? null : oldPath,
                }),
                Observability = Observability.Direct,
                Source = EventSourceKind.Etw,
            };
        }

        var fileKey = FirstUInt64(record, "FileKey");
        var path = FirstString(record, "FileName", "OpenPath", "Path");

        if (string.IsNullOrEmpty(path) && fileKey is { } key && _fileKeys.TryGetValue(key, out var cached))
        {
            path = cached;
        }

        path = Resolve(path);
        if (string.IsNullOrEmpty(path))
        {
            // Returning null here counted as "deliberately ignored" (Unmapped), which
            // reads as an uninteresting kind. It is actually a file event whose path we
            // could not resolve (no FileName, no OpenPath, no cached FileKey), so the
            // event is emitted with Partial observability and no target. Loss must be
            // recorded and shown, never hidden.
            return UnresolvedPathEvent(record, kind.Value, fileKey);
        }

        if (kind == EventKind.FileCreate && fileKey is { } createKey)
        {
            RememberFileKey(createKey, path);
        }
        else if (kind == EventKind.FileDelete && fileKey is { } deleteKey)
        {
            _fileKeys.Remove(deleteKey);
        }

        var size = FileSize(record);

        return new RawEvent
        {
            Ts = record.TimestampUtc,
            Kind = kind.Value,
            Pid = record.Pid,
            Tid = record.Tid,
            Target = path,
            // Byte counts belong in the contract fields, not only in Detail: the rules
            // must be able to tell a create that carried content from an empty one.
            BytesOut = kind is EventKind.FileCreate or EventKind.FileWrite ? size : null,
            BytesIn = kind is EventKind.FileRead ? size : null,
            FileEffect = kind == EventKind.FileCreate ? CreateEffect(record, path) : null,
            Detail = FileDetail(record, kind.Value),
            Observability = Observability.Direct,
            Source = EventSourceKind.Etw,
        };
    }

    /// <summary>
    /// Reads the create disposition that TraceEvent already decoded for us. Kernel
    /// <c>FileIO/Create</c> is "create or open", and this field is the only thing that
    /// separates the two: <c>OPEN_EXISTING</c> is an open of a file that already
    /// existed, while <c>CREATE_ALWAYS</c>/<c>CREATE_NEW</c>/<c>TRUNCATE_EXISTING</c>
    /// changed its content. <c>OPEN_ALWAYS</c> is genuinely ambiguous.
    ///
    /// A directory create is the same record shape but has no content, so it is left
    /// Unknown: creating a directory is not writing a file.
    /// </summary>
    private static FileEffect? CreateEffect(EtwRecord record, string? path)
    {
        if (IsDirectory(record) || (path is not null && path.EndsWith('\\')))
        {
            return FileEffect.Unknown;
        }

        var disposition = FirstString(record, "CreateDisposition");
        if (disposition is null)
        {
            return null;
        }

        return disposition.ToUpperInvariant() switch
        {
            "CREATE_ALWAYS" or "CREATE_NEW" or "SUPERSEDE" or "TRUNCATE_EXISTING"
                => FileEffect.CreatedOrTruncated,
            "OPEN_EXISTING" or "OPEN" => FileEffect.Opened,
            _ => FileEffect.Unknown,
        };
    }

    /// <summary>
    /// A directory create is reported as a Create record too, with
    /// <c>FileAttributes=Normal</c> — the directory bit is in the create options
    /// (<c>FILE_DIRECTORY_FILE = 0x1</c>), which is what Windows sets when
    /// CryptSvc recreates <c>System32\CatRoot2</c> during signature checks. Without
    /// this check that directory creation reads as a system file write.
    /// </summary>
    private static bool IsDirectory(EtwRecord record)
    {
        const long FileDirectoryFile = 0x1;
        const long AttributeDirectory = 0x10;

        return HasFlag(record, "CreateOptions", FileDirectoryFile)
            || HasFlag(record, "FileAttributes", AttributeDirectory)
            || AttributeTextContainsDirectory(record);
    }

    private static bool HasFlag(EtwRecord record, string name, long mask)
    {
        if (!record.Payload.TryGetValue(name, out var value) || value is null)
        {
            return false;
        }

        try
        {
            var numeric = value switch
            {
                byte[] { Length: 4 } bytes => BitConverter.ToUInt32(bytes, 0),
                byte[] { Length: 8 } bytes => (long)BitConverter.ToUInt64(bytes, 0),
                _ => Convert.ToInt64(value, CultureInfo.InvariantCulture),
            };

            return (numeric & mask) != 0;
        }
        catch (Exception exception) when (exception is FormatException or InvalidCastException or OverflowException)
        {
            // A payload shape we cannot read leaves the attribute unknown, which is not
            // a decode failure of the record itself.
            return false;
        }
    }

    private static bool AttributeTextContainsDirectory(EtwRecord record) =>
        FirstString(record, "FileAttributes")?.Contains("DIRECTORY", StringComparison.OrdinalIgnoreCase) == true;

    private static RawEvent UnresolvedPathEvent(EtwRecord record, EventKind kind, ulong? fileKey)
    {
        var detail = new Dictionary<string, string?>
        {
            ["pathUnresolved"] = "true",
        };

        if (fileKey is { } key)
        {
            detail["fileKey"] = key.ToString(CultureInfo.InvariantCulture);
        }

        return new RawEvent
        {
            Ts = record.TimestampUtc,
            Kind = kind,
            Pid = record.Pid,
            Tid = record.Tid,
            Detail = JsonSerializer.Serialize(detail),
            Observability = Observability.Partial,
            Source = EventSourceKind.Etw,
        };
    }

    private static EventKind? KindOfFileEvent(string name)
    {
        if (name.Contains("Rename", StringComparison.OrdinalIgnoreCase))
        {
            return EventKind.FileRename;
        }

        if (name.Contains("Delete", StringComparison.OrdinalIgnoreCase))
        {
            return EventKind.FileDelete;
        }

        if (name.Contains("Create", StringComparison.OrdinalIgnoreCase))
        {
            return EventKind.FileCreate;
        }

        if (name.Contains("Write", StringComparison.OrdinalIgnoreCase))
        {
            return EventKind.FileWrite;
        }

        if (name.Contains("Read", StringComparison.OrdinalIgnoreCase))
        {
            return EventKind.FileRead;
        }

        return null;
    }

    private RawEvent? MapNetwork(EtwRecord record, string name)
    {
        var kind = name switch
        {
            _ when name.Contains("Accept", StringComparison.OrdinalIgnoreCase) => EventKind.NetAccept,
            _ when name.Contains("Disconnect", StringComparison.OrdinalIgnoreCase)
                || name.Contains("Close", StringComparison.OrdinalIgnoreCase) => EventKind.NetClose,
            _ when name.Contains("Connect", StringComparison.OrdinalIgnoreCase) => EventKind.NetConnect,
            _ => (EventKind?)null,
        };

        if (kind is null)
        {
            return null;
        }

        var remoteIp = IpOf(FirstValue(record, "daddr", "destAddr", "DestAddr", "RemoteAddr", "remoteAddr"));
        var remotePort = FirstPort(record, "dport", "destPort", "DestPort", "RemotePort", "remotePort");
        if (string.IsNullOrEmpty(remoteIp) || remotePort is null)
        {
            return null;
        }

        var localIp = IpOf(FirstValue(record, "saddr", "srcAddr", "SourceAddr", "LocalAddr", "localAddr"));
        var localPort = FirstPort(record, "sport", "srcPort", "SourcePort", "LocalPort", "localPort");

        return new RawEvent
        {
            Ts = record.TimestampUtc,
            Kind = kind.Value,
            Pid = record.Pid,
            Tid = record.Tid,
            RemoteIp = remoteIp,
            RemotePort = remotePort,
            Protocol = "tcp",
            Detail = localIp is null
                ? null
                : JsonSerializer.Serialize(new Dictionary<string, string?>
                {
                    ["localIp"] = localIp,
                    ["localPort"] = localPort?.ToString(CultureInfo.InvariantCulture),
                }),
            Observability = Observability.Direct,
            Source = EventSourceKind.Etw,
        };
    }

    private RawEvent? MapRegistry(EtwRecord record, string name)
    {
        var handle = RegistryHandle(record);
        var reportedKey = FirstString(record, "KeyName", "Key", "Path");

        // Registry/Open and Registry/Create carry the key name and its handle; the write
        // events that follow carry only the handle. Measured live: every
        // Registry/SetValue arrived with an empty KeyName, so a write could never be
        // attributed to a key and the registry channel silently produced nothing.
        if (name.Contains("Open", StringComparison.OrdinalIgnoreCase)
            || name.Contains("Create", StringComparison.OrdinalIgnoreCase))
        {
            RememberRegistryKey(record.Pid, handle, reportedKey);
            return null;
        }

        if (name.Contains("Close", StringComparison.OrdinalIgnoreCase))
        {
            ForgetRegistryKey(record.Pid, handle);
            return null;
        }

        EventKind? kind = null;
        if (name.Contains("Delete", StringComparison.OrdinalIgnoreCase))
        {
            kind = EventKind.RegistryDeleteValue;
        }
        else if (name.Contains("Set", StringComparison.OrdinalIgnoreCase))
        {
            kind = EventKind.RegistrySetValue;
        }

        if (kind is null)
        {
            return null;
        }

        var key = string.IsNullOrEmpty(reportedKey)
            ? CachedRegistryKey(record.Pid, handle)
            : reportedKey;

        if (string.IsNullOrEmpty(key))
        {
            // A write whose handle was opened before capture began cannot be attributed.
            // It stays out of the stream rather than being guessed at; the process-level
            // rules still see the tool that performed it.
            return null;
        }

        var valueName = FirstString(record, "ValueName", "Value");
        var target = string.IsNullOrEmpty(valueName) ? key : key + "\\" + valueName;

        return new RawEvent
        {
            Ts = record.TimestampUtc,
            Kind = kind.Value,
            Pid = record.Pid,
            Tid = record.Tid,
            Target = target,
            Detail = string.IsNullOrEmpty(valueName)
                ? null
                : JsonSerializer.Serialize(new Dictionary<string, string?> { ["valueName"] = valueName }),
            Observability = reportedKey is null ? Observability.Inferred : Observability.Direct,
            Source = EventSourceKind.Etw,
        };
    }

    private static ulong? RegistryHandle(EtwRecord record)
    {
        var value = FirstValue(record, "KeyHandle", "Handle");
        if (value is null)
        {
            return null;
        }

        try
        {
            return Convert.ToUInt64(value, CultureInfo.InvariantCulture);
        }
        catch (Exception exception) when (exception is FormatException or InvalidCastException or OverflowException)
        {
            return null;
        }
    }

    private void RememberRegistryKey(int pid, ulong? handle, string? key)
    {
        if (handle is not { } keyHandle || string.IsNullOrEmpty(key))
        {
            return;
        }

        _registryKeys[(pid, keyHandle)] = key;

        if (_registryKeys.Count > MaxRegistryKeys)
        {
            _registryKeys.Clear();
        }
    }

    private void ForgetRegistryKey(int pid, ulong? handle)
    {
        if (handle is { } keyHandle)
        {
            _registryKeys.Remove((pid, keyHandle));
        }
    }

    private string? CachedRegistryKey(int pid, ulong? handle) =>
        handle is { } keyHandle && _registryKeys.TryGetValue((pid, keyHandle), out var key) ? key : null;

    private static RawEvent? MapDns(EtwRecord record)
    {
        var host = FirstString(record, "QueryName", "Name", "Query");
        if (string.IsNullOrEmpty(host))
        {
            return null;
        }

        var isResponse = record.EventId == 3008
            || record.EventName.Contains("Response", StringComparison.OrdinalIgnoreCase);

        var detail = new Dictionary<string, string?>();
        AddDetail(detail, "queryType", FirstValue(record, "QueryType", "Type"));
        AddDetail(detail, "status", FirstValue(record, "QueryStatus", "Status"));
        AddDetail(detail, "results", FirstValue(record, "QueryResults", "Results"));

        return new RawEvent
        {
            Ts = record.TimestampUtc,
            Kind = isResponse ? EventKind.DnsResponse : EventKind.DnsQuery,
            Pid = record.Pid,
            Tid = record.Tid,
            HostName = host,
            Target = host,
            Detail = detail.Count == 0 ? null : JsonSerializer.Serialize(detail),
            // DNS payloads carry a PID, but attribution is best-effort when the
            // query is serviced by a shared resolver thread.
            Observability = Observability.Partial,
            Source = EventSourceKind.Etw,
        };
    }

    private static bool IsDns(EtwRecord record) =>
        record.Provider.Contains("DNS-Client", StringComparison.OrdinalIgnoreCase)
        || record.EventId is 3006 or 3008;

    private string Resolve(string? path)
    {
        if (string.IsNullOrEmpty(path))
        {
            return string.Empty;
        }

        var resolved = _resolvePath(path);
        return string.IsNullOrEmpty(resolved) ? path : resolved;
    }

    private void RememberFileKey(ulong key, string path)
    {
        if (!_fileKeys.ContainsKey(key))
        {
            _fileKeyOrder.Enqueue(key);
        }

        _fileKeys[key] = path;

        while (_fileKeys.Count > MaxFileKeyEntries && _fileKeyOrder.TryDequeue(out var oldest))
        {
            _fileKeys.Remove(oldest);
        }
    }

    private static string? FileDetail(EtwRecord record, EventKind kind)
    {
        var detail = new Dictionary<string, object?>();

        // Kernel FileIO/Create is create-or-open: opening an existing DLL to load it and
        // writing a new file are the same record. Recording the ambiguity here keeps the
        // fact explicit for reports and for rules that must not read it as a write.
        if (kind == EventKind.FileCreate)
        {
            detail["createOrOpen"] = true;

            // The disposition decides whether this record means "opened" or "wrote";
            // keep the raw value so the evidence panel can show it.
            var disposition = FirstString(record, "CreateDisposition");
            if (disposition is not null)
            {
                detail["disposition"] = disposition;
            }

            if (IsDirectory(record))
            {
                detail["directory"] = true;
            }
        }

        var offset = FirstUInt64(record, "Offset", "FileOffset");
        if (offset is { } offsetValue)
        {
            detail["offset"] = offsetValue > long.MaxValue ? long.MaxValue : (long)offsetValue;
        }

        return detail.Count == 0 ? null : JsonSerializer.Serialize(detail);
    }

    private static long? FileSize(EtwRecord record)
    {
        var size = FirstUInt64(record, "IoSize", "Size", "TransferSize");
        if (size is not { } value)
        {
            return null;
        }

        return value > long.MaxValue ? long.MaxValue : (long)value;
    }

    private static void AddDetail(Dictionary<string, string?> detail, string key, object? value)
    {
        if (value is null)
        {
            return;
        }

        detail[key] = value switch
        {
            string text => text,
            IEnumerable<string> values => string.Join(',', values),
            _ => Convert.ToString(value, CultureInfo.InvariantCulture),
        };
    }

    private static object? FirstValue(EtwRecord record, params string[] names)
    {
        foreach (var name in names)
        {
            if (record.Payload.TryGetValue(name, out var value) && value is not null)
            {
                return value;
            }
        }

        return null;
    }

    private static string? FirstString(EtwRecord record, params string[] names)
    {
        var value = FirstValue(record, names);
        if (value is null)
        {
            return null;
        }

        var text = value switch
        {
            string stringValue => stringValue,
            byte[] bytes => System.Text.Encoding.Unicode.GetString(bytes).TrimEnd('\0'),
            _ => Convert.ToString(value, CultureInfo.InvariantCulture),
        };

        return string.IsNullOrWhiteSpace(text) ? null : text;
    }

    private static int? FirstInt(EtwRecord record, params string[] names)
    {
        var value = FirstValue(record, names);
        return value is null ? null : (int)Convert.ToInt64(value, CultureInfo.InvariantCulture);
    }

    private static ulong? FirstUInt64(EtwRecord record, params string[] names)
    {
        var value = FirstValue(record, names);
        if (value is null)
        {
            return null;
        }

        return value switch
        {
            byte[] { Length: 8 } bytes => BitConverter.ToUInt64(bytes, 0),
            byte[] { Length: 4 } bytes => BitConverter.ToUInt32(bytes, 0),
            _ => Convert.ToUInt64(value, CultureInfo.InvariantCulture),
        };
    }

    private static int? FirstPort(EtwRecord record, params string[] names)
    {
        var value = FirstValue(record, names);
        if (value is null)
        {
            return null;
        }

        var port = Convert.ToInt64(value, CultureInfo.InvariantCulture);
        if (port < 0 || port > ushort.MaxValue)
        {
            port = (ushort)IPAddress.NetworkToHostOrder((short)port);
        }

        return (int)port;
    }

    private static string? IpOf(object? value) => value switch
    {
        null => null,
        IPAddress address => address.ToString(),
        string text when !string.IsNullOrWhiteSpace(text) => text,
        byte[] { Length: 4 } bytes => new IPAddress(bytes).ToString(),
        byte[] { Length: 16 } bytes => new IPAddress(bytes).ToString(),
        uint number => new IPAddress(NetworkBytes(number)).ToString(),
        int number => new IPAddress(NetworkBytes(unchecked((uint)number))).ToString(),
        long number => new IPAddress(NetworkBytes(unchecked((uint)number))).ToString(),
        _ => Convert.ToString(value, CultureInfo.InvariantCulture),
    };

    private static byte[] NetworkBytes(uint value)
    {
        // ETW stores an IPv4 address as the in-memory form of in_addr, i.e. the
        // bytes are already in network order on disk. BitConverter returns that
        // same memory order, so 0x0100007F yields 127.0.0.1 without reversal.
        // Reversing here would produce the byte-reversed 1.0.0.127.
        return BitConverter.GetBytes(value);
    }

    public static string FileNameOf(string? path)
    {
        if (string.IsNullOrEmpty(path))
        {
            return string.Empty;
        }

        var index = path.LastIndexOfAny(['\\', '/']);
        return index < 0 ? path : path[(index + 1)..];
    }
}
