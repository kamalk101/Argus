namespace Argus.Agent;

using System.Collections.Concurrent;
using System.Text.Json;
using System.Threading.Channels;

public sealed record SseMessage(string Type, string Json);

/// <summary>
/// Fan-out for Server-Sent Events. Each subscriber has a bounded queue: a slow
/// dashboard must not grow memory or back-pressure collection, so old frames are
/// dropped and the client can refetch the snapshot.
/// </summary>
public sealed class SseHub
{
    private readonly ConcurrentDictionary<Guid, Channel<SseMessage>> _subscribers = new();

    public int SubscriberCount => _subscribers.Count;

    public (Guid Id, ChannelReader<SseMessage> Reader) Subscribe()
    {
        var id = Guid.NewGuid();
        var channel = Channel.CreateBounded<SseMessage>(new BoundedChannelOptions(512)
        {
            FullMode = BoundedChannelFullMode.DropOldest,
            SingleReader = true,
            SingleWriter = false,
        });

        _subscribers[id] = channel;
        return (id, channel.Reader);
    }

    public void Unsubscribe(Guid id)
    {
        if (_subscribers.TryRemove(id, out var channel))
        {
            channel.Writer.TryComplete();
        }
    }

    public void Publish(string type, object payload)
    {
        var message = new SseMessage(type, JsonSerializer.Serialize(payload, AgentJson.Options));
        foreach (var channel in _subscribers.Values)
        {
            channel.Writer.TryWrite(message);
        }
    }

    public void Complete()
    {
        foreach (var channel in _subscribers.Values)
        {
            channel.Writer.TryComplete();
        }

        _subscribers.Clear();
    }
}
