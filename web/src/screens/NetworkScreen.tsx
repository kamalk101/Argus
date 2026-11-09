import { useMemo, useState } from 'react';
import { useSession } from '../session';
import { Badge, Panel, StateNote } from '../components/ui';
import { useAsync } from '../hooks/useAsync';
import { listEvents } from '../api/client';
import { clock } from '../lib/format';

interface Destination {
  key: string;
  remoteIp: string;
  remotePort: number | null;
  hostName: string | null;
  protocol: string | null;
  pids: Set<number>;
  names: Set<string>;
  first: string;
  last: string;
  count: number;
}

/** Internal-vs-external is a labelled signal, not a verdict: private ranges say "inside the network". */
function isPrivate(ip: string | null): boolean {
  if (!ip) return false;
  if (ip.startsWith('10.') || ip.startsWith('192.168.') || ip.startsWith('127.')) return true;
  const match = /^172\.(\d+)\./.exec(ip);
  return match ? Number(match[1]) >= 16 && Number(match[1]) <= 31 : false;
}

export function NetworkScreen() {
  const { session, loading, error } = useSession();
  const id = session?.id ?? null;

  const events = useAsync(() => (id ? listEvents(id, { category: 'Network', limit: 100000 }) : Promise.resolve([])), [id]);
  const dns = useAsync(() => (id ? listEvents(id, { category: 'Dns', limit: 100000 }) : Promise.resolve([])), [id]);

  const [text, setText] = useState('');
  const [grouped, setGrouped] = useState(true);

  const destinations = useMemo(() => {
    const map = new Map<string, Destination>();
    for (const event of events.data ?? []) {
      const key = `${event.remoteIp ?? 'unknown'}:${event.remotePort ?? ''}`;
      const existing = map.get(key);
      if (existing) {
        existing.pids.add(event.pid);
        if (event.imageName) existing.names.add(event.imageName);
        existing.count += 1;
        if (event.timestampUtc < existing.first) existing.first = event.timestampUtc;
        if (event.timestampUtc > existing.last) existing.last = event.timestampUtc;
        if (!existing.hostName && event.hostName) existing.hostName = event.hostName;
      } else {
        map.set(key, {
          key,
          remoteIp: event.remoteIp ?? 'unknown',
          remotePort: event.remotePort,
          hostName: event.hostName,
          protocol: event.protocol,
          pids: new Set([event.pid]),
          names: new Set(event.imageName ? [event.imageName] : []),
          first: event.timestampUtc,
          last: event.timestampUtc,
          count: 1,
        });
      }
    }
    return [...map.values()].sort((a, b) => b.count - a.count);
  }, [events.data]);

  const visible = destinations.filter((destination) =>
    !text || [destination.remoteIp, destination.hostName, [...destination.names].join(' ')].join(' ').toLowerCase().includes(text.toLowerCase()),
  );

  if (loading) return <StateNote kind="loading" />;
  if (error) return <StateNote kind="error" message={error} />;
  if (!session) return <StateNote kind="empty" message="No session to read connections from." />;

  return (
    <div className="space-y-3 p-4">
      <div className="flex flex-wrap items-center gap-2">
        <h1 className="mr-2 text-sm font-semibold uppercase tracking-wider">Network activity</h1>
        <input
          value={text}
          onChange={(event) => setText(event.target.value)}
          placeholder="address, host or process"
          aria-label="filter destinations"
          className="w-64 rounded border border-ink-700 bg-ink-950 px-2 py-1 text-[11px] focus:border-benign focus:outline-none"
        />
        <button
          type="button"
          onClick={() => setGrouped((value) => !value)}
          className="rounded border border-ink-600 px-2 py-0.5 text-[11px] text-ink-300 hover:bg-ink-850"
          aria-pressed={grouped}
        >
          {grouped ? 'grouped by destination' : 'every connection'}
        </button>
        <span className="text-[10px] text-ink-400">
          {(events.data ?? []).length} connect records · {(dns.data ?? []).length} DNS records
        </span>
      </div>

      <div className="grid gap-3 xl:grid-cols-4">
        <Panel title={grouped ? 'Destinations' : 'Connections'} className="xl:col-span-3">
          {events.error ? (
            <StateNote kind="error" message={events.error} onRetry={events.reload} />
          ) : visible.length === 0 ? (
            <StateNote kind="empty" message="No connections in scope for this session." />
          ) : grouped ? (
            <table className="w-full border-collapse text-[12px]">
              <thead>
                <tr className="border-b border-ink-800 text-left text-[10px] uppercase tracking-wider text-ink-400">
                  <th className="px-3 py-1.5 font-medium">destination</th>
                  <th className="px-3 py-1.5 font-medium">name</th>
                  <th className="px-3 py-1.5 font-medium">process</th>
                  <th className="px-3 py-1.5 font-medium">connects</th>
                  <th className="px-3 py-1.5 font-medium">first</th>
                  <th className="px-3 py-1.5 font-medium">last</th>
                  <th className="px-3 py-1.5 font-medium">reach</th>
                </tr>
              </thead>
              <tbody>
                {visible.map((destination) => (
                  <tr key={destination.key} className="row-dense border-b border-ink-850 hover:bg-ink-850">
                    <td className="px-3 py-1.5">{destination.remoteIp}{destination.remotePort ? `:${destination.remotePort}` : ''}</td>
                    <td className="px-3 py-1.5 text-ink-300" title={destination.hostName ? 'resolved in this session' : 'no DNS record seen in this session'}>
                      {destination.hostName ?? <span className="text-ink-500">not resolved in-session</span>}
                    </td>
                    <td className="px-3 py-1.5 text-ink-300">{[...destination.names].join(', ') || '—'}</td>
                    <td className="px-3 py-1.5">{destination.count}</td>
                    <td className="px-3 py-1.5 text-ink-400">{clock(destination.first)}</td>
                    <td className="px-3 py-1.5 text-ink-400">{clock(destination.last)}</td>
                    <td className="px-3 py-1.5">
                      <Badge tone={isPrivate(destination.remoteIp) ? 'neutral' : 'warn'}>
                        {isPrivate(destination.remoteIp) ? 'internal' : 'external'}
                      </Badge>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <table className="w-full border-collapse text-[12px]">
              <thead>
                <tr className="border-b border-ink-800 text-left text-[10px] uppercase tracking-wider text-ink-400">
                  <th className="px-3 py-1.5 font-medium">time</th>
                  <th className="px-3 py-1.5 font-medium">process</th>
                  <th className="px-3 py-1.5 font-medium">destination</th>
                  <th className="px-3 py-1.5 font-medium">protocol</th>
                  <th className="px-3 py-1.5 font-medium">observability</th>
                </tr>
              </thead>
              <tbody>
                {(events.data ?? []).slice(-2000).map((event) => (
                  <tr key={event.seq} className="row-dense border-b border-ink-850 hover:bg-ink-850">
                    <td className="px-3 py-1.5 text-ink-400">{clock(event.timestampUtc)}</td>
                    <td className="px-3 py-1.5">{event.imageName} <span className="text-ink-400">{event.pid}</span></td>
                    <td className="px-3 py-1.5">{event.remoteIp}{event.remotePort ? `:${event.remotePort}` : ''}</td>
                    <td className="px-3 py-1.5 text-ink-300">{event.protocol ?? '—'}</td>
                    <td className="px-3 py-1.5 text-[10px] uppercase text-ink-400">{event.observability.toLowerCase()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Panel>

        <Panel title="DNS in this session" actions={<span className="text-[10px] text-ink-400">how a name was attributed</span>}>
          <ul className="max-h-[420px] overflow-auto p-3 text-[12px]">
            {(dns.data ?? []).slice(0, 200).map((event) => (
              <li key={event.seq} className="flex items-baseline gap-2 border-b border-ink-850 py-1 last:border-0">
                <span className="w-14 shrink-0 text-ink-400">{clock(event.timestampUtc)}</span>
                <span className="min-w-0 flex-1 truncate" title={event.hostName ?? undefined}>{event.hostName ?? '—'}</span>
                <span className="shrink-0 text-[10px] text-ink-400">{event.observability.toLowerCase()}</span>
              </li>
            ))}
            {(dns.data ?? []).length === 0 && <li className="text-ink-400">No DNS records — every name above would be unresolvable in-session.</li>}
          </ul>
        </Panel>
      </div>
    </div>
  );
}
