import { useEffect, useMemo, useRef, useState } from 'react';
import { useSession } from '../session';
import { Badge, Panel, StateNote } from '../components/ui';
import { useAsync } from '../hooks/useAsync';
import { listDetections, listEvents } from '../api/client';
import { clock, elide } from '../lib/format';

const SAVED_KEY = 'argus.savedFilters';

interface SavedFilter {
  name: string;
  query: string;
  scope: 'everything' | 'paths' | 'domains' | 'commands' | 'detections';
}

const DEFAULT_SAVED: SavedFilter[] = [
  { name: 'writable locations', query: '\\temp\\', scope: 'paths' },
  { name: 'powershell', query: 'powershell', scope: 'commands' },
  { name: 'external connections', query: 'https', scope: 'everything' },
];

/**
 * Search covers paths, domains, command lines and detection reasons. In the live agent this is FTS5
 * over the session database; in fixture mode it filters the captured payloads with the same intent,
 * so the screen's states are exercised without a database.
 */
export function SearchScreen() {
  const { session, loading, error } = useSession();
  const id = session?.id ?? null;
  const inputRef = useRef<HTMLInputElement>(null);

  const events = useAsync(() => (id ? listEvents(id, { limit: 100000 }) : Promise.resolve([])), [id]);
  const detections = useAsync(() => (id ? listDetections(id) : Promise.resolve([])), [id]);

  const [query, setQuery] = useState('');
  const [scope, setScope] = useState<SavedFilter['scope']>('everything');
  const [saved, setSaved] = useState<SavedFilter[]>(() => {
    try {
      const stored = localStorage.getItem(SAVED_KEY);
      return stored ? (JSON.parse(stored) as SavedFilter[]) : DEFAULT_SAVED;
    } catch {
      return DEFAULT_SAVED;
    }
  });

  useEffect(() => {
    // `Ctrl+K` and `/` both land here from anywhere in the shell.
    inputRef.current?.focus();
  }, []);

  useEffect(() => {
    localStorage.setItem(SAVED_KEY, JSON.stringify(saved));
  }, [saved]);

  const results = useMemo(() => {
    if (query.trim().length < 2) return { events: [], detections: [] };
    const wanted = query.toLowerCase();

    const matchEvent = (haystack: Array<string | null | undefined>) =>
      haystack.filter(Boolean).some((value) => value!.toLowerCase().includes(wanted));

    const eventHits = (events.data ?? []).filter((event) => {
      if (scope === 'paths') return matchEvent([event.target, event.imagePath]);
      if (scope === 'domains') return matchEvent([event.hostName, event.remoteIp]);
      if (scope === 'commands') return matchEvent([event.imagePath]);
      if (scope === 'detections') return false;
      return matchEvent([event.target, event.imagePath, event.hostName, event.remoteIp, event.imageName]);
    });

    const detectionHits = (detections.data ?? []).filter((detection) =>
      [detection.title, detection.reason, detection.counterfactual, detection.ruleId, detection.factorsJson]
        .filter(Boolean)
        .some((value) => value.toLowerCase().includes(wanted)),
    );

    return { events: eventHits, detections: detectionHits };
  }, [query, scope, events.data, detections.data]);

  if (loading) return <StateNote kind="loading" />;
  if (error) return <StateNote kind="error" message={error} />;
  if (!session) return <StateNote kind="empty" message="No session to search." />;

  return (
    <div className="space-y-3 p-4">
      <div className="flex flex-wrap items-center gap-2">
        <h1 className="mr-2 text-sm font-semibold uppercase tracking-wider">Search</h1>
        <input
          ref={inputRef}
          value={query}
          onChange={(event) => setQuery(event.target.value)}
          placeholder="path, domain, command line or reason  (Ctrl+K)"
          aria-label="search"
          className="w-[380px] rounded border border-ink-700 bg-ink-950 px-2 py-1 text-[12px] focus:border-benign focus:outline-none"
        />
        <select
          value={scope}
          onChange={(event) => setScope(event.target.value as SavedFilter['scope'])}
          aria-label="search scope"
          className="rounded border border-ink-700 bg-ink-950 px-2 py-1 text-[11px]"
        >
          <option value="everything">everything</option>
          <option value="paths">paths</option>
          <option value="domains">domains and addresses</option>
          <option value="commands">command lines</option>
          <option value="detections">detections only</option>
        </select>
        <button
          type="button"
          disabled={query.trim().length < 2}
          onClick={() => setSaved([...saved.filter((entry) => entry.name !== query), { name: query, query, scope }])}
          className="rounded border border-ink-600 px-2 py-0.5 text-[11px] text-ink-300 hover:bg-ink-850 disabled:opacity-40"
        >
          save this filter
        </button>
        <span className="text-[10px] text-ink-400">
          {results.events.length} events · {results.detections.length} detections
        </span>
      </div>

      <div className="flex flex-wrap gap-1">
        {saved.map((entry) => (
          <button
            key={entry.name}
            type="button"
            onClick={() => {
              setQuery(entry.query);
              setScope(entry.scope);
            }}
            className="rounded border border-ink-700 px-2 py-0.5 text-[11px] text-ink-300 hover:bg-ink-850"
            title={`${entry.scope}: ${entry.query}`}
          >
            {entry.name}
          </button>
        ))}
        {saved.length > 0 && (
          <button type="button" onClick={() => setSaved([])} className="text-[10px] text-ink-500 hover:text-ink-300">
            clear saved
          </button>
        )}
      </div>

      {query.trim().length < 2 ? (
        <StateNote kind="empty" message="Type at least two characters. Nothing is hidden by the empty state: there is simply no query yet." />
      ) : (
        <div className="grid gap-3 xl:grid-cols-3">
          <Panel title="Detections" className="xl:col-span-1">
            {results.detections.length === 0 ? (
              <StateNote kind="empty" message="No detection matches." />
            ) : (
              <ul className="p-2 text-[12px]">
                {results.detections.map((detection) => (
                  <li key={detection.detectionKey} className="border-b border-ink-850 py-1 last:border-0">
                    <div>
                      <span className={detection.severity >= 50 ? 'text-malicious' : 'text-suspicious'}>{detection.ruleId}</span> {detection.title}
                    </div>
                    <div className="text-[11px] text-ink-300">{elide(detection.reason, 90)}</div>
                  </li>
                ))}
              </ul>
            )}
          </Panel>

          <Panel title="Events" className="xl:col-span-2" actions={<span className="text-[10px] text-ink-400">first 300 matches</span>}>
            {results.events.length === 0 ? (
              <StateNote kind="empty" message="No event matches." />
            ) : (
              <table className="w-full border-collapse text-[12px]">
                <thead>
                  <tr className="border-b border-ink-800 text-left text-[10px] uppercase tracking-wider text-ink-400">
                    <th className="px-3 py-1.5 font-medium">time</th>
                    <th className="px-3 py-1.5 font-medium">process</th>
                    <th className="px-3 py-1.5 font-medium">target</th>
                    <th className="px-3 py-1.5 font-medium">observability</th>
                  </tr>
                </thead>
                <tbody>
                  {results.events.slice(0, 300).map((event) => (
                    <tr key={event.seq} className="row-dense border-b border-ink-850 hover:bg-ink-850">
                      <td className="px-3 py-1.5 text-ink-400">{clock(event.timestampUtc)}</td>
                      <td className="px-3 py-1.5">{event.imageName} <span className="text-ink-400">{event.pid}</span></td>
                      <td className="max-w-[420px] truncate px-3 py-1.5" title={event.target ?? undefined}>{elide(event.target ?? event.hostName, 52)}</td>
                      <td className="px-3 py-1.5"><Badge tone="neutral">{event.observability.toLowerCase()}</Badge></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </Panel>
        </div>
      )}
    </div>
  );
}
