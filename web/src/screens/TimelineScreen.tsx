import { useMemo, useState } from 'react';
import { useSession } from '../session';
import { EventTable, type EventColumn } from '../components/EventTable';
import { Panel, StateNote } from '../components/ui';
import { RiskChart } from '../components/RiskChart';
import { useAsync } from '../hooks/useAsync';
import { getTimeline, listScores } from '../api/client';
import { clock } from '../lib/format';
import type { MonitorEvent } from '../api/types';

const COLUMNS: EventColumn[] = ['time', 'category', 'process', 'target', 'detail', 'observability'];

/** Timestamps arrive as ISO strings; the range filter below works on epoch milliseconds. */
const categories = ['Process', 'File', 'Registry', 'Network', 'Dns', 'Detection', 'Gap'];

export function TimelineScreen() {
  const { session, loading, error } = useSession();
  const id = session?.id ?? null;

  const timeline = useAsync(() => (id ? getTimeline(id) : Promise.resolve(null)), [id]);
  const scores = useAsync(() => (id ? listScores(id) : Promise.resolve(null)), [id]);

  const [enabled, setEnabled] = useState<Set<string>>(new Set(['Process', 'File', 'Registry', 'Network', 'Dns']));
  const [range, setRange] = useState<{ from: string; to: string } | null>(null);
  const [selected, setSelected] = useState<MonitorEvent | null>(null);

  const events = useMemo(() => {
    const all = timeline.data?.events ?? [];
    const from = range ? new Date(range.from).getTime() : Number.NEGATIVE_INFINITY;
    const to = range ? new Date(range.to).getTime() : Number.POSITIVE_INFINITY;
    return all.filter((event) => {
      if (!enabled.has(event.category)) return false;
      const time = new Date(event.timestampUtc).getTime();
      return time >= from && time <= to;
    });
  }, [timeline.data, enabled, range]);

  if (loading) return <StateNote kind="loading" />;
  if (error) return <StateNote kind="error" message={error} />;
  if (!session) return <StateNote kind="empty" message="No session — the timeline fills as events arrive." />;

  const detections = timeline.data?.detections ?? [];

  return (
    <div className="space-y-3 p-4">
      <div className="flex flex-wrap items-center gap-2">
        <h1 className="mr-2 text-sm font-semibold uppercase tracking-wider">Timeline</h1>
        {categories.map((category) => {
          const on = enabled.has(category);
          return (
            <button
              key={category}
              type="button"
              aria-pressed={on}
              onClick={() =>
                setEnabled((current) => {
                  const next = new Set(current);
                  if (next.has(category)) next.delete(category);
                  else next.add(category);
                  return next;
                })
              }
              className={`rounded border px-2 py-0.5 text-[11px] ${on ? 'border-benign/50 bg-benign/10 text-benign' : 'border-ink-700 text-ink-400'}`}
            >
              {category.toLowerCase()}
            </button>
          );
        })}
        {range && (
          <button type="button" onClick={() => setRange(null)} className="rounded border border-ink-600 px-2 py-0.5 text-[11px] text-ink-300">
            clear range {clock(range.from)}–{clock(range.to)} ✕
          </button>
        )}
        <span className="ml-auto text-[10px] text-ink-400">{events.length.toLocaleString('en-GB')} events shown</span>
      </div>

      <Panel title="Risk, with detections marked" actions={<span className="text-[10px] text-ink-400">click twice to zoom a range</span>}>
        {scores.loading ? (
          <StateNote kind="loading" />
        ) : (
          <RiskChart
            points={scores.data ?? []}
            marks={detections.map((detection) => ({ at: detection.firstSeenUtc, label: `${detection.ruleId} ${detection.title}` }))}
            onSelectRange={(from, to) => setRange({ from, to })}
          />
        )}
      </Panel>

      <div className="grid gap-3 xl:grid-cols-4">
        <Panel title="Events" className="xl:col-span-3">
          {timeline.error ? (
            <StateNote kind="error" message={timeline.error} onRetry={timeline.reload} />
          ) : (
            <EventTable
              events={events}
              columns={COLUMNS}
              onSelect={setSelected}
              selectedSeq={selected?.seq ?? null}
              emptyNote="No events in this range with these categories enabled."
              height={480}
            />
          )}
        </Panel>

        <div className="space-y-3">
          <Panel title={`Detections (${detections.length})`}>
            <ul className="max-h-[280px] overflow-auto p-2 text-[12px]">
              {detections.map((detection) => (
                <li key={detection.ruleId + detection.firstSeenUtc}>
                  <button
                    type="button"
                    onClick={() => setRange({ from: detection.firstSeenUtc, to: detection.lastSeenUtc })}
                    className="w-full rounded px-1 py-0.5 text-left hover:bg-ink-850"
                    title="zoom the chart to this detection"
                  >
                    <span className={detection.severity >= 50 ? 'text-malicious' : 'text-suspicious'}>{detection.ruleId}</span>{' '}
                    <span className="text-ink-200">{detection.title}</span>
                    <span className="block text-[10px] text-ink-400">{clock(detection.firstSeenUtc)} · {detection.eventCount} events</span>
                  </button>
                </li>
              ))}
              {detections.length === 0 && <li className="p-1 text-ink-400">No detections in this session.</li>}
            </ul>
          </Panel>

          <Panel title="Selected event">
            {!selected ? (
              <StateNote kind="empty" message="Select a row for its full detail." />
            ) : (
              <dl className="space-y-1 p-2 text-[11px]">
                <Row label="seq" value={String(selected.seq)} />
                <Row label="time" value={selected.timestampUtc} />
                <Row label="kind" value={selected.kind} />
                <Row label="category" value={selected.category} />
                <Row label="process" value={`${selected.imageName ?? '—'} (${selected.pid})`} />
                <Row label="target" value={selected.target ?? '—'} />
                <Row label="scope" value={selected.scopeReason ?? selected.scope} />
                <Row label="observability" value={selected.observability} />
                <Row label="source" value={selected.source} />
              </dl>
            )}
          </Panel>
        </div>
      </div>
    </div>
  );
}

function Row({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex gap-2">
      <dt className="w-24 shrink-0 text-ink-400">{label}</dt>
      <dd className="min-w-0 break-all text-ink-200">{value}</dd>
    </div>
  );
}
