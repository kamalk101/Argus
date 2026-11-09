import { useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { useSession } from '../session';
import { EventTable, type EventColumn } from '../components/EventTable';
import { Badge, Panel, StateNote } from '../components/ui';
import { useAsync } from '../hooks/useAsync';
import { listDetections, listEvents } from '../api/client';
import { elide } from '../lib/format';
import type { MonitorEvent } from '../api/types';

const COLUMNS: EventColumn[] = ['time', 'process', 'target', 'detail', 'observability'];

/** File activity: the file rows of the session, filterable by operation, process and path. */
export function FilesScreen() {
  const { session, loading, error } = useSession();
  const id = session?.id ?? null;

  const events = useAsync(() => (id ? listEvents(id, { limit: 100000 }) : Promise.resolve([])), [id]);
  const detections = useAsync(() => (id ? listDetections(id) : Promise.resolve([])), [id]);

  const [operation, setOperation] = useState('');
  const [text, setText] = useState('');
  const [pid, setPid] = useState('');
  const [selected, setSelected] = useState<MonitorEvent | null>(null);

  const fileEvents = useMemo(() => (events.data ?? []).filter((event) => event.category === 'File'), [events.data]);
  const operations = useMemo(() => [...new Set(fileEvents.map((event) => event.kind))].sort(), [fileEvents]);
  const processes = useMemo(() => [...new Set(fileEvents.map((event) => event.pid))].sort((a, b) => a - b), [fileEvents]);

  const filtered = useMemo(
    () =>
      fileEvents.filter((event) => {
        if (operation && event.kind !== operation) return false;
        if (pid && event.pid !== Number(pid)) return false;
        if (text) {
          const wanted = text.toLowerCase();
          return (event.target ?? '').toLowerCase().includes(wanted) || (event.imageName ?? '').toLowerCase().includes(wanted);
        }
        return true;
      }),
    [fileEvents, operation, pid, text],
  );

  if (loading) return <StateNote kind="loading" />;
  if (error) return <StateNote kind="error" message={error} />;
  if (!session) return <StateNote kind="empty" message="No session to read file activity from." />;

  const related = selected
    ? (detections.data ?? []).filter((detection) => detection.scopePid === selected.pid)
    : [];

  return (
    <div className="grid gap-3 p-4 xl:grid-cols-4">
      <Panel
        title="File activity"
        className="xl:col-span-3"
        actions={<span className="text-[10px] text-ink-400">{filtered.length.toLocaleString('en-GB')} of {fileEvents.length.toLocaleString('en-GB')} file events</span>}
      >
        <div className="flex flex-wrap items-center gap-2 border-b border-ink-800 px-3 py-2">
          <select
            aria-label="operation"
            value={operation}
            onChange={(event) => setOperation(event.target.value)}
            className="rounded border border-ink-700 bg-ink-950 px-2 py-0.5 text-[11px]"
          >
            <option value="">all operations</option>
            {operations.map((kind) => (
              <option key={kind} value={kind}>{kind.toLowerCase()}</option>
            ))}
          </select>

          <select
            aria-label="process"
            value={pid}
            onChange={(event) => setPid(event.target.value)}
            className="rounded border border-ink-700 bg-ink-950 px-2 py-0.5 text-[11px]"
          >
            <option value="">all processes</option>
            {processes.map((processPid) => (
              <option key={processPid} value={processPid}>
                {fileEvents.find((event) => event.pid === processPid)?.imageName} ({processPid})
              </option>
            ))}
          </select>

          <input
            value={text}
            onChange={(event) => setText(event.target.value)}
            placeholder="path substring"
            aria-label="path substring"
            className="w-64 rounded border border-ink-700 bg-ink-950 px-2 py-0.5 text-[11px] focus:border-benign focus:outline-none"
          />
        </div>

        {events.error ? (
          <StateNote kind="error" message={events.error} onRetry={events.reload} />
        ) : (
          <EventTable
            events={filtered.slice(-20000)}
            columns={COLUMNS}
            onSelect={setSelected}
            selectedSeq={selected?.seq ?? null}
            emptyNote="No file events match these filters."
            height={520}
          />
        )}
      </Panel>

      <Panel title="Why flagged">
        {!selected ? (
          <StateNote kind="empty" message="Select a row to see the rule, its factors, and the related events." />
        ) : (
          <div className="space-y-3 p-3 text-[12px]">
            <div>
              <div className="text-[10px] uppercase tracking-wider text-ink-400">path</div>
              <div className="break-all" title={selected.target ?? undefined}>{elide(selected.target, 46)}</div>
            </div>
            <div className="flex flex-wrap gap-1">
              <Badge>{selected.kind.toLowerCase()}</Badge>
              <Badge tone={selected.scope === 'InScope' ? 'info' : 'neutral'}>{selected.scope.toLowerCase()}</Badge>
              <Badge tone="neutral" title="observability">{selected.observability.toLowerCase()}</Badge>
            </div>
            <div>
              <div className="text-[10px] uppercase tracking-wider text-ink-400">process</div>
              <div>{selected.imageName} ({selected.pid})</div>
            </div>
            <div>
              <div className="text-[10px] uppercase tracking-wider text-ink-400">detections naming this process</div>
              {related.length === 0 ? (
                <div className="text-ink-400">none — this row is context, not evidence</div>
              ) : (
                <ul className="space-y-1">
                  {related.map((detection) => (
                    <li key={detection.detectionKey}>
                      <span className="text-suspicious">{detection.ruleId}</span> {detection.title}
                      <div className="text-[11px] text-ink-300">{detection.reason}</div>
                    </li>
                  ))}
                </ul>
              )}
            </div>
            <Link to="/timeline" className="inline-block text-[11px] text-benign hover:underline">
              Show this range in the timeline →
            </Link>
          </div>
        )}
      </Panel>
    </div>
  );
}
