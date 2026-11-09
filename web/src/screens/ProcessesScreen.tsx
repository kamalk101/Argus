import { useMemo, useState } from 'react';
import { useSession } from '../session';
import { Badge, Panel, StateNote } from '../components/ui';
import { useAsync } from '../hooks/useAsync';
import { listDetections, listEvents, listProcesses } from '../api/client';
import { clock, elide } from '../lib/format';
import type { MonitorEvent, Process } from '../api/types';

export function ProcessesScreen() {
  const { session, loading, error } = useSession();
  const id = session?.id ?? null;

  const processes = useAsync(() => (id ? listProcesses(id) : Promise.resolve([])), [id]);
  const events = useAsync(() => (id ? listEvents(id, { limit: 5000 }) : Promise.resolve([])), [id]);
  const detections = useAsync(() => (id ? listDetections(id) : Promise.resolve([])), [id]);

  const [selected, setSelected] = useState<number | null>(null);
  const [filter, setFilter] = useState('');

  const rows = useMemo(() => {
    const list = processes.data ?? [];
    const byParent = new Map<number | null, Process[]>();
    for (const process of list) {
      const key = process.parentPid;
      byParent.set(key, [...(byParent.get(key) ?? []), process]);
    }

    const depthOf = new Map<number, number>();
    const walk = (pid: number, depth: number) => {
      depthOf.set(pid, depth);
      for (const child of byParent.get(pid) ?? []) walk(child.pid, depth + 1);
    };
    if (session) walk(session.rootPid, 0);
    for (const process of list) if (!depthOf.has(process.pid)) depthOf.set(process.pid, 0);

    return list
      .filter((process) => !filter || (process.imageName ?? '').toLowerCase().includes(filter.toLowerCase()) || (process.commandLine ?? '').toLowerCase().includes(filter.toLowerCase()))
      .sort((a, b) => (depthOf.get(a.pid) ?? 0) - (depthOf.get(b.pid) ?? 0) || a.startedUtc.localeCompare(b.startedUtc))
      .map((process) => ({ process, depth: depthOf.get(process.pid) ?? 0 }));
  }, [processes.data, filter, session]);

  const selectedProcess = rows.find((row) => row.process.pid === selected)?.process ?? null;
  const selectedEvents = (events.data ?? []).filter((event) => event.pid === selected);
  const selectedDetections = (detections.data ?? []).filter((detection) => detection.scopePid === selected);

  if (loading) return <StateNote kind="loading" />;
  if (error) return <StateNote kind="error" message={error} />;
  if (!session) return <StateNote kind="empty" message="No session — the process tree appears once one is running." />;

  return (
    <div className="grid gap-3 p-4 xl:grid-cols-3">
      <Panel
        title="Process tree"
        className="xl:col-span-2"
        actions={
          <input
            value={filter}
            onChange={(event) => setFilter(event.target.value)}
            placeholder="/ search name or command line"
            aria-label="filter processes"
            className="w-64 rounded border border-ink-700 bg-ink-950 px-2 py-0.5 text-[11px] focus:border-benign focus:outline-none"
          />
        }
      >
        {processes.error ? (
          <StateNote kind="error" message={processes.error} onRetry={processes.reload} />
        ) : rows.length === 0 ? (
          <StateNote kind="empty" message="The sensor reported no processes in scope." />
        ) : (
          <table className="w-full border-collapse text-[12px]">
            <thead>
              <tr className="border-b border-ink-800 text-left text-[10px] uppercase tracking-wider text-ink-400">
                <th className="px-3 py-1.5 font-medium">name</th>
                <th className="px-3 py-1.5 font-medium">pid</th>
                <th className="px-3 py-1.5 font-medium">ppid</th>
                <th className="px-3 py-1.5 font-medium">command line</th>
                <th className="px-3 py-1.5 font-medium">started</th>
                <th className="px-3 py-1.5 font-medium">scope</th>
              </tr>
            </thead>
            <tbody>
              {rows.map(({ process, depth }) => {
                const flagged = (detections.data ?? []).some((detection) => detection.scopePid === process.pid);
                return (
                  <tr
                    key={process.pid}
                    tabIndex={0}
                    onClick={() => setSelected(process.pid)}
                    onKeyDown={(event) => {
                      if (event.key === 'Enter') setSelected(process.pid);
                    }}
                    className={`row-dense cursor-pointer border-b border-ink-850 ${selected === process.pid ? 'bg-ink-800' : 'hover:bg-ink-850'}`}
                    data-depth={depth}
                  >
                    <td className="px-3 py-1.5" style={{ paddingLeft: 12 + depth * 14 }}>
                      {depth > 0 && <span className="mr-1 text-ink-600">└</span>}
                      {process.imageName ?? '—'}
                      {flagged && <span className="ml-2 text-suspicious" title="a detection names this process">●</span>}
                    </td>
                    <td className="px-3 py-1.5 text-ink-300">{process.pid}</td>
                    <td className="px-3 py-1.5 text-ink-400">{process.parentPid ?? '—'}</td>
                    <td className="max-w-[380px] truncate px-3 py-1.5 text-ink-300" title={process.commandLine ?? undefined}>
                      {elide(process.commandLine, 40)}
                    </td>
                    <td className="px-3 py-1.5 text-ink-400">{clock(process.startedUtc)}</td>
                    <td className="px-3 py-1.5">
                      <Badge tone={process.scope === 'InScope' ? 'info' : 'neutral'}>{process.scope.toLowerCase()}</Badge>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </Panel>

      <Panel title={selectedProcess ? `PID ${selectedProcess.pid}` : 'Select a process'}>
        {!selectedProcess ? (
          <StateNote kind="empty" message="Pick a process to see its identity, its event counts and the detections that name it." />
        ) : (
          <div className="space-y-3 p-3 text-[12px]">
            <dl className="space-y-1">
              <Row label="image" value={selectedProcess.imageName ?? '—'} />
              <Row label="path" value={selectedProcess.imagePath ?? '—'} mono title={selectedProcess.imagePath ?? undefined} />
              <Row label="command" value={selectedProcess.commandLine ?? '—'} mono title={selectedProcess.commandLine ?? undefined} />
              <Row label="started" value={clock(selectedProcess.startedUtc)} />
              <Row label="scope" value={selectedProcess.scopeReason ?? selectedProcess.scope} />
            </dl>

            <div>
              <h3 className="text-[10px] uppercase tracking-wider text-ink-400">events by category</h3>
              <ul className="mt-1 space-y-0.5">
                {Object.entries(countBy(selectedEvents, (event) => event.category)).map(([category, count]) => (
                  <li key={category} className="flex justify-between">
                    <span className="text-ink-300">{category.toLowerCase()}</span>
                    <span>{count}</span>
                  </li>
                ))}
                {selectedEvents.length === 0 && <li className="text-ink-400">none attributed to this process</li>}
              </ul>
            </div>

            <div>
              <h3 className="text-[10px] uppercase tracking-wider text-ink-400">detections</h3>
              <ul className="mt-1 space-y-0.5">
                {selectedDetections.map((detection) => (
                  <li key={detection.detectionKey} className="text-suspicious">
                    {detection.ruleId} · {detection.title}
                  </li>
                ))}
                {selectedDetections.length === 0 && <li className="text-ink-400">none</li>}
              </ul>
            </div>
          </div>
        )}
      </Panel>
    </div>
  );
}

function Row({ label, value, mono, title }: { label: string; value: string; mono?: boolean; title?: string }) {
  return (
    <div className="flex gap-2">
      <dt className="w-16 shrink-0 text-ink-400">{label}</dt>
      <dd className={`min-w-0 break-all ${mono ? 'text-ink-200' : ''}`} title={title}>{value}</dd>
    </div>
  );
}

export function countBy<T>(items: T[], key: (item: T) => string): Record<string, number> {
  const result: Record<string, number> = {};
  for (const item of items) {
    const name = key(item);
    result[name] = (result[name] ?? 0) + 1;
  }
  return result;
}

export type { MonitorEvent };
