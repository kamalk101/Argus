import { useState } from 'react';
import { Link } from 'react-router-dom';
import { useSession } from '../session';
import { Badge, ObservabilityBadge, Panel, StateNote } from '../components/ui';
import { useAsync } from '../hooks/useAsync';
import { getEvidence, listDetections } from '../api/client';
import { clock, elide } from '../lib/format';
import type { StoredDetection } from '../api/types';

export function ThreatsScreen() {
  const { session, loading, error } = useSession();
  const id = session?.id ?? null;
  const detections = useAsync(() => (id ? listDetections(id) : Promise.resolve([])), [id]);

  const [open, setOpen] = useState<string | null>(null);
  const [focus, setFocus] = useState<string | null>(null);

  if (loading) return <StateNote kind="loading" />;
  if (error) return <StateNote kind="error" message={error} />;
  if (!session) return <StateNote kind="empty" message="No session — detections appear here as the rules fire." />;

  if (detections.error) return <StateNote kind="error" message={detections.error} onRetry={detections.reload} />;
  if (detections.loading) return <StateNote kind="loading" />;

  const sorted = [...(detections.data ?? [])].sort((a, b) => b.severity - a.severity || b.firstSeenUtc.localeCompare(a.firstSeenUtc));

  if (sorted.length === 0) {
    return (
      <div className="p-4">
        <StateNote
          kind="empty"
          message={`No rule fired in this session. That is a report about the evidence Argus could see${session.coverage.complete ? '' : ' — and this session had collection gaps, so read it as weaker than usual'}.`}
        />
      </div>
    );
  }

  const focused = focus ? sorted.find((detection) => detection.detectionKey === focus) ?? null : null;
  if (focused) {
    return <Investigate id={id!} detection={focused} onClose={() => setFocus(null)} />;
  }

  return (
    <div className="space-y-2 p-4">
      <div className="flex items-center justify-between">
        <h1 className="text-sm font-semibold uppercase tracking-wider">
          Detections <span className="text-ink-400">({sorted.length})</span>
        </h1>
        <span className="text-[10px] text-ink-400">sorted by severity, then recency</span>
      </div>

      {sorted.map((detection) => (
        <DetectionCard
          key={detection.detectionKey}
          id={id!}
          detection={detection}
          expanded={open === detection.detectionKey}
          onToggle={() => setOpen(open === detection.detectionKey ? null : detection.detectionKey)}
          onInvestigate={() => setFocus(detection.detectionKey)}
        />
      ))}
    </div>
  );
}

function DetectionCard({ id, detection, expanded, onToggle, onInvestigate }: { id: string; detection: StoredDetection; expanded: boolean; onToggle: () => void; onInvestigate: () => void }) {
  const evidence = useAsync(() => (expanded ? getEvidence(id, detection.detectionKey) : Promise.resolve(null)), [expanded, detection.detectionKey]);
  const factors = parseFactors(detection.factorsJson);
  const mitre = detection.mitre?.split(/[,\s]+/).filter(Boolean) ?? [];
  const tone = detection.severity >= 50 ? 'border-malicious/40' : detection.severity >= 30 ? 'border-suspicious/40' : 'border-ink-700';

  return (
    <section className={`rounded border bg-ink-900/50 ${tone}`}>
      <button type="button" onClick={onToggle} aria-expanded={expanded} className="flex w-full items-start gap-3 px-3 py-2 text-left hover:bg-ink-850">
        <span className={detection.severity >= 50 ? 'text-malicious' : 'text-suspicious'} aria-hidden>{detection.severity >= 50 ? '▲' : '●'}</span>
        <span className="min-w-0 flex-1">
          <span className="block truncate text-[13px] text-ink-100">{detection.title}</span>
          <span className="mt-0.5 block truncate text-[11px] text-ink-400">{detection.reason}</span>
        </span>
        <span className="shrink-0 text-right text-[11px]">
          <span className="block">{detection.ruleId}</span>
          <span className={detection.severity >= 50 ? 'text-malicious' : 'text-suspicious'}>severity {detection.severity}</span>
        </span>
        <span className="w-16 shrink-0 text-right text-[11px] text-ink-400">{clock(detection.firstSeenUtc)}</span>
        <span className="w-14 shrink-0 text-right text-[11px] text-ink-400">pid {detection.scopePid}</span>
        <span className="w-16 shrink-0 text-right text-[11px] text-ink-400">{detection.eventCount} ev</span>
      </button>

      {expanded && (
        <div className="space-y-3 border-t border-ink-800 px-3 py-2 text-[12px]">
          <Field label="Why">
            {detection.reason}
          </Field>
          {factors.length > 0 && (
            <Field label="Factors">
              <ul className="space-y-0.5">
                {factors.map((factor) => (
                  <li key={factor} className="text-ink-300">· {factor}</li>
                ))}
              </ul>
            </Field>
          )}
          <Field label="Counterfactual">
            <span className="text-ink-300">{detection.counterfactual}</span>
          </Field>
          <Field label="Weight">
            <span className="text-ink-300">
              w = {detection.weight.toFixed(3)} · confidence {(detection.confidence * 100).toFixed(0)}% · categories {detection.categories}
            </span>
          </Field>
          {mitre.length > 0 && (
            <Field label="MITRE">
              <span className="flex flex-wrap gap-1">
                {mitre.map((technique) => (
                  <Badge key={technique}>{technique}</Badge>
                ))}
              </span>
            </Field>
          )}

          <Field label="Evidence">
            {evidence.loading ? (
              <StateNote kind="loading" />
            ) : evidence.error ? (
              <StateNote kind="error" message={evidence.error} onRetry={evidence.reload} />
            ) : (evidence.data?.events.length ?? 0) === 0 ? (
              <span className="text-ink-400">The agent reported no evidence rows for this detection.</span>
            ) : (
              <ul className="divide-y divide-ink-850 rounded border border-ink-800">
                {evidence.data!.events.map((event) => (
                  <li key={event.seq} className="flex items-baseline gap-2 px-2 py-1">
                    <span className="w-14 shrink-0 text-ink-400">{clock(event.timestampUtc)}</span>
                    <span className="w-16 shrink-0 text-ink-300">{event.category.toLowerCase()}</span>
                    <span className="min-w-0 flex-1 truncate" title={event.target ?? event.imagePath ?? undefined}>
                      {elide(event.target ?? event.imagePath, 52)}
                    </span>
                    <ObservabilityBadge observability={event.observability} />
                  </li>
                ))}
              </ul>
            )}
          </Field>

          <div className="flex gap-2 text-[11px]">
            <button type="button" onClick={onInvestigate} className="rounded border border-ink-600 px-2 py-0.5 hover:bg-ink-850">Investigate</button>
            <Link to="/timeline" className="rounded border border-ink-600 px-2 py-0.5 hover:bg-ink-850">Show in timeline</Link>
            <button
              type="button"
              onClick={() => download(detection, evidence.data?.events ?? [])}
              className="rounded border border-ink-600 px-2 py-0.5 hover:bg-ink-850"
            >
              Export evidence
            </button>
          </div>
        </div>
      )}
    </section>
  );
}

/** The brief's focused mode: the evidence chain as a horizontal graph, each node its own event. */
function Investigate({ id, detection, onClose }: { id: string; detection: StoredDetection; onClose: () => void }) {
  const evidence = useAsync(() => getEvidence(id, detection.detectionKey), [detection.detectionKey]);

  return (
    <div className="space-y-3 p-4">
      <div className="flex items-center justify-between">
        <h1 className="text-sm font-semibold">
          <span className="text-suspicious">{detection.ruleId}</span> {detection.title}
        </h1>
        <button type="button" onClick={onClose} className="rounded border border-ink-600 px-2 py-0.5 text-[11px] hover:bg-ink-850">Close</button>
      </div>

      <p className="text-[12px] text-ink-300">{detection.reason}</p>

      <Panel title="Evidence chain">
        {evidence.loading ? (
          <StateNote kind="loading" />
        ) : evidence.error ? (
          <StateNote kind="error" message={evidence.error} />
        ) : (
          <ol className="flex gap-3 overflow-x-auto p-3">
            {evidence.data!.events.map((event, index) => (
              <li key={event.seq} className="w-56 shrink-0 rounded border border-ink-700 bg-ink-950 p-2 text-[11px]">
                <div className="text-[10px] uppercase tracking-wider text-ink-400">step {index + 1} · {event.category.toLowerCase()}</div>
                <div className="mt-1 truncate" title={event.imageName ?? undefined}>{event.imageName ?? '—'} <span className="text-ink-400">{event.pid}</span></div>
                <div className="mt-1 h-8 overflow-hidden text-ink-300" title={event.target ?? undefined}>{elide(event.target ?? event.imagePath, 34)}</div>
                <div className="mt-1 flex items-center justify-between">
                  <span className="text-ink-400">{clock(event.timestampUtc)}</span>
                  <ObservabilityBadge observability={event.observability} />
                </div>
              </li>
            ))}
            {evidence.data!.events.length === 0 && <li className="text-[12px] text-ink-400">No evidence rows.</li>}
          </ol>
        )}
      </Panel>

      <Panel title="What would change the verdict">
        <p className="p-3 text-[12px] text-ink-300">{detection.counterfactual}</p>
      </Panel>
    </div>
  );
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex gap-3">
      <span className="w-24 shrink-0 text-[10px] uppercase tracking-wider text-ink-400">{label}</span>
      <span className="min-w-0 flex-1">{children}</span>
    </div>
  );
}

function parseFactors(factorsJson: string | null | undefined): string[] {
  if (!factorsJson) return [];
  try {
    const parsed = JSON.parse(factorsJson) as unknown;
    if (Array.isArray(parsed)) return parsed.map(String);
    if (typeof parsed === 'string') return [parsed];
    return [];
  } catch {
    return factorsJson.length > 0 ? [factorsJson] : [];
  }
}

function download(detection: StoredDetection, events: unknown[]) {
  const payload = JSON.stringify({ detection, events }, null, 2);
  const url = URL.createObjectURL(new Blob([payload], { type: 'application/json' }));
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = `argus-${detection.ruleId}-${detection.id}.json`;
  anchor.click();
  URL.revokeObjectURL(url);
}
