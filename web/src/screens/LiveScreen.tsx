import { useEffect, useMemo, useRef, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { useSession } from '../session';
import { Counter, Panel, StateNote, VerdictPill, Badge } from '../components/ui';
import { RiskChart } from '../components/RiskChart';
import { clock, duration, elide, number } from '../lib/format';
import { getSession, getTimeline, listScores, streamUrl } from '../api/client';
import { useAsync } from '../hooks/useAsync';
import type { MonitorEvent } from '../api/types';

type Link = 'connecting' | 'open' | 'reconnecting' | 'fixture';

/** A counter the stream has not reported yet reads "—", never 0. */
function counter(value: number | undefined): string {
  return typeof value === 'number' ? number(value) : '—';
}

/**
 * Live dashboard. Frames arrive over SSE (state, stats, events, detection, score, gap); the screen
 * treats them as hints and refetches the snapshot on reconnect, so a dropped connection recovers the
 * real state rather than silently showing a stale one.
 */
export function LiveScreen() {
  const context = useSession();
  const [params] = useSearchParams();
  const routeId = params.get('session') ?? undefined;

  // A launch navigates to /live?session=<id>, and the shell may still hold the list from before that
  // session existed. The URL is the more specific statement, so it wins; the context is the fallback.
  const named = useAsync(() => (routeId ? getSession(routeId) : Promise.resolve(null)), [routeId]);
  const session = routeId ? named.data : context.session;
  const loading = routeId ? named.loading : context.loading;
  const error = routeId ? named.error : context.error;
  const reload = routeId ? named.reload : context.reload;
  const id = session?.id;

  const timeline = useAsync(() => (id ? getTimeline(id) : Promise.resolve(null)), [id]);
  const scores = useAsync(() => (id ? listScores(id) : Promise.resolve(null)), [id]);

  const [liveEvents, setLiveEvents] = useState<MonitorEvent[]>([]);
  const [link, setLink] = useState<Link>('connecting');
  const [stats, setStats] = useState<{ monitor: { eventsSeen: number; eventsForwarded: number; outsideScope: number; throttled: boolean } | null } | null>(null);
  const [paused, setPaused] = useState(false);
  const sourceRef = useRef<EventSource | null>(null);

  useEffect(() => {
    if (!id) return;
    let cancelled = false;
    let retry = 0;

    const connect = async () => {
      const url = await streamUrl(id);
      if (cancelled) return;
      if (!url) {
        setLink('fixture');
        return;
      }

      const source = new EventSource(url);
      sourceRef.current = source;
      source.onopen = () => {
        retry = 0;
        setLink('open');
      };
      source.onerror = () => {
        source.close();
        if (cancelled) return;
        setLink('reconnecting');
        // Reconnect on a widening delay, and refetch the snapshot: the stream only carries deltas.
        retry = Math.min(retry + 1, 5);
        window.setTimeout(() => {
          if (cancelled) return;
          timeline.reload();
          scores.reload();
          void connect();
        }, 500 * retry);
      };

      source.addEventListener('events', (frame) => {
        const batch = JSON.parse((frame as MessageEvent).data) as MonitorEvent[];
        setLiveEvents((current) => [...batch.reverse(), ...current].slice(0, 300));
      });
      source.addEventListener('stats', (frame) => setStats(JSON.parse((frame as MessageEvent).data)));
      source.addEventListener('state', () => {
        reload();
      });
      source.addEventListener('score', () => scores.reload());
      source.addEventListener('detection', () => timeline.reload());
    };

    void connect();
    return () => {
      cancelled = true;
      sourceRef.current?.close();
    };
    // `timeline`/`scores` are stable per id; including them would reconnect on every refetch.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [id]);

  const allEvents = useMemo(() => {
    const base = timeline.data?.events ?? [];
    const seen = new Set(liveEvents.map((event) => event.seq));
    return [...liveEvents, ...base.filter((event) => !seen.has(event.seq))].slice(0, 400);
  }, [timeline.data, liveEvents]);

  const marks = useMemo(
    () => (timeline.data?.detections ?? []).map((detection) => ({ at: detection.firstSeenUtc, label: `${detection.ruleId} ${detection.title}` })),
    [timeline.data],
  );

  if (loading) return <StateNote kind="loading" />;
  if (error) return <StateNote kind="error" message={error} onRetry={reload} />;
  if (!session) return <StateNote kind="empty" message="No session to watch. Start one and this screen attaches to it." />;

  const counters = {
    processes: allEvents.filter((event) => event.category === 'Process').length,
    fileOps: allEvents.filter((event) => event.category === 'File').length,
    network: allEvents.filter((event) => event.category === 'Network').length,
    suspicious: timeline.data?.detections.length ?? 0,
  };

  return (
    <div className="space-y-3">
      {/* The shell already renders the coverage banner; repeating it here would double the alarm. */}
      <div className="flex flex-wrap items-center justify-between gap-3 px-4 pt-3">
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <h1 className="truncate text-sm text-ink-100" title={session.targetPath}>{elide(session.targetPath, 40)}</h1>
            <VerdictPill verdict={session.verdict} score={session.score} />
            <Badge tone={session.status === 'running' ? 'info' : 'neutral'}>{session.status}</Badge>
          </div>
          <div className="mt-1 text-[11px] text-ink-400">
            root pid {session.rootPid} · started {clock(session.startedUtc)} · {duration(session.startedUtc, session.endedUtc)}
            {session.recordPath && <span title={session.recordPath}> · recording</span>}
          </div>
        </div>

        <div className="flex items-center gap-2 text-[11px]">
          <span className={link === 'open' ? 'text-benign' : link === 'fixture' ? 'text-ink-400' : 'text-suspicious'} aria-live="polite">
            {link === 'open' ? 'live' : link === 'fixture' ? 'fixture data (no stream)' : link === 'reconnecting' ? 'reconnecting…' : 'connecting…'}
          </span>
          <button
            type="button"
            onClick={() => setPaused((value) => !value)}
            className="rounded border border-ink-600 px-2 py-0.5 text-ink-300 hover:bg-ink-850"
            aria-pressed={paused}
          >
            {paused ? 'resume feed' : 'pause feed'}
          </button>
          <button type="button" disabled title="Stopping needs the agent (Phase 5)" className="rounded border border-ink-700 px-2 py-0.5 text-ink-400 disabled:cursor-not-allowed">
            Stop monitoring
          </button>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-2 px-4 md:grid-cols-3 xl:grid-cols-6">
        <Counter label="risk" value={session.score.toFixed(1)} tone={session.score >= 50 ? 'text-malicious' : session.score >= 20 ? 'text-suspicious' : 'text-benign'} />
        <Counter label="peak" value={session.peakScore.toFixed(1)} />
        <Counter label="processes" value={number(counters.processes)} />
        <Counter label="file ops" value={number(counters.fileOps)} />
        <Counter label="network" value={number(counters.network)} />
        <Counter label="suspicious events" value={number(counters.suspicious)} tone={counters.suspicious > 0 ? 'text-suspicious' : undefined} />
      </div>

      <div className="grid gap-3 px-4 xl:grid-cols-3">
        <Panel title="Risk over time" className="xl:col-span-2" actions={<span className="text-[10px] text-ink-400">1 s samples · detection markers</span>}>
          {scores.error ? (
            <StateNote kind="error" message={scores.error} onRetry={scores.reload} />
          ) : scores.loading ? (
            <StateNote kind="loading" />
          ) : (
            <RiskChart points={scores.data ?? []} marks={marks} />
          )}
        </Panel>

        <Panel title="Collection health">
          <dl className="grid grid-cols-2 gap-2 p-3 text-[11px]">
            {/* Unknown is not zero. The fallbacks here used to print 0 for "the frame has not arrived
                yet" and the rendered-row count for "forwarded", which is how a broken stats frame looked
                like a quiet sensor instead of an error. */}
            <div><dt className="text-ink-400">events seen</dt><dd>{counter(stats?.monitor?.eventsSeen)}</dd></div>
            <div><dt className="text-ink-400">forwarded</dt><dd>{counter(stats?.monitor?.eventsForwarded)}</dd></div>
            <div><dt className="text-ink-400">outside scope</dt><dd>{counter(stats?.monitor?.outsideScope)}</dd></div>
            <div>
              <dt className="text-ink-400">throttled</dt>
              <dd className={stats?.monitor?.throttled ? 'text-suspicious' : 'text-ink-300'}>
                {stats?.monitor ? (stats.monitor.throttled ? 'yes' : 'no') : '—'}
              </dd>
            </div>
            <div className="col-span-2">
              <dt className="text-ink-400">gaps</dt>
              <dd className={session.coverage.complete ? 'text-benign' : 'text-suspicious'}>
                {session.coverage.complete ? 'none reported' : `${session.coverage.gaps} — ${session.coverage.reasons.join('; ')}`}
              </dd>
            </div>
          </dl>
        </Panel>
      </div>

      <div className="grid gap-3 px-4 pb-4 xl:grid-cols-3">
        <Panel title="Live signal feed" className="xl:col-span-2" actions={<span className="text-[10px] text-ink-400">newest first{paused ? ' · paused' : ''}</span>}>
          <ul className="max-h-[320px] overflow-auto" onMouseEnter={() => setPaused(true)} onMouseLeave={() => setPaused(false)}>
            {allEvents.slice(0, 120).map((event) => (
              <li key={event.seq} className="row-dense flex items-baseline gap-2 border-b border-ink-850 px-3 py-1 text-[12px]">
                <span className="w-16 shrink-0 text-ink-400">{clock(event.timestampUtc)}</span>
                <span className="w-20 shrink-0 text-ink-300">{event.category.toLowerCase()}</span>
                <span className="w-32 shrink-0 truncate">{event.imageName ?? '—'}</span>
                <span className="min-w-0 flex-1 truncate text-ink-300" title={event.target ?? undefined}>{elide(event.target ?? event.hostName ?? '', 46)}</span>
              </li>
            ))}
            {allEvents.length === 0 && <li className="px-3 py-4 text-[12px] text-ink-400">No events yet.</li>}
          </ul>
        </Panel>

        <Panel title="Top rules triggered">
          <ul className="p-3 text-[12px]">
            {(timeline.data?.detections ?? []).slice(0, 8).map((detection) => (
              <li key={detection.ruleId + detection.firstSeenUtc} className="flex items-baseline justify-between gap-2 border-b border-ink-850 py-1 last:border-0">
                <span className="truncate" title={detection.reason}>{detection.ruleId} <span className="text-ink-300">{detection.title}</span></span>
                <span className={detection.severity >= 50 ? 'text-malicious' : 'text-suspicious'}>{detection.severity}</span>
              </li>
            ))}
            {(timeline.data?.detections ?? []).length === 0 && <li className="text-ink-400">No detections in this session.</li>}
          </ul>
        </Panel>
      </div>
    </div>
  );
}
