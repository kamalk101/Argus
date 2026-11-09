import { Link } from 'react-router-dom';
import { useSession } from '../session';
import { Counter, Panel, StateNote, VerdictPill } from '../components/ui';
import { clock, duration, elide, number, stamp } from '../lib/format';
import type { SessionState } from '../api/types';

export function SessionsScreen() {
  const { sessions, error, loading, reload } = useSession();

  if (loading) return <StateNote kind="loading" />;
  if (error) return <StateNote kind="error" message={`Could not list sessions: ${error}`} onRetry={reload} />;
  if (!sessions || sessions.length === 0) {
    return (
      <StateNote
        kind="empty"
        message="No sessions yet. Start one with “Monitor an application”, or record a session with scripts/corpus.ps1 and replay it."
      />
    );
  }

  const newest = sessions[0];
  const totals = sessions.reduce(
    (sum, session) => ({ gaps: sum.gaps + (session.coverage.complete ? 0 : session.coverage.gaps) }),
    { gaps: 0 },
  );

  return (
    <div className="space-y-4 p-4">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-sm font-semibold uppercase tracking-wider text-ink-100">Sessions</h1>
          <p className="mt-1 text-[12px] text-ink-400">
            Every monitored run, newest first. A verdict is only ever a summary of detections below it.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            type="button"
            disabled
            title="Launching a target needs the elevated agent on Windows (Phase 5 wires this button)."
            className="rounded border border-ink-600 px-3 py-1.5 text-[12px] text-ink-400 disabled:cursor-not-allowed"
          >
            Monitor an application
          </button>
          <Link to="/live" className="rounded border border-benign/40 bg-benign/10 px-3 py-1.5 text-[12px] text-benign hover:bg-benign/20">
            Live dashboard
          </Link>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-2 md:grid-cols-4">
        <Counter label="sessions" value={number(sessions.length)} />
        <Counter label="newest verdict" value={<VerdictPill verdict={newest.verdict} score={newest.score} />} />
        <Counter label="collection gaps" value={number(totals.gaps)} tone={totals.gaps > 0 ? 'text-suspicious' : undefined} />
        <Counter label="agent pid (newest)" value={number(newest.rootPid)} />
      </div>

      <div className="grid gap-3 lg:grid-cols-2">
        {sessions.map((session) => (
          <SessionCard key={session.id} session={session} />
        ))}
      </div>

      <Panel title="History">
        <table className="w-full border-collapse text-[12px]">
          <thead>
            <tr className="border-b border-ink-800 text-left text-[10px] uppercase tracking-wider text-ink-400">
              <th className="px-3 py-1.5 font-medium">started</th>
              <th className="px-3 py-1.5 font-medium">target</th>
              <th className="px-3 py-1.5 font-medium">verdict</th>
              <th className="px-3 py-1.5 font-medium">risk</th>
              <th className="px-3 py-1.5 font-medium">duration</th>
              <th className="px-3 py-1.5 font-medium">coverage</th>
              <th className="px-3 py-1.5 font-medium">session</th>
            </tr>
          </thead>
          <tbody>
            {sessions.map((session) => (
              <tr key={session.id} className="border-b border-ink-850 hover:bg-ink-850">
                <td className="px-3 py-1.5 text-ink-300">{stamp(session.startedUtc)}</td>
                <td className="px-3 py-1.5" title={session.targetPath}>{elide(session.targetPath, 26)}</td>
                <td className="px-3 py-1.5"><VerdictPill verdict={session.verdict} /></td>
                <td className="px-3 py-1.5">{session.score.toFixed(1)} <span className="text-ink-400">/ peak {session.peakScore.toFixed(1)}</span></td>
                <td className="px-3 py-1.5 text-ink-300">{duration(session.startedUtc, session.endedUtc)}</td>
                <td className="px-3 py-1.5">
                  {session.coverage.complete ? (
                    <span className="text-benign">complete</span>
                  ) : (
                    <span className="text-suspicious" title={session.coverage.statement}>{session.coverage.gaps} gaps</span>
                  )}
                </td>
                <td className="px-3 py-1.5 text-ink-400">{session.id.slice(0, 8)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </Panel>
    </div>
  );
}

function SessionCard({ session }: { session: SessionState }) {
  return (
    <Panel className="p-3">
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0">
          <div className="truncate text-[13px] text-ink-100" title={session.targetPath}>
            {session.targetPath.split(/[\\/]/).pop()}
          </div>
          <div className="mt-0.5 truncate text-[11px] text-ink-400" title={session.targetPath}>
            {elide(session.targetPath, 34)}
          </div>
        </div>
        <VerdictPill verdict={session.verdict} score={session.score} />
      </div>

      <dl className="mt-3 grid grid-cols-3 gap-2 text-[11px]">
        <div>
          <dt className="text-ink-400">status</dt>
          <dd className={session.status === 'running' ? 'text-benign' : 'text-ink-300'}>{session.status}</dd>
        </div>
        <div>
          <dt className="text-ink-400">peak</dt>
          <dd>{session.peakScore.toFixed(1)}</dd>
        </div>
        <div>
          <dt className="text-ink-400">started</dt>
          <dd>{clock(session.startedUtc)}</dd>
        </div>
        <div>
          <dt className="text-ink-400">duration</dt>
          <dd>{duration(session.startedUtc, session.endedUtc)}</dd>
        </div>
        <div>
          <dt className="text-ink-400">root pid</dt>
          <dd>{session.rootPid}</dd>
        </div>
        <div>
          <dt className="text-ink-400">coverage</dt>
          <dd className={session.coverage.complete ? 'text-benign' : 'text-suspicious'}>
            {session.coverage.complete ? 'complete' : `${session.coverage.gaps} gaps`}
          </dd>
        </div>
      </dl>

      <div className="mt-3 flex gap-2 text-[11px]">
        <Link to="/live" className="text-benign hover:underline">Live</Link>
        <Link to="/threats" className="text-ink-300 hover:underline">Detections</Link>
        <Link to="/timeline" className="text-ink-300 hover:underline">Timeline</Link>
      </div>
    </Panel>
  );
}
