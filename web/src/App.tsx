import { useEffect, useState } from 'react';
import { NavLink, Navigate, Route, Routes, useNavigate } from 'react-router-dom';
import { SessionProvider, useSession } from './session';
import { mode } from './api/client';
import { SessionsScreen } from './screens/SessionsScreen';
import { LiveScreen } from './screens/LiveScreen';
import { ProcessesScreen } from './screens/ProcessesScreen';
import { FilesScreen } from './screens/FilesScreen';
import { NetworkScreen } from './screens/NetworkScreen';
import { ThreatsScreen } from './screens/ThreatsScreen';
import { TimelineScreen } from './screens/TimelineScreen';
import { SearchScreen } from './screens/SearchScreen';
import { SettingsScreen } from './screens/SettingsScreen';
import { CoverageBanner, VerdictPill } from './components/ui';
import { ExportButton } from './components/ExportButton';

const NAV = [
  { to: '/', label: 'Sessions' },
  { to: '/live', label: 'Live' },
  { to: '/processes', label: 'Processes' },
  { to: '/files', label: 'Files' },
  { to: '/network', label: 'Network' },
  { to: '/threats', label: 'Detections' },
  { to: '/timeline', label: 'Timeline' },
  { to: '/search', label: 'Search' },
  { to: '/settings', label: 'Settings' },
];

export default function App() {
  return (
    <SessionProvider>
      <Shell />
    </SessionProvider>
  );
}

function Shell() {
  const { session } = useSession();
  const navigate = useNavigate();
  const [density, setDensity] = useState<'dense' | 'comfortable'>('dense');

  useEffect(() => {
    document.documentElement.dataset.density = density;
  }, [density]);

  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      // Ctrl+K and `/` both reach Search from anywhere; neither steals a keystroke from an input.
      const target = event.target as HTMLElement | null;
      const typing = target && ['INPUT', 'TEXTAREA', 'SELECT'].includes(target.tagName);
      if (!typing && ((event.ctrlKey && event.key.toLowerCase() === 'k') || event.key === '/')) {
        event.preventDefault();
        navigate('/search');
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [navigate]);

  return (
    <div className="flex min-h-screen">
      <aside className="flex w-44 shrink-0 flex-col border-r border-ink-800 bg-ink-900/60">
        <div className="border-b border-ink-800 px-3 py-3">
          <div className="text-[13px] font-semibold tracking-wide text-ink-100">ARGUS</div>
          <div className="mt-0.5 text-[10px] uppercase tracking-wider text-ink-400">
            {mode === 'fixture' ? 'fixture data' : 'live agent'}
          </div>
        </div>

        <nav className="flex-1 py-2" aria-label="sections">
          {NAV.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.to === '/'}
              className={({ isActive }) =>
                `block px-3 py-1.5 text-[12px] ${isActive ? 'border-l-2 border-benign bg-ink-850 text-ink-100' : 'border-l-2 border-transparent text-ink-300 hover:bg-ink-850'}`
              }
            >
              {item.label}
            </NavLink>
          ))}
        </nav>

        <div className="border-t border-ink-800 p-3 text-[10px] text-ink-400">
          <button
            type="button"
            onClick={() => setDensity(density === 'dense' ? 'comfortable' : 'dense')}
            className="w-full rounded border border-ink-700 px-2 py-1 text-left hover:bg-ink-850"
            aria-pressed={density === 'comfortable'}
          >
            density: {density}
          </button>
          <p className="mt-2 leading-relaxed">
            Ctrl+K search · arrows move · Enter opens
          </p>
        </div>
      </aside>

      <main className="min-w-0 flex-1">
        <header className="flex items-center justify-between gap-3 border-b border-ink-800 bg-ink-900/40 px-4 py-2">
          <div className="flex min-w-0 items-center gap-2 text-[12px]">
            <span className="text-ink-400">session</span>
            {session ? (
              <>
                <span className="truncate text-ink-100" title={session.targetPath}>{session.targetPath.split(/[\\/]/).pop()}</span>
                <VerdictPill verdict={session.verdict} score={session.score} />
              </>
            ) : (
              <span className="text-ink-400">none</span>
            )}
          </div>
          <div className="flex items-center gap-3 text-[10px] text-ink-400">
            <ExportButton sessionId={session?.id ?? null} />
            <span title="Absence of detection is weaker evidence when the sensor lost events">
              coverage: {session ? (session.coverage.complete ? 'complete' : `${session.coverage.gaps} gaps`) : '—'}
            </span>
            <span>peak {session ? session.peakScore.toFixed(1) : '—'}</span>
          </div>
        </header>

        {session && <CoverageBanner coverage={session.coverage} />}

        <Routes>
          <Route path="/" element={<SessionsScreen />} />
          <Route path="/live" element={<LiveScreen />} />
          <Route path="/processes" element={<ProcessesScreen />} />
          <Route path="/files" element={<FilesScreen />} />
          <Route path="/network" element={<NetworkScreen />} />
          <Route path="/threats" element={<ThreatsScreen />} />
          <Route path="/timeline" element={<TimelineScreen />} />
          <Route path="/search" element={<SearchScreen />} />
          <Route path="/settings" element={<SettingsScreen />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </main>
    </div>
  );
}
