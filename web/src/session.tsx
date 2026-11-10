import { createContext, useContext, useEffect, type ReactNode } from 'react';
import type { SessionState } from './api/types';
import { listSessions } from './api/client';
import { useAsync } from './hooks/useAsync';

interface SessionContextValue {
  sessions: SessionState[] | null;
  session: SessionState | null;
  error: string | null;
  loading: boolean;
  reload: () => void;
}

const SessionContext = createContext<SessionContextValue>({
  sessions: null,
  session: null,
  error: null,
  loading: true,
  reload: () => {},
});

/**
 * The newest session, loaded once for the whole shell. Screens read it from here so that the header,
 * the sidebar counters and the tables cannot disagree about which session they are describing.
 */
export function SessionProvider({ children }: { children: ReactNode }) {
  const state = useAsync(listSessions, []);

  // Refetching happens where the change happens: the launch dialog calls `reload` once the agent has
  // answered. A blanket reload on every navigation was tried and reverted — it re-rendered screens
  // mid-interaction (measured: the Ctrl+K focus moved to a freshly mounted input) for no new data.
  //
  // A session can also appear from outside the window (the CLI, another dashboard). Without this poll
  // the shell says "No session to watch" while the agent is monitoring — a false statement about the
  // machine, and there is no refresh control in the packaged window. It stops as soon as a running
  // session is known, so the cost is a few loopback requests, not a steady stream.
  const running = state.data?.some((entry) => entry.status === 'running') ?? false;
  useEffect(() => {
    if (running || !state.data) {
      return;
    }

    const timer = window.setInterval(state.reload, 10_000);
    return () => window.clearInterval(timer);
  }, [running, state.data, state.reload]);

  const sessions = state.data;
  const newest = sessions && sessions.length > 0 ? [...sessions].sort((a, b) => b.startedUtc.localeCompare(a.startedUtc))[0] : null;

  return (
    <SessionContext.Provider value={{ sessions, session: newest, error: state.error, loading: state.loading, reload: state.reload }}>
      {children}
    </SessionContext.Provider>
  );
}

export function useSession(): SessionContextValue {
  return useContext(SessionContext);
}
