import { createContext, useContext, type ReactNode } from 'react';
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
