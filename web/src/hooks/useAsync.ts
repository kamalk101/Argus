import { useCallback, useEffect, useState } from 'react';

export interface AsyncState<T> {
  data: T | null;
  error: string | null;
  loading: boolean;
  reload: () => void;
}

/**
 * One loading lifecycle for every screen: loading, error, data, refetch. Screens render their three
 * states explicitly — the specification forbids a spinner that could equally mean "empty" or "the
 * agent is down".
 */
export function useAsync<T>(load: () => Promise<T>, deps: unknown[]): AsyncState<T> {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [nonce, setNonce] = useState(0);

  // `load` is recreated every render by callers; the dep list is what actually drives reloads.
  // eslint-disable-next-line react-hooks/exhaustive-deps
  const run = useCallback(load, deps);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);

    run()
      .then((value) => {
        if (!cancelled) {
          setData(value);
          setLoading(false);
        }
      })
      .catch((cause: unknown) => {
        if (!cancelled) {
          setError(cause instanceof Error ? cause.message : String(cause));
          setLoading(false);
        }
      });

    return () => {
      cancelled = true;
    };
  }, [run, nonce]);

  const reload = useCallback(() => setNonce((value) => value + 1), []);
  return { data, error, loading, reload };
}

/** The session every screen is about: the one in the route, else the newest the agent reports. */
export function useSessionId(routeId: string | undefined, sessions: { id: string }[] | null): string | null {
  if (routeId) {
    return routeId;
  }
  return sessions && sessions.length > 0 ? sessions[0].id : null;
}
