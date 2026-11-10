import { useState } from 'react';
import { exportReport } from '../api/client';

/**
 * Export the session report — HTML for a reader, JSON for a tool.
 *
 * Deliberately next to the session in the header rather than buried in a screen: the report describes
 * the whole session, so it does not belong to any one view. Downloads are fetched with the bearer
 * token and saved from a blob, so the token never appears in a URL that ends up in the address bar,
 * browser history or a proxy log.
 */
export function ExportButton({ sessionId }: { sessionId: string | null }) {
  const [state, setState] = useState<{ busy: boolean; error: string | null; done: string | null }>({
    busy: false,
    error: null,
    done: null,
  });

  const run = async (format: 'html' | 'json') => {
    if (!sessionId) return;
    setState({ busy: true, error: null, done: null });
    try {
      await exportReport(sessionId, format);
      setState({ busy: false, error: null, done: format });
    } catch (error) {
      setState({ busy: false, error: error instanceof Error ? error.message : String(error), done: null });
    }
  };

  const disabled = !sessionId || state.busy;

  return (
    <span className="flex items-center gap-1">
      <span className="text-ink-400">export</span>
      <button
        type="button"
        onClick={() => void run('html')}
        disabled={disabled}
        title={sessionId ? 'Download the self-contained HTML report for this session' : 'Start a session to export a report'}
        className="rounded border border-ink-700 px-1.5 py-0.5 text-[10px] text-ink-200 hover:bg-ink-850 disabled:opacity-40"
      >
        HTML
      </button>
      <button
        type="button"
        onClick={() => void run('json')}
        disabled={disabled}
        title={sessionId ? 'Download the raw JSON bundle the report is built from' : 'Start a session to export a report'}
        className="rounded border border-ink-700 px-1.5 py-0.5 text-[10px] text-ink-200 hover:bg-ink-850 disabled:opacity-40"
      >
        JSON
      </button>
      {state.busy && <span className="text-ink-400">building…</span>}
      {state.done && <span className="text-benign">saved</span>}
      {state.error && (
        <span className="text-malicious" title={state.error}>
          export failed
        </span>
      )}
    </span>
  );
}
