import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { inspectTarget, mode, startSession } from '../api/client';
import type { TargetPreview } from '../api/client';
import type { SessionState } from '../api/types';
import { Badge } from '../components/ui';
import { useSession } from '../session';
import { bytes } from '../lib/format';

/**
 * "Monitor an application": the operator names what to run, sees what it is — path, size, signature,
 * SHA-256 — and only then starts it. Nothing is launched until that preview has been shown, because
 * the subject of the session is the one decision the whole report hangs on.
 *
 * The dialog is a plain form rather than a native file picker: a browser cannot hand back a full
 * path, and the agent's `/api/inspect` already answers from the machine the agent runs on.
 */
export function LaunchDialog({ onClose }: { onClose: () => void }) {
  const navigate = useNavigate();
  const { reload } = useSession();
  const [path, setPath] = useState('');
  const [args, setArgs] = useState('');
  const [preview, setPreview] = useState<TargetPreview | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const canLaunch = preview?.exists === true && preview.executable === true;

  const inspect = async () => {
    setBusy(true);
    setError(null);
    setPreview(null);
    try {
      setPreview(await inspectTarget(path));
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : String(cause));
    } finally {
      setBusy(false);
    }
  };

  const launch = async () => {
    setBusy(true);
    setError(null);
    try {
      const session: SessionState = await startSession({ path, args: args || undefined, mode: 'launch' });
      // The shell's list predates this session by definition; without this the sidebar would keep
      // describing the previous run until the next navigation.
      reload();
      // The agent launches before it answers, so a slow target is not a failed launch; navigating to
      // the live screen is what shows progress (or the absence of it).
      navigate(`/live?session=${session.id}`);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : String(cause));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center bg-black/60 pt-24" role="dialog" aria-modal="true" aria-label="Monitor an application">
      <div className="w-[560px] rounded border border-ink-700 bg-ink-900 p-4 shadow-xl">
        <div className="flex items-start justify-between">
          <div>
            <h2 className="text-[13px] font-semibold">Monitor an application</h2>
            <p className="mt-1 text-[11px] text-ink-400">
              Argus launches this program and watches it and everything it starts. Nothing else on the machine is monitored.
            </p>
          </div>
          <button type="button" onClick={onClose} className="rounded border border-ink-700 px-2 py-0.5 text-[11px] text-ink-300 hover:bg-ink-850">
            Close
          </button>
        </div>

        {mode === 'fixture' && (
          <p className="mt-3 rounded border border-suspicious/40 bg-suspicious/10 px-2 py-1 text-[11px] text-suspicious">
            This is fixture data — there is no agent to launch anything. Start a live agent to use this dialog.
          </p>
        )}

        <label className="mt-3 block text-[10px] uppercase tracking-wider text-ink-400" htmlFor="target-path">
          executable path
        </label>
        <input
          id="target-path"
          value={path}
          onChange={(event) => setPath(event.target.value)}
          placeholder="C:\Program Files\Contoso\app.exe"
          spellCheck={false}
          className="mt-1 w-full rounded border border-ink-700 bg-ink-950 px-2 py-1 text-[12px] focus:border-benign focus:outline-none"
        />

        <label className="mt-2 block text-[10px] uppercase tracking-wider text-ink-400" htmlFor="target-args">
          arguments (optional)
        </label>
        <input
          id="target-args"
          value={args}
          onChange={(event) => setArgs(event.target.value)}
          spellCheck={false}
          className="mt-1 w-full rounded border border-ink-700 bg-ink-950 px-2 py-1 text-[12px] focus:border-benign focus:outline-none"
        />

        <div className="mt-3 flex items-center gap-2">
          <button
            type="button"
            onClick={inspect}
            disabled={busy || path.trim().length === 0 || mode === 'fixture'}
            className="rounded border border-ink-600 px-2 py-1 text-[11px] hover:bg-ink-850 disabled:opacity-40"
          >
            Check this file
          </button>
          <button
            type="button"
            onClick={launch}
            disabled={!canLaunch || busy}
            className="rounded border border-benign/50 bg-benign/10 px-2 py-1 text-[11px] text-benign hover:bg-benign/20 disabled:opacity-40"
          >
            {busy && canLaunch ? 'Starting…' : 'Start monitoring'}
          </button>
          {preview && !preview.exists && <span className="text-[11px] text-malicious">no such file on the agent's machine</span>}
          {preview?.exists && preview.executable === false && <span className="text-[11px] text-malicious">not an .exe</span>}
        </div>

        {error && <p role="alert" className="mt-3 text-[11px] text-malicious">{error}</p>}

        {preview?.exists && (
          <dl className="mt-3 space-y-1 rounded border border-ink-800 bg-ink-950/60 p-2 text-[11px]">
            <div className="flex gap-2">
              <dt className="w-20 shrink-0 text-ink-400">name</dt>
              <dd>{preview.name}</dd>
            </div>
            <div className="flex gap-2">
              <dt className="w-20 shrink-0 text-ink-400">size</dt>
              <dd>{bytes(preview.size)}</dd>
            </div>
            <div className="flex gap-2">
              <dt className="w-20 shrink-0 text-ink-400">signature</dt>
              <dd>
                <Badge tone={preview.signature === 'valid' ? 'info' : preview.signature === 'invalid' ? 'bad' : 'warn'}>{preview.signature}</Badge>
                {preview.signature !== 'valid' && (
                  <span className="ml-2 text-ink-400">unknown means the check could not run — never read it as “unsigned”</span>
                )}
              </dd>
            </div>
            <div className="flex gap-2">
              <dt className="w-20 shrink-0 text-ink-400">sha-256</dt>
              <dd className="break-all font-mono text-[10px]">{preview.sha256 ?? 'not readable'}</dd>
            </div>
            <div className="flex gap-2">
              <dt className="w-20 shrink-0 text-ink-400">path</dt>
              <dd className="break-all">{preview.path}</dd>
            </div>
          </dl>
        )}
      </div>
    </div>
  );
}
