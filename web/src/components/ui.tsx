import type { ReactNode } from 'react';
import { bandOf } from '../lib/format';
import type { Coverage } from '../api/types';

const BAND_STYLE: Record<string, string> = {
  Benign: 'text-benign border-benign/40 bg-benign/10',
  Suspicious: 'text-suspicious border-suspicious/40 bg-suspicious/10',
  Malicious: 'text-malicious border-malicious/40 bg-malicious/10',
  Unknown: 'text-ink-300 border-ink-600 bg-ink-800',
};

export function VerdictPill({ verdict, score }: { verdict: string | null | undefined; score?: number }) {
  const band = bandOf(verdict);
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded border px-2 py-0.5 text-[11px] font-semibold uppercase tracking-wide ${BAND_STYLE[band]}`}
      role="status"
      aria-label={`verdict ${band}${score === undefined ? '' : `, risk ${score.toFixed(1)}`}`}
    >
      {band}
      {score !== undefined && <span className="font-mono text-[11px] opacity-80">{score.toFixed(1)}</span>}
    </span>
  );
}

export function Badge({ children, tone = 'neutral', title }: { children: ReactNode; tone?: 'neutral' | 'warn' | 'info' | 'bad'; title?: string }) {
  const tones = {
    neutral: 'border-ink-600 text-ink-300',
    warn: 'border-suspicious/50 text-suspicious',
    info: 'border-ink-500 text-ink-100',
    bad: 'border-malicious/50 text-malicious',
  } as const;
  return (
    <span title={title} className={`inline-flex items-center rounded border px-1.5 py-px text-[10px] uppercase tracking-wide ${tones[tone]}`}>
      {children}
    </span>
  );
}

/**
 * The observability badge every event row carries. The agent's vocabulary is `Direct` (the sensor
 * recorded this event itself), `Inferred` (attributed via the owner table or tree location) and
 * `Partial` (some field could not be resolved). They are not synonyms: only the first is a direct
 * observation, and the dashboard says which one you are looking at.
 */
export function ObservabilityBadge({ observability }: { observability: string }) {
  if (observability === 'Direct') {
    return (
      <span className="text-[10px] uppercase tracking-wide text-benign/80" title="Recorded by the sensor directly: process, time and target all resolved">
        observed
      </span>
    );
  }
  if (observability === 'Inferred') {
    return (
      <span className="text-[10px] uppercase tracking-wide text-suspicious/90" title="Attributed by inference (owner table or tree location), not by a direct sensor record">
        inferred
      </span>
    );
  }
  return (
    <span className="text-[10px] uppercase tracking-wide text-ink-400" title="Partially resolved: at least one field could not be attributed">
      {observability.toLowerCase()}
    </span>
  );
}

/**
 * Persistent, not dismissible. A session with gaps is not the same evidence as a clean one, and the
 * score alone cannot say so.
 */
export function CoverageBanner({ coverage }: { coverage: Coverage | null | undefined }) {
  if (!coverage) return null;
  if (coverage.complete) {
    return (
      <div className="border-b border-ink-800 bg-ink-900/60 px-4 py-1.5 text-[11px] text-ink-400">
        Collection complete — no gaps reported by the sensor.
      </div>
    );
  }
  return (
    <div role="alert" className="border-b border-suspicious/40 bg-suspicious/10 px-4 py-1.5 text-[11px] text-suspicious">
      This session has collection gaps — absence of detection here is weaker evidence than usual.
      <span className="ml-2 text-suspicious/80">
        {coverage.gaps} gap{coverage.gaps === 1 ? '' : 's'}
        {coverage.reasons.length > 0 ? `: ${coverage.reasons.join('; ')}` : ''}
      </span>
    </div>
  );
}

export function Panel({ title, actions, children, className = '' }: { title?: ReactNode; actions?: ReactNode; children: ReactNode; className?: string }) {
  return (
    <section className={`rounded border border-ink-800 bg-ink-900/50 ${className}`}>
      {(title || actions) && (
        <header className="flex items-center justify-between border-b border-ink-800 px-3 py-2">
          <h2 className="text-[11px] font-semibold uppercase tracking-wider text-ink-300">{title}</h2>
          {actions}
        </header>
      )}
      {children}
    </section>
  );
}

/** Loading, empty and error are three different facts and never look alike. */
export function StateNote({ kind, message, onRetry }: { kind: 'loading' | 'empty' | 'error'; message?: string; onRetry?: () => void }) {
  if (kind === 'loading') {
    return <div className="px-3 py-6 text-[12px] text-ink-400">Loading…</div>;
  }
  if (kind === 'empty') {
    return <div className="px-3 py-6 text-[12px] text-ink-400">{message ?? 'Nothing here — and that is a measurement, not a failure.'}</div>;
  }
  return (
    <div role="alert" className="px-3 py-6 text-[12px] text-malicious">
      {message ?? 'Could not load.'}
      {onRetry && (
        <button type="button" onClick={onRetry} className="ml-3 rounded border border-malicious/50 px-2 py-0.5 text-malicious hover:bg-malicious/10">
          Retry
        </button>
      )}
    </div>
  );
}

export function Counter({ label, value, tone }: { label: string; value: ReactNode; tone?: string }) {
  return (
    <div className="rounded border border-ink-800 bg-ink-900/60 px-3 py-2">
      <div className="text-[10px] uppercase tracking-wider text-ink-400">{label}</div>
      <div className={`mt-0.5 text-lg leading-none ${tone ?? 'text-ink-100'}`}>{value}</div>
    </div>
  );
}
