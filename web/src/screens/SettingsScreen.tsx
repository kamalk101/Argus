import { Badge, Panel, StateNote } from '../components/ui';
import { useAsync } from '../hooks/useAsync';
import { getSettings, mode } from '../api/client';

/**
 * Settings, as facts rather than switches.
 *
 * Everything here is read from the running agent (`GET /api/settings`): the port it actually bound,
 * the rules it loaded, the digest that identifies that configuration, and the observability table the
 * exported report prints. The agent reads its options at launch, so a toggle on this screen could not
 * take effect — offering one would describe a program other than the one running. The honest shape is
 * therefore a report of what *is*, with the restart instruction beside it.
 */

/** Human labels for the threshold keys. A key with no label is shown by its raw name rather than
 *  hidden: a new threshold must not become invisible the day it ships. */
const LABELS: Record<string, string> = {
  massFileCreationCount: 'Files created before F-004 reports a rate',
  massFileCreationWindowSeconds: 'F-004 window (seconds)',
  destructiveRenameCount: 'Rewrites/marker renames before F-006 reports',
  destructiveRenameDirectories: 'Distinct directories F-006 needs',
  destructiveRenameWindowSeconds: 'F-006 window (seconds)',
  beaconConnections: 'Connections before N-002 reports a beacon',
  beaconWindowSeconds: 'N-002 window (seconds)',
  beaconMinMeanIntervalSeconds: 'N-002 minimum mean interval (seconds)',
  beaconMaxJitter: 'N-002 maximum coefficient of variation',
  repeatedFlagsThreshold: 'Relaunches before P-006 reports',
  repeatedFlagsWindowSeconds: 'P-006 window (seconds)',
  outboundVolumeBytes: 'Outbound bytes in the window before N-003 reports',
  outboundVolumeWindowSeconds: 'N-003 window (seconds)',
  failedLookupCount: 'Failed lookups before N-005 reports',
  failedLookupWindowSeconds: 'N-005 window (seconds)',
};

function label(key: string): string {
  return LABELS[key] ?? key.replace(/([A-Z])/g, ' $1').replace(/^./, (c) => c.toUpperCase());
}

function value(key: string, raw: number): string {
  if (/Window|Interval/i.test(key)) return `${raw} s`;
  if (/Bytes/i.test(key)) return `${(raw / (1024 * 1024)).toFixed(1)} MB`;
  if (/Jitter|WindowSeconds$/i.test(key) && raw < 1) return raw.toFixed(2);
  return String(raw);
}

export function SettingsScreen() {
  const settings = useAsync(() => getSettings(), []);

  if (settings.loading && !settings.data) return <StateNote kind="loading" message="Reading agent configuration…" />;
  if (settings.error && !settings.data) {
    return (
      <StateNote
        kind="error"
        message={`The agent did not answer /api/settings: ${settings.error.message}`}
        onRetry={settings.reload}
      />
    );
  }
  if (!settings.data) return <StateNote kind="empty" message="No configuration was reported." />;

  const agent = settings.data;
  const thresholds = Object.entries(agent.rules ?? {});

  return (
    <div className="space-y-3 p-3">
      <Panel
        title="This agent"
        actions={
          mode === 'fixture' ? (
            <Badge tone="info" title="Captured from a real session; nothing here is answering live">
              captured payload
            </Badge>
          ) : (
            <Badge tone={agent.elevated ? 'info' : 'warn'} title={agent.elevated ? 'Full ETW visibility' : 'Degraded: no kernel provider'}>
              {agent.elevated ? 'elevated' : 'not elevated'}
            </Badge>
          )
        }
      >
        <dl className="grid grid-cols-[190px_1fr] gap-x-3 gap-y-1 text-[12px]">
          <dt className="text-ink-400">version</dt>
          <dd className="text-ink-100">{agent.agent}</dd>
          <dt className="text-ink-400">process</dt>
          <dd>
            pid {agent.agentPid} · {agent.runtime}
          </dd>
          <dt className="text-ink-400">windows</dt>
          <dd>
            {agent.os} (build {agent.osBuild})
          </dd>
          <dt className="text-ink-400">listening on</dt>
          <dd title={agent.requestedPort === 0 ? 'The port was chosen by the OS (--port 0)' : undefined}>
            127.0.0.1:{agent.port}
            {agent.requestedPort === 0 ? <span className="text-ink-400"> · chosen by the OS</span> : null}
          </dd>
          <dt className="text-ink-400">sessions on disk</dt>
          <dd className="break-all">{agent.dataRoot}</dd>
          <dt className="text-ink-400">dashboard root</dt>
          <dd className="break-all">{agent.webRoot}</dd>
          <dt className="text-ink-400">ETW session name</dt>
          <dd>{agent.sessionName}</dd>
          <dt className="text-ink-400">duration limit</dt>
          <dd>{agent.durationSeconds ? `${agent.durationSeconds} s` : 'none · stops when asked'}</dd>
          <dt className="text-ink-400">config digest</dt>
          <dd>
            <code className="text-ink-100">{agent.configHash}</code>
            <span className="text-ink-400"> · printed on every exported report, so a report can be matched to this configuration</span>
          </dd>
        </dl>
      </Panel>

      <Panel
        title="Rule thresholds in force"
        actions={<span className="text-[10px] text-ink-400">source: {agent.rulesPath}</span>}
      >
        <table className="w-full text-[12px]">
          <thead className="text-[10px] uppercase tracking-wider text-ink-400">
            <tr>
              <th className="py-1 text-left font-medium">Threshold</th>
              <th className="py-1 text-left font-medium">Setting</th>
              <th className="py-1 text-right font-medium">Value</th>
            </tr>
          </thead>
          <tbody>
            {thresholds.map(([key, raw]) => (
              <tr key={key} className="border-t border-ink-850">
                <td className="py-1 pr-3 text-ink-300">{label(key)}</td>
                <td className="py-1 pr-3">
                  <code className="text-[11px] text-ink-400">{key}</code>
                </td>
                <td className="py-1 text-right tabular-nums text-ink-100">{value(key, raw)}</td>
              </tr>
            ))}
          </tbody>
        </table>
        <p className="mt-2 text-[11px] leading-relaxed text-ink-400">
          Read at startup and fixed for the life of this process: the agent is not a service and does not reload
          its configuration mid-session. To change a number, edit the rules file and restart with{' '}
          <code>--rules &lt;path&gt;</code> — a session recorded under different thresholds is not comparable to
          one recorded under these.
        </p>
      </Panel>

      <Panel title="What this tool can and cannot see">
        <table className="w-full text-[12px]">
          <thead className="text-[10px] uppercase tracking-wider text-ink-400">
            <tr>
              <th className="py-1 text-left font-medium">Observation</th>
              <th className="py-1 text-left font-medium">Level</th>
              <th className="py-1 text-left font-medium">Why</th>
            </tr>
          </thead>
          <tbody>
            {(agent.observability ?? []).map((row) => (
              <tr key={row.observation} className="border-t border-ink-850 align-top">
                <td className="py-1 pr-3 text-ink-200">{row.observation}</td>
                <td className="py-1 pr-3">
                  <Badge tone={row.level === 'Direct' ? 'neutral' : row.level === 'Not observable' ? 'bad' : 'warn'}>
                    {row.level}
                  </Badge>
                </td>
                <td className="py-1 text-ink-400">{row.note}</td>
              </tr>
            ))}
          </tbody>
        </table>
        <p className="mt-2 text-[11px] text-ink-400">
          The same table is printed in every exported report, from the same data — a report and a settings screen
          that disagreed about what the sensor sees would be two different products.
        </p>
      </Panel>
    </div>
  );
}
