// The dashboard's only door to data.
//
// Two modes, one code path for the screens:
//
//   live    — the local agent over loopback (`/api/...` through the Vite proxy, or same-origin in the
//             packaged shell). Requires the bearer token the agent printed at startup.
//   fixture — a captured payload set under /fixtures/<name>/, recorded from a real session by
//             `scripts/dashboard-fixtures.ps1`. Screen tests run here: they see the exact JSON the
//             agent serves, so a DTO change cannot pass the test while breaking the UI.
//
// The mode is chosen by `?fixtures=benign|flagged` (tests, screenshots, offline development) or by
// the absence of a token (nothing else can work without one).

import type {
  AgentSettings,
  EvidenceResponse,
  Health,
  MonitorEvent,
  Process,
  ScorePoint,
  SessionState,
  StoredDetection,
  TimelineResponse,
} from './types';

const params = new URLSearchParams(window.location.search);
const fixtureSet = params.get('fixtures');
const base = params.get('api') ?? '';

export const mode: 'fixture' | 'live' = fixtureSet ? 'fixture' : 'live';

const TOKEN_KEY = 'argus.token';

export function token(): string | null {
  const fromUrl = params.get('token');
  if (fromUrl) {
    localStorage.setItem(TOKEN_KEY, fromUrl);
    return fromUrl;
  }
  return localStorage.getItem(TOKEN_KEY);
}

/** A live fetch with the bearer token; the agent rejects everything else on /api. */
async function live<T>(path: string, init: RequestInit = {}): Promise<T> {
  const bearer = token();
  const response = await fetch(base + path, {
    ...init,
    headers: {
      ...(init.headers ?? {}),
      ...(bearer ? { Authorization: `Bearer ${bearer}` } : {}),
    },
  });

  if (response.status === 401) {
    throw new Error('The agent rejected this session: no valid bearer token. Relaunch Argus from the dashboard.');
  }
  if (!response.ok) {
    throw new Error(`${path} answered ${response.status} ${response.statusText}`);
  }
  return (await response.json()) as T;
}

async function fixture<T>(name: string): Promise<T> {
  const response = await fetch(`/fixtures/${fixtureSet}/${name}`);
  if (!response.ok) {
    throw new Error(`fixture ${fixtureSet}/${name} is missing (${response.status})`);
  }
  return (await response.json()) as T;
}

export interface EventQuery {
  category?: string;
  kind?: string;
  pid?: number;
  text?: string;
  after?: number;
  limit?: number;
  inScopeOnly?: boolean;
}

export async function listSessions(): Promise<SessionState[]> {
  if (mode === 'fixture') {
    return toArray(await fixture<SessionState[] | SessionState>('sessions.json'));
  }
  return live<SessionState[]>('/api/sessions');
}

export async function getSession(id: string): Promise<SessionState> {
  if (mode === 'fixture') {
    // `/api/sessions/{id}` answers `{record, state}` — the stored row plus the live state — while the
    // list endpoint answers bare states. The fixture keeps the agent's shape, so unwrap it here.
    const wrapped = await fixture<SessionState | { state: SessionState }>('session.json');
    return 'state' in wrapped ? wrapped.state : wrapped;
  }
  // Both branches unwrap: `/api/sessions/{id}` answers `{record, state}`, and a screen that asked for
  // one session should not have to know that.
  const wrapped = await live<SessionState | { state: SessionState }>(`/api/sessions/${id}`);
  return 'state' in wrapped ? wrapped.state : wrapped;
}

export async function getHealth(): Promise<Health> {
  if (mode === 'fixture') {
    return fixture<Health>('health.json');
  }
  return live<Health>('/api/health');
}

export async function listProcesses(id: string): Promise<Process[]> {
  if (mode === 'fixture') {
    return toArray(await fixture<Process[] | Process>('processes.json'));
  }
  return live<Process[]>(`/api/sessions/${id}/processes`);
}

export async function listDetections(id: string): Promise<StoredDetection[]> {
  if (mode === 'fixture') {
    return toArray(await fixture<StoredDetection[] | StoredDetection>('detections.json'));
  }
  return live<StoredDetection[]>(`/api/sessions/${id}/detections`);
}

export async function listEvents(id: string, query: EventQuery = {}): Promise<MonitorEvent[]> {
  if (mode === 'fixture') {
    const all = toArray(await fixture<MonitorEvent[] | MonitorEvent>('events.json'));
    return filterEvents(all, query);
  }

  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(query)) {
    if (value !== undefined && value !== null && value !== '') {
      search.set(key, String(value));
    }
  }
  const suffix = search.size > 0 ? `?${search}` : '';
  return live<MonitorEvent[]>(`/api/sessions/${id}/events${suffix}`);
}

export async function getTimeline(id: string): Promise<TimelineResponse> {
  if (mode === 'fixture') {
    return fixture<TimelineResponse>('timeline.json');
  }
  return live<TimelineResponse>(`/api/sessions/${id}/timeline?limit=2000`);
}

export async function listScores(id: string): Promise<ScorePoint[]> {
  if (mode === 'fixture') {
    return toArray(await fixture<ScorePoint[] | ScorePoint>('scores.json'));
  }
  return live<ScorePoint[]>(`/api/sessions/${id}/scores`);
}

export async function getEvidence(id: string, key: string): Promise<EvidenceResponse> {
  if (mode === 'fixture') {
    // Captured from the same endpoint on a real session when the fixture was taken.
    try {
      return await fixture<EvidenceResponse>('evidence.json');
    } catch {
      // A benign fixture has no detection to expand; answer with an empty chain rather than a lie.
      const detections = await listDetections(id);
      const detection = detections.find((candidate) => candidate.detectionKey === key);
      const events = toArray(await fixture<MonitorEvent[] | MonitorEvent>('events.json'));
      return { detection: detection ?? { ruleId: '', title: '' }, evidenceSeq: [], events };
    }
  }
  return live<EvidenceResponse>(`/api/sessions/${id}/detections/${encodeURIComponent(key)}`);
}

/** What the running agent is configured with. Read-only: the agent's options are fixed at launch. */
export async function getSettings(): Promise<AgentSettings> {
  if (mode === 'fixture') {
    return fixture<AgentSettings>('settings.json');
  }
  return live<AgentSettings>('/api/settings');
}

/**
 * Download a session report.
 *
 * The bearer token cannot travel in a link — `GET /api/...` rejects an unauthenticated request, and
 * `?token=` in a URL is the pattern the stream tickets exist to avoid. So the document is fetched
 * with the header, turned into a blob, and saved by the browser. Nothing about the token reaches the
 * URL bar, the history, or a proxy log.
 */
export async function exportReport(id: string, format: 'html' | 'json'): Promise<void> {
  if (mode === 'fixture') {
    // The fixture set carries a report captured from a real session, so the download path is still
    // exercised — but it is that session's report, not one this browser could ask an agent for.
    const response = await fetch(`/fixtures/${fixtureSet}/report.${format}`);
    if (!response.ok) {
      throw new Error(`fixture ${fixtureSet}/report.${format} is missing (${response.status})`);
    }
    saveBlob(await response.blob(), `argus-fixture-report.${format}`);
    return;
  }

  const bearer = token();
  const response = await fetch(base + `/api/sessions/${id}/report.${format}`, {
    headers: bearer ? { Authorization: `Bearer ${bearer}` } : {},
  });
  if (response.status === 401) {
    throw new Error('The agent rejected this session: no valid bearer token.');
  }
  if (!response.ok) {
    throw new Error(`report.${format} answered ${response.status} ${response.statusText}`);
  }
  saveBlob(await response.blob(), `argus-report-${format === 'json' ? 'session' : 'report'}-${stamp()}.${format}`);
}

function stamp(): string {
  const now = new Date();
  const pad = (value: number) => String(value).padStart(2, '0');
  return `${now.getFullYear()}${pad(now.getMonth() + 1)}${pad(now.getDate())}-${pad(now.getHours())}${pad(now.getMinutes())}`;
}

function saveBlob(blob: Blob, filename: string): void {
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  // Freed on the next tick: revoking synchronously can cancel the download in some browsers.
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

/** What a launch would run: the preview the operator sees before anything starts. */
export interface TargetPreview {
  exists: boolean;
  path: string;
  name?: string;
  directory?: string;
  size?: number;
  sha256?: string | null;
  signature?: string;
  executable?: boolean;
}

export async function inspectTarget(path: string): Promise<TargetPreview> {
  if (mode === 'fixture') {
    // No agent to ask; answer honestly rather than inventing a signature.
    return { exists: false, path };
  }
  return live<TargetPreview>(`/api/inspect?path=${encodeURIComponent(path)}`);
}

export interface StartSessionRequest {
  path: string;
  args?: string;
  mode?: 'launch';
}

export async function startSession(request: StartSessionRequest): Promise<SessionState> {
  if (mode === 'fixture') {
    throw new Error('Fixture mode has no agent to launch a target with.');
  }
  return live<SessionState>('/api/sessions', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(request),
  });
}

export async function stopSession(id: string): Promise<void> {
  if (mode === 'fixture') {
    throw new Error('Fixture mode has no agent to stop.');
  }
  await live(`/api/sessions/${id}/stop`, { method: 'POST' });
}

/**
 * The event stream URL, or null when there is nothing to stream (fixture mode, or a session that has
 * already stopped). `EventSource` cannot send headers, so a single-use ticket is fetched first: the
 * bearer token itself must never appear in a URL.
 */
export async function streamUrl(id: string): Promise<string | null> {
  if (mode === 'fixture') {
    return null;
  }

  const ticket = await live<{ ticket: string }>(`/api/sessions/${id}/stream-ticket`, { method: 'POST' });
  return `${base}/api/sessions/${id}/stream?ticket=${ticket.ticket}`;
}

function filterEvents(events: MonitorEvent[], query: EventQuery): MonitorEvent[] {
  let result = events;
  if (query.category) {
    const wanted = query.category.toLowerCase();
    result = result.filter((event) => event.category.toLowerCase() === wanted);
  }
  if (query.kind) {
    const wanted = query.kind.toLowerCase();
    result = result.filter((event) => event.kind.toLowerCase() === wanted);
  }
  if (query.pid !== undefined) {
    result = result.filter((event) => event.pid === query.pid);
  }
  if (query.text) {
    const wanted = query.text.toLowerCase();
    result = result.filter((event) =>
      [event.target, event.imagePath, event.hostName, event.remoteIp, event.imageName]
        .filter(Boolean)
        .some((value) => value!.toLowerCase().includes(wanted)),
    );
  }
  if (query.after !== undefined) {
    result = result.filter((event) => event.seq > query.after!);
  }
  if (query.inScopeOnly) {
    result = result.filter((event) => event.scope !== 'OutOfScope');
  }
  const limit = query.limit ?? 500;
  return result.slice(-limit);
}

/** Windows PowerShell's ConvertTo-Json collapses one-element arrays; the fixtures keep the brackets,
 *  but a hand-edited one may not, so a bare object is accepted as a one-item list. */
function toArray<T>(value: T[] | T): T[] {
  return Array.isArray(value) ? value : [value];
}
