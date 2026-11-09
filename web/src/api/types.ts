// The payload contract, copied from src/Argus.Agent/AgentJson.cs. These types are the front end's
// only description of what the agent sends, so a field that disappears there is a compile error here
// rather than an undefined at runtime.

export type Verdict = 'Benign' | 'Suspicious' | 'Malicious' | 'Unknown';

export interface Coverage {
  complete: boolean;
  gaps: number;
  reasons: string[];
  statement: string;
}

export interface SessionState {
  id: string;
  targetPath: string;
  rootPid: number;
  status: string;
  startedUtc: string;
  endedUtc: string | null;
  verdict: Verdict | null;
  score: number;
  peakScore: number;
  databasePath: string | null;
  recordPath: string | null;
  coverage: Coverage;
}

export interface Detection {
  key: string;
  ruleId: string;
  title: string;
  severity: number;
  confidence: number;
  categories: string;
  scopePid: number;
  firstSeenUtc: string;
  lastSeenUtc: string;
  eventCount: number;
  status: string;
  reason: string;
  counterfactual: string;
  factors: string[];
  mitre: string[];
  evidenceSeq: number[];
}

/** A detection row as stored and listed: the agent serves `detectionKey` here and the raw
 *  `factorsJson` from the database, not the expanded `Detection` shape. */
export interface StoredDetection {
  id: number;
  detectionKey: string;
  ruleId: string;
  title: string;
  severity: number;
  confidence: number;
  categories: string;
  scopePid: number;
  firstSeenUtc: string;
  lastSeenUtc: string;
  eventCount: number;
  status: string;
  reason: string;
  counterfactual: string;
  factorsJson: string;
  mitre: string;
  weight: number;
}

export interface MonitorEvent {
  seq: number;
  timestampUtc: string;
  kind: string;
  category: string;
  pid: number;
  parentPid: number | null;
  imageName: string | null;
  imagePath: string | null;
  target: string | null;
  remoteIp: string | null;
  remotePort: number | null;
  protocol: string | null;
  hostName: string | null;
  scope: string;
  scopeReason: string | null;
  observability: string;
  confidence: number;
  source: string;
}

export interface Process {
  pid: number;
  parentPid: number | null;
  imageName: string | null;
  imagePath: string | null;
  commandLine: string | null;
  startedUtc: string;
  scope: string;
  scopeReason: string | null;
}

export interface MonitorCounters {
  eventsSeen: number;
  eventsForwarded: number;
  outsideScope: number;
  sampledReads: number;
  throttledEvents: number;
  channelDropped: number;
  mappingFailures: number;
  processStarts: number;
  fileEvents: number;
  networkEvents: number;
  dnsEvents: number;
  registryEvents: number;
  throttled: boolean;
}

export interface Health {
  status: string;
  version: string;
  elevated: boolean;
  agentPid: number;
  os: string;
  etwStarted: boolean;
  dnsProviderEnabled: boolean;
  registryProviderEnabled: boolean;
  tcpTableAvailable: boolean;
  etwLostEvents: number;
  etwError: string | null;
  dnsError: string | null;
  registryProviderError: string | null;
  monitor: MonitorCounters | null;
  session: SessionState | null;
}

export interface TimelineResponse {
  events: MonitorEvent[];
  detections: Array<{
    ruleId: string;
    title: string;
    severity: number;
    firstSeenUtc: string;
    lastSeenUtc: string;
    eventCount: number;
    reason: string;
  }>;
}

export interface ScorePoint {
  ts: string;
  score: number;
  peak: number;
  band: string;
}

/** The detection a chain belongs to: the list row, or a bare stub when a fixture has no detection. */
export type DetectionRef = Pick<StoredDetection, 'detectionKey' | 'ruleId' | 'title'> | { ruleId: string; title: string };

export interface EvidenceResponse {
  detection: DetectionRef;
  evidenceSeq: number[];
  events: MonitorEvent[];
}
