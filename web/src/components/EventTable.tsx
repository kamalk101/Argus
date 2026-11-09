import { useRef } from 'react';
import { useVirtualizer } from '@tanstack/react-virtual';
import type { MonitorEvent } from '../api/types';
import { clock, elide } from '../lib/format';
import { ObservabilityBadge } from './ui';

export type EventColumn = 'time' | 'category' | 'process' | 'target' | 'detail' | 'observability';

const COLUMN_CLASS: Record<EventColumn, string> = {
  time: 'w-20 shrink-0',
  category: 'w-24 shrink-0',
  process: 'w-40 shrink-0 truncate',
  target: 'flex-1 min-w-0 truncate',
  detail: 'w-52 shrink-0 truncate',
  observability: 'w-20 shrink-0 text-right',
};

/**
 * Virtualised event list. A hundred thousand rows must scroll at 60 fps, so only the visible window
 * is rendered; the row height is fixed so the scrollbar is honest without measuring every row.
 */
export function EventTable({
  events,
  columns,
  onSelect,
  selectedSeq,
  emptyNote,
  height = 460,
}: {
  events: MonitorEvent[];
  columns: EventColumn[];
  onSelect?: (event: MonitorEvent) => void;
  selectedSeq?: number | null;
  emptyNote?: string;
  height?: number;
}) {
  const parentRef = useRef<HTMLDivElement>(null);
  const virtualizer = useVirtualizer({
    count: events.length,
    getScrollElement: () => parentRef.current,
    estimateSize: () => 24,
    overscan: 12,
  });

  if (events.length === 0) {
    return <div className="px-3 py-6 text-[12px] text-ink-400">{emptyNote ?? 'No events match this filter.'}</div>;
  }

  return (
    <div>
      <div className="flex gap-2 border-b border-ink-800 px-3 py-1 text-[10px] uppercase tracking-wider text-ink-400">
        {columns.map((column) => (
          <span key={column} className={COLUMN_CLASS[column]}>
            {column === 'process' ? 'process' : column}
          </span>
        ))}
      </div>
      <div ref={parentRef} className="overflow-auto" style={{ height }} tabIndex={0} aria-label="event list">
        <div style={{ height: virtualizer.getTotalSize(), position: 'relative' }}>
          {virtualizer.getVirtualItems().map((row) => {
            const event = events[row.index];
            const selected = selectedSeq === event.seq;
            return (
              <div
                key={event.seq}
                data-index={row.index}
                role="row"
                tabIndex={0}
                onClick={() => onSelect?.(event)}
                onKeyDown={(keyboard) => {
                  if (keyboard.key === 'Enter') onSelect?.(event);
                }}
                className={`row-dense absolute left-0 top-0 flex w-full items-center gap-2 px-3 ${selected ? 'bg-ink-800' : 'hover:bg-ink-850'} ${onSelect ? 'cursor-pointer' : ''}`}
                style={{ height: row.size, transform: `translateY(${row.start}px)` }}
              >
                {columns.map((column) => (
                  <span key={column} className={`text-[12px] ${COLUMN_CLASS[column]}`}>
                    {renderCell(event, column)}
                  </span>
                ))}
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}

function renderCell(event: MonitorEvent, column: EventColumn) {
  switch (column) {
    case 'time':
      return <span className="text-ink-300">{clock(event.timestampUtc)}</span>;
    case 'category':
      return <span className="text-ink-300">{event.category.toLowerCase()}</span>;
    case 'process':
      return (
        <span title={event.imagePath ?? undefined}>
          {event.imageName ?? '—'} <span className="text-ink-400">{event.pid}</span>
        </span>
      );
    case 'target':
      return <span title={event.target ?? event.imagePath ?? undefined}>{elide(event.target ?? event.imagePath, 40)}</span>;
    case 'detail':
      return <span className="text-ink-300" title={event.scopeReason ?? undefined}>{detailOf(event)}</span>;
    case 'observability':
      return <ObservabilityBadge observability={event.observability} />;
  }
}

function detailOf(event: MonitorEvent): string {
  const parts: string[] = [];
  if (event.kind) parts.push(event.kind.toLowerCase());
  if (event.remoteIp) parts.push(`${event.remoteIp}${event.remotePort ? `:${event.remotePort}` : ''}`);
  if (event.hostName) parts.push(event.hostName);
  if (event.scope !== 'InScope') parts.push(event.scope.toLowerCase());
  return parts.join(' · ');
}
