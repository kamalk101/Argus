import { useMemo } from 'react';
import type { ScorePoint } from '../api/types';
import { clock } from '../lib/format';

/**
 * Risk over time. One sample per second from the score history, with the band thresholds drawn in:
 * the point of the chart is to show when the score crossed a line, not to decorate a header.
 */
export function RiskChart({
  points,
  marks = [],
  height = 120,
  onSelectRange,
}: {
  points: ScorePoint[];
  marks?: Array<{ at: string; label: string }>;
  height?: number;
  onSelectRange?: (from: string, to: string) => void;
}) {
  const width = 720;
  const padding = { left: 28, right: 8, top: 8, bottom: 16 };

  const geometry = useMemo(() => {
    if (points.length === 0) return null;

    const times = points.map((point) => new Date(point.ts).getTime());
    const first = times[0];
    const last = Math.max(times[times.length - 1], first + 1);
    const peak = Math.max(25, ...points.map((point) => Math.max(point.peak, point.score)));
    const x = (time: number) => padding.left + ((time - first) / (last - first)) * (width - padding.left - padding.right);
    const y = (score: number) => padding.top + (1 - score / peak) * (height - padding.top - padding.bottom);

    const line = points.map((point, index) => `${index === 0 ? 'M' : 'L'}${x(times[index]).toFixed(1)},${y(point.score).toFixed(1)}`).join(' ');
    const area = `${line} L${x(last).toFixed(1)},${y(0).toFixed(1)} L${x(first).toFixed(1)},${y(0).toFixed(1)} Z`;

    return { x, y, line, area, first, last, peak, times };
  }, [points, height]);

  if (!geometry) {
    return <div className="px-3 py-6 text-[12px] text-ink-400">No score samples yet.</div>;
  }

  const bands = [
    { from: 20, to: 50, fill: 'rgb(245 165 36 / 0.10)' },
    { from: 50, to: geometry.peak, fill: 'rgb(229 72 77 / 0.10)' },
  ];

  return (
    <svg
      viewBox={`0 0 ${width} ${height}`}
      className="w-full"
      role="img"
      aria-label={`Risk over time, peak ${geometry.peak.toFixed(0)}`}
      onMouseDown={
        onSelectRange
          ? (event) => {
              const rect = (event.currentTarget as SVGSVGElement).getBoundingClientRect();
              const x = ((event.clientX - rect.left) / rect.width) * width;
              const time = geometry.first + ((x - padding.left) / (width - padding.left - padding.right)) * (geometry.last - geometry.first);
              const nearest = points.reduce((best, point) =>
                Math.abs(new Date(point.ts).getTime() - time) < Math.abs(new Date(best.ts).getTime() - time) ? point : best,
              );
              const anchor = (event.currentTarget as SVGSVGElement).dataset.anchor;
              if (anchor) {
                const [from, to] = anchor < nearest.ts ? [anchor, nearest.ts] : [nearest.ts, anchor];
                onSelectRange(from, to);
                delete (event.currentTarget as SVGSVGElement).dataset.anchor;
              } else {
                (event.currentTarget as SVGSVGElement).dataset.anchor = nearest.ts;
              }
            }
          : undefined
      }
    >
      {bands.map((band) => (
        <rect key={band.from} x={padding.left} y={geometry.y(band.to)} width={width - padding.left - padding.right} height={Math.max(0, geometry.y(band.from) - geometry.y(band.to))} fill={band.fill} />
      ))}

      {[0, 20, 50, 100].filter((value) => value <= geometry.peak).map((value) => (
        <g key={value}>
          <line x1={padding.left} x2={width - padding.right} y1={geometry.y(value)} y2={geometry.y(value)} stroke="rgb(58 69 87 / 0.5)" strokeDasharray="2 3" />
          <text x={2} y={geometry.y(value) + 3} fill="#6b7787" fontSize="9">
            {value}
          </text>
        </g>
      ))}

      <path d={geometry.area} fill="rgb(62 196 160 / 0.12)" />
      <path d={geometry.line} fill="none" stroke="#3ec4a0" strokeWidth="1.5" />

      {marks.map((mark) => {
        const x = geometry.x(new Date(mark.at).getTime());
        return (
          <g key={mark.at + mark.label}>
            <line x1={x} x2={x} y1={padding.top} y2={height - padding.bottom} stroke="rgb(245 165 36 / 0.7)" strokeDasharray="3 2" />
            <title>{`${mark.label} at ${clock(mark.at)}`}</title>
          </g>
        );
      })}

      <text x={padding.left} y={height - 4} fill="#6b7787" fontSize="9">
        {clock(points[0].ts)}
      </text>
      <text x={width - padding.right} y={height - 4} fill="#6b7787" fontSize="9" textAnchor="end">
        {clock(points[points.length - 1].ts)}
      </text>
    </svg>
  );
}
