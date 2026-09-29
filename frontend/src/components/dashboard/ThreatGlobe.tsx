'use client';

import { useEffect, useMemo, useRef, useState } from 'react';
import Link from 'next/link';
import createGlobe from 'cobe';
import { useAlerts } from '@/hooks/useAlerts';
import type { AlertsResponse, AlertRecord, Severity } from '@/types/trinetra';
import { THREAT_META } from '@/lib/threatMeta';
import { formatTimeShort } from '@/lib/formatters';
import styles from './ThreatGlobe.module.css';

const SEV_COLOR: Record<Severity, string> = {
  CRITICAL: '#ee0000',
  HIGH: '#f5a623',
  MEDIUM: '#a1a1a1',
  LOW: '#0c8c4a',
  INFO: '#666666',
};

function ipToLatLng(ip?: string): [number, number] {
  if (!ip) return [20, 78];
  const parts = ip.split('.').map((x) => parseInt(x, 10) || 0);
  const seed = parts.reduce((a, b, i) => a + b * (i + 3) * 17, 0);
  const lat = ((seed % 140) - 70) + (parts[2] % 10) * 0.1;
  const lng = ((Math.floor(seed / 3) % 360) - 180) + (parts[3] % 10) * 0.1;
  return [lat, lng];
}

function severitySize(sev?: string): number {
  switch (sev) {
    case 'CRITICAL':
      return 0.15;
    case 'HIGH':
      return 0.11;
    case 'MEDIUM':
      return 0.08;
    default:
      return 0.055;
  }
}

interface Props {
  initialData?: AlertsResponse;
  height?: number;
}

export function ThreatGlobe({ initialData, height = 560 }: Props) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const { data, isConnected } = useAlerts(initialData);
  const alerts = data?.alerts ?? [];

  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [autoRotate, setAutoRotate] = useState(true);
  const [dragging, setDragging] = useState(false);
  const [hint, setHint] = useState('Drag to orbit · scroll to zoom · click a vector to focus');
  const [zoomLabel, setZoomLabel] = useState('1.05×');

  const selectedIdRef = useRef(selectedId);
  const alertsRef = useRef(alerts);
  selectedIdRef.current = selectedId;
  alertsRef.current = alerts;

  const markers = useMemo(
    () =>
      alerts.slice(0, 40).map((a) => ({
        id: a.alert_id,
        location: ipToLatLng(a.source?.ip) as [number, number],
        size: severitySize(a.severity) * (selectedId === a.alert_id ? 1.6 : 1),
        color:
          selectedId === a.alert_id
            ? ([0.0, 0.44, 0.95] as [number, number, number])
            : a.severity === 'CRITICAL' || a.severity === 'HIGH'
              ? ([0.93, 0.0, 0.0] as [number, number, number])
              : ([0.55, 0.55, 0.55] as [number, number, number]),
      })),
    [alerts, selectedId],
  );

  const arcs = useMemo(
    () =>
      alerts.slice(0, 20).map((a) => ({
        id: a.alert_id,
        from: ipToLatLng(a.source?.ip) as [number, number],
        to: ipToLatLng(a.destination?.ip) as [number, number],
        color:
          selectedId === a.alert_id
            ? ([0.0, 0.44, 0.95] as [number, number, number])
            : ([0.35, 0.45, 0.55] as [number, number, number]),
      })),
    [alerts, selectedId],
  );

  const markersRef = useRef(markers);
  const arcsRef = useRef(arcs);
  const autoRef = useRef(autoRotate);
  markersRef.current = markers;
  arcsRef.current = arcs;
  autoRef.current = autoRotate;

  const phiRef = useRef(0.15);
  const thetaRef = useRef(0.28);
  const scaleRef = useRef(1.05);
  const pointer = useRef({ down: false, x: 0, y: 0, moved: false });

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    let width = canvas.offsetWidth;
    let raf = 0;

    const onResize = () => {
      width = canvas.offsetWidth;
    };
    window.addEventListener('resize', onResize);

    const globe = createGlobe(canvas, {
      devicePixelRatio: 2,
      width: width * 2,
      height: height * 2,
      phi: phiRef.current,
      theta: thetaRef.current,
      dark: 1,
      diffuse: 1.15,
      mapSamples: 18000,
      mapBrightness: 4.6,
      baseColor: [0.04, 0.04, 0.05],
      markerColor: [0.93, 0.0, 0.0],
      glowColor: [0.12, 0.14, 0.18],
      scale: scaleRef.current,
      markers: markersRef.current,
      arcs: arcsRef.current,
      arcColor: [0.4, 0.5, 0.6],
      arcWidth: 0.45,
      arcHeight: 0.28,
      markerElevation: 0.02,
    });

    const tick = () => {
      if (autoRef.current && !pointer.current.down) {
        phiRef.current += 0.0018;
      }
      globe.update({
        phi: phiRef.current,
        theta: thetaRef.current,
        scale: scaleRef.current,
        width: width * 2,
        height: height * 2,
        markers: markersRef.current,
        arcs: arcsRef.current,
      });
      raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);

    const onPointerDown = (e: PointerEvent) => {
      pointer.current = { down: true, x: e.clientX, y: e.clientY, moved: false };
      canvas.setPointerCapture(e.pointerId);
      setDragging(true);
      setAutoRotate(false);
      setHint('Orbiting…');
    };

    const onPointerMove = (e: PointerEvent) => {
      if (!pointer.current.down) return;
      const dx = e.clientX - pointer.current.x;
      const dy = e.clientY - pointer.current.y;
      if (Math.abs(dx) + Math.abs(dy) > 3) pointer.current.moved = true;
      pointer.current.x = e.clientX;
      pointer.current.y = e.clientY;
      phiRef.current += dx * 0.005;
      thetaRef.current = Math.max(-1.2, Math.min(1.2, thetaRef.current + dy * 0.005));
    };

    const onPointerUp = (e: PointerEvent) => {
      const wasClick = pointer.current.down && !pointer.current.moved;
      pointer.current.down = false;
      setDragging(false);
      try {
        canvas.releasePointerCapture(e.pointerId);
      } catch {
        /* ignore */
      }
      const list = alertsRef.current;
      if (wasClick && list.length) {
        const idx = list.findIndex((a) => a.alert_id === selectedIdRef.current);
        const next = list[(idx + 1) % Math.min(list.length, 16)];
        setSelectedId(next.alert_id);
        const label =
          (THREAT_META[next.threat_class] ?? THREAT_META.UNKNOWN_ANOMALY).label;
        setHint(`Focused · ${label}`);
      } else {
        setHint('Drag to orbit · scroll to zoom · click to focus next vector');
      }
    };

    const onWheel = (e: WheelEvent) => {
      e.preventDefault();
      const next = scaleRef.current - e.deltaY * 0.0012;
      scaleRef.current = Math.max(0.72, Math.min(1.65, next));
      setAutoRotate(false);
      setZoomLabel(`${scaleRef.current.toFixed(2)}×`);
      setHint(`Zoom ${scaleRef.current.toFixed(2)}×`);
    };

    canvas.addEventListener('pointerdown', onPointerDown);
    canvas.addEventListener('pointermove', onPointerMove);
    canvas.addEventListener('pointerup', onPointerUp);
    canvas.addEventListener('pointercancel', onPointerUp);
    canvas.addEventListener('wheel', onWheel, { passive: false });

    return () => {
      cancelAnimationFrame(raf);
      globe.destroy();
      window.removeEventListener('resize', onResize);
      canvas.removeEventListener('pointerdown', onPointerDown);
      canvas.removeEventListener('pointermove', onPointerMove);
      canvas.removeEventListener('pointerup', onPointerUp);
      canvas.removeEventListener('pointercancel', onPointerUp);
      canvas.removeEventListener('wheel', onWheel);
    };
  }, [height]);

  const selected: AlertRecord | undefined = alerts.find((a) => a.alert_id === selectedId);
  const queue = useMemo(
    () =>
      [...alerts]
        .sort((a, b) => {
          const rank = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 } as const;
          const ra = rank[a.severity] ?? 5;
          const rb = rank[b.severity] ?? 5;
          if (ra !== rb) return ra - rb;
          return String(b.timestamp).localeCompare(String(a.timestamp));
        })
        .slice(0, 10),
    [alerts],
  );

  const criticalHigh = alerts.filter(
    (a) => a.severity === 'CRITICAL' || a.severity === 'HIGH',
  ).length;
  const uniqueSrc = new Set(alerts.map((a) => a.source?.ip).filter(Boolean)).size;
  const plotted = Math.min(alerts.length, 40);

  function focusAlert(a: AlertRecord) {
    setSelectedId(a.alert_id);
    setAutoRotate(false);
    const label = (THREAT_META[a.threat_class] ?? THREAT_META.UNKNOWN_ANOMALY).label;
    setHint(`Focused · ${label}`);
  }

  return (
    <div className={styles.page}>
      <section className={styles.kpiRow} aria-label="Globe metrics">
        <div className={styles.kpi}>
          <div className={styles.kpiLabel}>Vectors plotted</div>
          <div className={styles.kpiValue}>{plotted}</div>
          <div className={styles.kpiHint}>of {alerts.length} sealed</div>
        </div>
        <div className={styles.kpi} data-tone={criticalHigh > 0 ? 'alert' : ''}>
          <div className={styles.kpiLabel}>Critical / high</div>
          <div className={styles.kpiValue}>{criticalHigh}</div>
          <div className={styles.kpiHint}>Elevated markers</div>
        </div>
        <div className={styles.kpi}>
          <div className={styles.kpiLabel}>Unique sources</div>
          <div className={styles.kpiValue}>{uniqueSrc}</div>
          <div className={styles.kpiHint}>Projected origins</div>
        </div>
        <div className={styles.kpi} data-tone={isConnected ? 'ok' : 'warn'}>
          <div className={styles.kpiLabel}>Projection</div>
          <div className={styles.kpiValue}>{autoRotate ? 'Spin' : 'Hold'}</div>
          <div className={styles.kpiHint}>Zoom {zoomLabel}</div>
        </div>
      </section>

      <section className={styles.mainGrid}>
        <div className={styles.canvasPanel}>
          <div className={styles.canvasHead}>
            <div>
              <h2 className={styles.panelTitle}>Threat surface</h2>
              <p className={styles.panelSub}>{hint}</p>
            </div>
            <div className={styles.toolbar}>
              <button
                type="button"
                className={styles.toolBtn}
                onClick={() => setAutoRotate((v) => !v)}
              >
                {autoRotate ? 'Pause' : 'Spin'}
              </button>
              <button
                type="button"
                className={styles.toolBtn}
                onClick={() => {
                  scaleRef.current = 1.05;
                  thetaRef.current = 0.28;
                  phiRef.current = 0.15;
                  setZoomLabel('1.05×');
                  setHint('View reset');
                }}
              >
                Reset
              </button>
            </div>
          </div>

          <div className={styles.canvasBox} style={{ height }}>
            <canvas
              ref={canvasRef}
              className={styles.canvas}
              style={{ width: '100%', height, cursor: dragging ? 'grabbing' : 'grab' }}
              aria-label="Interactive global threat globe"
            />
            <div className={styles.legend}>
              <span><i style={{ background: '#ee0000' }} /> Crit / High</span>
              <span><i style={{ background: '#8c8c8c' }} /> Other</span>
              <span><i style={{ background: '#0070f3' }} /> Focused</span>
            </div>
          </div>
        </div>

        <aside className={styles.side}>
          <div className={styles.panel}>
            <div className={styles.panelHead}>
              <h2 className={styles.panelTitle}>Focus</h2>
            </div>
            {!selected ? (
              <div className={styles.empty}>Select a vector from the list or click the globe.</div>
            ) : (
              <div className={styles.focusBody}>
                <span
                  className={styles.sev}
                  style={{ color: SEV_COLOR[selected.severity] }}
                >
                  {selected.severity}
                </span>
                <div className={styles.focusTitle}>
                  {(THREAT_META[selected.threat_class] ?? THREAT_META.UNKNOWN_ANOMALY).label}
                </div>
                <div className={styles.mono}>
                  {selected.source?.ip ?? '—'} → {selected.destination?.ip ?? '—'}
                </div>
                <div className={styles.focusMeta}>
                  <div>
                    <span className={styles.k}>Conf</span>
                    <span className={styles.mono}>{Math.round(selected.confidence * 100)}%</span>
                  </div>
                  <div>
                    <span className={styles.k}>Time</span>
                    <span className={styles.mono}>{formatTimeShort(selected.timestamp)}</span>
                  </div>
                </div>
                <Link className={styles.focusLink} href={`/forensics/${selected.alert_id}`}>
                  Open forensics
                </Link>
              </div>
            )}
          </div>

          <div className={`${styles.panel} ${styles.listPanel}`}>
            <div className={styles.panelHead}>
              <div>
                <h2 className={styles.panelTitle}>Active vectors</h2>
                <p className={styles.panelSub}>Severity-sorted · top {queue.length}</p>
              </div>
              <Link href="/alerts" className={styles.panelLink}>
                Alerts
              </Link>
            </div>

            {queue.length === 0 ? (
              <div className={styles.empty}>No detections yet.</div>
            ) : (
              <ul className={styles.vecList}>
                {queue.map((a) => {
                  const active = selectedId === a.alert_id;
                  const meta = THREAT_META[a.threat_class] ?? THREAT_META.UNKNOWN_ANOMALY;
                  return (
                    <li key={a.alert_id}>
                      <button
                        type="button"
                        className={`${styles.vecRow} ${active ? styles.vecActive : ''}`}
                        onClick={() => focusAlert(a)}
                      >
                        <span
                          className={styles.sev}
                          style={{ color: SEV_COLOR[a.severity] }}
                        >
                          {a.severity}
                        </span>
                        <span className={styles.vecClass}>{meta.label}</span>
                        <span className={styles.mono}>
                          {a.source?.ip ?? '—'} → {a.destination?.ip ?? '—'}
                        </span>
                        <span className={styles.mono}>{Math.round(a.confidence * 100)}%</span>
                      </button>
                    </li>
                  );
                })}
              </ul>
            )}
          </div>
        </aside>
      </section>
    </div>
  );
}
