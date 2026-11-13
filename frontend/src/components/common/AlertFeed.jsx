import React, { useEffect, useState } from 'react';
import { AlertTriangle, CheckCircle2, Clock3 } from 'lucide-react';
import api from '../../api/client';
import { useMasked } from '../../context/PrivacyContext';
import { useAuth } from '../../context/AuthContext';

export default function AlertFeed() {
  const [rawAlerts, setAlerts] = useState(null);
  const [error, setError] = useState('');
  const [pending, setPending] = useState(null);
  const { user } = useAuth();
  const alerts = useMasked(rawAlerts);

  useEffect(() => {
    let active = true;
    api.getAlerts()
      .then((rows) => { if (active) setAlerts(rows); })
      .catch((err) => { if (active) setError(err.message); });
    return () => { active = false; };
  }, []);

  const update = async (id, status) => {
    setPending(id);
    setError('');
    try {
      const alert = await api.updateAlert(id, status);
      setAlerts((rows) => rows.map((row) => row.alert_id === id ? alert : row));
    } catch (err) {
      setError(err.message);
    } finally {
      setPending(null);
    }
  };

  return (
    <section className="soc-alert-feed rounded-xl border p-5 space-y-3" aria-labelledby="alerts-heading">
      <div className="soc-alert-feed-heading">
        <AlertTriangle size={16} aria-hidden="true" />
        <h2 id="alerts-heading">Investigation alerts</h2>
        <span>ALERT QUEUE</span>
      </div>

      {error && <p role="alert" className="text-xs text-red-300">{error}</p>}
      {!alerts && !error && (
        <p role="status" className="text-xs text-slate-400 flex items-center gap-2">
          <Clock3 size={13} aria-hidden="true" /> Loading alert queue…
        </p>
      )}
      {alerts?.length === 0 && (
        <p className="text-xs text-slate-400 flex items-center gap-2">
          <CheckCircle2 size={14} className="text-emerald-400" aria-hidden="true" />
          No open alerts. Analyze an email to begin monitoring.
        </p>
      )}

      {alerts?.map((alert) => (
        <article key={alert.alert_id} className="soc-alert-item space-y-2">
          <div className="flex items-start justify-between gap-3">
            <p>{alert.title} <span className="text-slate-400 font-normal">· {alert.status}</span></p>
            <span className="text-[9px] text-slate-500 font-mono shrink-0">{alert.alert_id}</span>
          </div>
          <p>{alert.case_id} · {alert.created_at}</p>
          {user?.role !== 'viewer' && (
            <div className="soc-alert-actions flex flex-wrap gap-2">
              {alert.status === 'OPEN' && (
                <button disabled={pending === alert.alert_id} onClick={() => update(alert.alert_id, 'ACKNOWLEDGED')}>
                  Acknowledge
                </button>
              )}
              {alert.status !== 'RESOLVED' && (
                <button disabled={pending === alert.alert_id} onClick={() => update(alert.alert_id, 'RESOLVED')}>
                  Resolve alert
                </button>
              )}
            </div>
          )}
        </article>
      ))}
    </section>
  );
}
