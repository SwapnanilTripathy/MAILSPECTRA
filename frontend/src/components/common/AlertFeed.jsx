import React, { useEffect, useState } from 'react';
import api from '../../api/client';
import { useMasked } from '../../context/PrivacyContext';
import { useAuth } from '../../context/AuthContext';
export default function AlertFeed() {
  const [rawAlerts, setAlerts] = useState(null);
  const [error, setError] = useState('');
  const [pending, setPending] = useState(null);
  const { user } = useAuth();
  const alerts = useMasked(rawAlerts);
  useEffect(() => { api.getAlerts().then(setAlerts).catch(e => setError(e.message)); }, []);
  const update = async (id,status) => {
    setPending(id);setError('');
    try { const alert = await api.updateAlert(id,status); setAlerts(rows => rows.map(row => row.alert_id === id ? alert : row)); }
    catch(e) { setError(e.message); }
    finally { setPending(null); }
  };
  return <section className="rounded-xl border border-slate-700 p-5 space-y-3">
    <h2 className="text-lg text-white">Investigation alerts</h2>
    {error && <p role="alert" className="text-red-300">{error}</p>}
    {!alerts && !error && <p role="status">Loading alerts…</p>}
    {alerts?.length === 0 && <p>No alerts yet. Analyze an email to begin.</p>}
    {alerts?.map(alert => <article key={alert.alert_id} className="border-t border-slate-700 py-3 space-y-2">
      <p className="text-sm text-slate-200">{alert.title} — {alert.status}</p>
      <p className="text-xs text-slate-400">{alert.case_id} • {alert.created_at}</p>
      {user?.role !== 'viewer' && <div className="flex gap-3">
        {alert.status === 'OPEN' && <button disabled={pending === alert.alert_id} className="px-3 py-2 text-cyan-300 border border-slate-600 rounded" onClick={() => update(alert.alert_id,'ACKNOWLEDGED')}>Acknowledge</button>}
        {alert.status !== 'RESOLVED' && <button disabled={pending === alert.alert_id} className="px-3 py-2 text-cyan-300 border border-slate-600 rounded" onClick={() => update(alert.alert_id,'RESOLVED')}>Resolve</button>}
      </div>}
    </article>)}
  </section>;
}
