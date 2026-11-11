import { useId, useState } from 'react';
import { Navigate, useNavigate } from 'react-router-dom';
import { useUser } from '../contexts/useUser';
import { adminApi } from '../api/admin';
import { useSignOut } from '../data/auth/useSignOut';
import { useUnsavedNavigation } from '../data/shared/useUnsavedNavigation';
import { SessionChangeFeedback } from '../components/common/SessionChangeFeedback';
import { ContentState } from '../components/common/ContentState';
import { AdminWorkspacesPanel } from '../components/admin/AdminWorkspacesPanel';
import { AdminUsersPanel } from '../components/admin/AdminUsersPanel';
import { AdminTemplatesPanel } from '../components/admin/AdminTemplatesPanel';
import { AdminSupportSection } from '../components/support/AdminSupportSection';
import { useSectionStatus } from '../data/settings/useSectionStatus';
import { createAdministratorSessionGateway } from '../data/admin/createAdministratorSessionGateway';
import '../styles/SystemAdmin.css';

const SECTIONS = [
  { id: 'workspaces', label: 'Workspaces' },
  { id: 'users', label: 'Users' },
  { id: 'templates', label: 'System Templates' },
  { id: 'support', label: 'Support' },
] as const;
type AdminSection = typeof SECTIONS[number]['id'];

export default function SystemAdmin() {
  const { user, loading } = useUser();
  if (loading) return <main className="system-admin"><ContentState kind="loading" title="Checking administrator access…" /></main>;
  if (!user?.isSystemAdministrator) return <Navigate to="/" replace />;
  return <AdminDashboard currentUserId={user.userId} />;
}

function AdminDashboard({ currentUserId }: { currentUserId: number }) {
  const { logout, refetch } = useUser();
  const navigate = useNavigate();
  const [active, setActive] = useState<AdminSection>('workspaces');
  const status = useSectionStatus(active);
  useUnsavedNavigation(status.dirty, status.pending);
  const signOut = useSignOut({ logout, refetch }, () => window.location.assign('/'));
  const sessionGateway = createAdministratorSessionGateway(
    adminApi, signOut.changes, () => refetch({ throwOnError: true }),
    () => window.confirm('You have unsaved changes. Discard them?'),
  );
  const panelId = useId();
  const leave = (action: () => void) => {
    if (!status.dirty || window.confirm('Discard unsaved changes?')) action();
  };

  return <div className="system-admin">
    <header className="system-admin__header">
      <div><p className="system-admin__eyebrow">OneBigHead</p><h1>System Administration</h1></div>
      <div className="system-admin__actions">
        <button type="button" className="admin-panel__button" disabled={signOut.busy || status.pending} onClick={() => navigate('/')}>← Back to App</button>
        <button type="button" className="admin-panel__button" disabled={signOut.busy || status.pending} onClick={signOut.signOut}>
          {signOut.signingOut ? 'Signing out…' : 'Sign Out'}</button>
      </div>
    </header>
    <nav className="system-admin__navigation" aria-label="Administration sections">
      {SECTIONS.map(section => <button key={section.id} type="button" className="system-admin__section-button"
        aria-pressed={active === section.id} aria-controls={panelId} disabled={signOut.busy || status.pending} onClick={() => {
          if (active !== section.id) leave(() => setActive(section.id));
        }}>{section.label}</button>)}
    </nav>
    <main id={panelId} className="system-admin__content">
      {signOut.error && <ContentState kind="error" title="Unable to sign out">{signOut.error}</ContentState>}
      {active === 'workspaces' && <AdminWorkspacesPanel gateway={sessionGateway} onStatusChange={status.report} />}
      {active === 'users' && <AdminUsersPanel gateway={sessionGateway} currentUserId={currentUserId} onStatusChange={status.report} />}
      {active === 'templates' && <AdminTemplatesPanel gateway={adminApi} onStatusChange={status.report} />}
      {active === 'support' && <section className="admin-panel" aria-label="Support administration"><h2 className="admin-panel__title">Support Requests</h2><AdminSupportSection onStatusChange={status.report} /></section>}
    </main>
    {!signOut.managed && <SessionChangeFeedback changes={signOut.changes} />}
  </div>;
}
