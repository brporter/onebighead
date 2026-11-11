import { useCallback, useEffect, useState } from 'react';
import { useLocation, useNavigate, useParams } from 'react-router-dom';
import { invitationsApi } from '../api/invitations';
import { useUser } from '../contexts/useUser';
import { useRemoteResource } from '../data/shared/useRemoteResource';
import { useSessionChanges } from '../data/auth/useSessionChanges';
import { readInvitationLink } from '../data/invitations/invitationLink';
import type { InvitationAccess } from '../data/invitations/types';
import { WorkspaceRole } from '../utils/types';
import RequireAuth from '../components/common/RequireAuth';
import { ContentState } from '../components/common/ContentState';
import { SiteHeader } from '../components/common/SiteHeader';
import { SessionChangeFeedback } from '../components/common/SessionChangeFeedback';
import '../styles/components/InvitationView.css';

export default function InvitationView() {
  const { invitationId = '' } = useParams();
  const location = useLocation();
  return <div className="invitation-view">
    <SiteHeader title="Workspace invitation" showWorkspaceSwitcher={false} />
    <main className="invitation-view__main">
      <InvitationEntry key={`${invitationId}:${location.hash}`} invitationId={invitationId} fragment={location.hash} pathname={location.pathname} />
    </main>
  </div>;
}

function InvitationEntry({ invitationId, fragment, pathname }: { invitationId: string; fragment: string; pathname: string }) {
  const navigate = useNavigate();
  const read = useCallback(async () => readInvitationLink(invitationId, fragment, sessionStorage), [invitationId, fragment]);
  const capture = useRemoteResource(read, 'Your browser could not save this invitation.');
  useEffect(() => {
    if (capture.data && fragment) void navigate(pathname, { replace: true });
  }, [capture.data, fragment, pathname, navigate]);
  if (capture.error) return <ContentState kind="error" title="Unable to save this invitation">
    Sign in first, then open the invitation link again with tab storage enabled.
  </ContentState>;
  // Finish storing and removing the fragment before the sign-in gate can redirect.
  if (capture.loading || (capture.data && fragment)) return <ContentState kind="loading" title="Opening invitation…" />;
  if (capture.data === null) return <ContentState kind="error" title="This invitation link is incomplete">Ask an administrator for a new private link.</ContentState>;
  return <RequireAuth skipWelcomeCheck skipTermsCheck><AcceptInvitation access={capture.data} /></RequireAuth>;
}

function AcceptInvitation({ access }: { access: InvitationAccess }) {
  const { user, refetch } = useUser();
  const navigate = useNavigate();
  const { changes, state, managed } = useSessionChanges();
  const [source] = useState(() => Symbol('invitation'));
  const [confirmed, setConfirmed] = useState(false);
  const { invitationId, token } = access;
  const read = useCallback((options: { signal: AbortSignal }) => invitationsApi.preview({ invitationId, token }, options), [invitationId, token]);
  const preview = useRemoteResource(read, 'Unable to load this invitation');
  const pending = state.pending || state.recovery || state.leaving;
  useEffect(() => {
    if (confirmed && !pending && !state.error) void navigate('/collections', { replace: true });
  }, [confirmed, pending, state.error, navigate]);
  const join = async () => {
    await changes.run('workspace', async () => { await invitationsApi.accept(access); setConfirmed(true); },
      () => refetch({ throwOnError: true }), () => window.confirm('Discard unsaved changes and join this workspace?'), source);
  };
  return <>
    {preview.data === null ? <ContentState kind={preview.loading ? 'loading' : 'error'} title={preview.loading ? 'Loading invitation…' : 'Invitation unavailable'}
      action={preview.loading ? undefined : <button type="button" onClick={() => void preview.reload()}>Try again</button>}>{preview.error}</ContentState> :
      <section className="invitation-view__card">
        <h2>Join {preview.data.workspaceName}</h2>
        <p>This private invitation was created for {preview.data.email}.</p>
        <p>You will join as <strong>{preview.data.role === WorkspaceRole.WorkspaceAdmin ? 'an admin' : 'a member'}</strong> using <strong>{user!.email}</strong>.</p>
        <p>Only continue if this invitation was shared with you. Existing members keep their current role.</p>
        <button type="button" className="invitation-view__join" disabled={pending || confirmed} onClick={() => void join()}>Join workspace</button>
        <a href="/collections">Return to my collections</a>
      </section>}
    {state.source === source && state.error && !state.recovery && <p role="alert">{state.error}</p>}
    {!managed && <SessionChangeFeedback changes={changes} />}
  </>;
}
