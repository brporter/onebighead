import type { ReactNode } from 'react';
import { ContentState } from '../common/ContentState';
import '../../styles/components/AdminPanel.css';

interface AdminResourceProps {
  loading: boolean;
  error: string | null;
  retry: () => void;
  empty: boolean;
  subject: string;
  actionError: string | null;
  children: ReactNode;
}

/** Shared feedback leaves each panel in charge of its data and available actions. */
export function AdminResource({ loading, error, retry, empty, subject, actionError, children }: AdminResourceProps) {
  return <>
    {actionError && <ContentState kind="error" title="Action needs review" action={
      <button type="button" disabled={loading} onClick={retry}>Reload {subject}</button>
    }>{actionError}</ContentState>}
    {loading ? <ContentState kind="loading" title={`Loading ${subject}…`} /> : error ?
      <ContentState kind="error" title={`Unable to load ${subject}`} action={<button type="button" onClick={retry}>Retry</button>}>{error}</ContentState> :
      empty ? <ContentState kind="empty" title={`No ${subject} found`} /> : children}
  </>;
}
