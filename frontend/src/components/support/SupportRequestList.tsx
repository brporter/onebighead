import { useCallback } from 'react';
import type { RequestOptions } from '../../api/client';
import type { SupportRequest } from '../../api/support';
import { useAsyncData } from '../../utils/useAsyncData';
import { ContentState } from '../common/ContentState';
import { SupportDate, SupportStatus } from './SupportPresentation';
import '../../styles/components/SupportPanel.css';

interface SupportRequestListProps {
  load: (options?: RequestOptions) => Promise<SupportRequest[]>;
  onSelect: (id: number) => void;
}

export function SupportRequestList({ load, onSelect }: SupportRequestListProps) {
  const fetch = useCallback((signal: AbortSignal) => load({ signal }), [load]);
  const resource = useAsyncData(fetch);
  return <div className="support-panel">
    {resource.loading && <ContentState kind="loading" title="Loading support requests…" />}
    {resource.error && <ContentState kind="error" title="Unable to load support requests" action={<button type="button" className="content-state__button" onClick={resource.retry}>Try again</button>}>{resource.error}</ContentState>}
    {resource.data?.length === 0 && <ContentState kind="empty" title="You haven't submitted any support requests yet." />}
    {resource.data?.map(request => <button type="button" key={request.supportRequestId} className={`support-card ${request.unreadCount > 0 ? 'support-card--unread' : ''}`}
      onClick={() => onSelect(request.supportRequestId)} aria-label={`Support request: ${request.subject}, ${request.status}, ${request.replyCount} replies${request.unreadCount > 0 ? `, ${request.unreadCount} unread` : ''}`}>
      <span className="support-card__header"><strong>{request.subject}</strong><SupportStatus status={request.status} /></span>
      <span className="support-card__preview">{request.description}</span>
      <span className="support-panel__meta"><SupportDate value={request.createdAt} /><span>{request.replyCount} {request.replyCount === 1 ? 'reply' : 'replies'}</span>{request.unreadCount > 0 && <strong>{request.unreadCount} new</strong>}</span>
    </button>)}
  </div>;
}
