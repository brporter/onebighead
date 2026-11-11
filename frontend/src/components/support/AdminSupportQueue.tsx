import { useSupportQueue } from '../../data/support/useSupportQueue';
import type { SupportQueuePort, SupportQueueQuery } from '../../data/support/ports';
import { useEditorStatus, type EditorStatusListener } from '../../data/shared/useEditorStatus';
import { ContentState } from '../common/ContentState';
import { SUPPORT_STATUSES, SupportDate, SupportDeleteButton, SupportStatus } from './SupportPresentation';
import '../../styles/components/AdminSupportSection.css';

interface AdminSupportQueueProps {
  query: SupportQueueQuery;
  gateway: SupportQueuePort;
  onQueryChange: (query: SupportQueueQuery) => void;
  onPageChange: (page: number) => void;
  onSelect: (id: number) => void;
  onStatusChange?: EditorStatusListener;
}

export function AdminSupportQueue({ query, gateway, onQueryChange, onPageChange, onSelect, onStatusChange }: AdminSupportQueueProps) {
  const queue = useSupportQueue(query, gateway, onPageChange);
  useEditorStatus(false, queue.pending, onStatusChange);
  return <div className="support-panel">
    <div className="support-queue__filters">
      <label className="support-panel__field">Filter by status<select disabled={queue.pending} value={query.status} onChange={event => onQueryChange({ ...query, status: event.target.value, page: 0 })}>
        <option value="">All statuses</option>{SUPPORT_STATUSES.map(status => <option key={status.value} value={status.value}>{status.label}</option>)}
      </select></label>
      <label className="support-queue__checkbox"><input type="checkbox" disabled={queue.pending} checked={query.includeDeleted} onChange={event => onQueryChange({ ...query, includeDeleted: event.target.checked, page: 0 })} />Include deleted</label>
    </div>
    {queue.loading && <ContentState kind="loading" title="Loading support requests…" />}
    {queue.error && <ContentState kind="error" title="Unable to load support requests" action={<button type="button" className="content-state__button" onClick={queue.retry}>Try again</button>}>{queue.error}</ContentState>}
    {queue.actionError && <ContentState kind="error" title="Unable to delete request">{queue.actionError}</ContentState>}
    {queue.pending && <p role="status">Deleting request…</p>}
    {queue.data && <>
      <p className="support-panel__hint">Showing {queue.data.items.length} of {queue.data.total} requests</p>
      {queue.data.items.length === 0 ? <ContentState kind="empty" title="No support requests found." /> : <div className="support-queue__scroll" role="region" aria-label="Support request queue" tabIndex={0}>
        <table className="support-queue__table"><caption>Support requests</caption><thead><tr><th scope="col">Subject</th><th scope="col">From</th><th scope="col">Status</th><th scope="col">Replies</th><th scope="col">Created</th><th scope="col">Actions</th></tr></thead>
          <tbody>{queue.data.items.map(request => <tr key={request.supportRequestId}>
            <td><button type="button" className="support-panel__button" disabled={queue.pending} onClick={() => onSelect(request.supportRequestId)}>{request.subject}</button>{request.isDeleted && <span> (deleted)</span>}</td>
            <td>{request.email}{request.userId !== null && ' (user)'}</td><td><SupportStatus status={request.status} /></td><td>{request.replyCount}</td><td><SupportDate value={request.createdAt} /></td>
            <td><div className="support-panel__actions"><button type="button" className="support-panel__button" aria-label={`View support request: ${request.subject}`} disabled={queue.pending} onClick={() => onSelect(request.supportRequestId)}>View</button>
              {!request.isDeleted && <SupportDeleteButton request={request} disabled={queue.pending} onDelete={() => { void queue.remove(request.supportRequestId); }} />}</div></td>
          </tr>)}</tbody>
        </table>
      </div>}
      {queue.totalPages > 1 && <nav className="support-queue__pagination" aria-label="Support pages">
        <button type="button" className="support-panel__button" disabled={queue.pending || query.page === 0} onClick={() => onPageChange(query.page - 1)}>Previous</button>
        <span>Page {query.page + 1} of {queue.totalPages}</span>
        <button type="button" className="support-panel__button" disabled={queue.pending || query.page >= queue.totalPages - 1} onClick={() => onPageChange(query.page + 1)}>Next</button>
      </nav>}
    </>}
  </div>;
}
