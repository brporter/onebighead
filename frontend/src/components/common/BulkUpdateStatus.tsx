import type { BulkUpdateJobResponse } from '../../api/bulkUpdates';
import { ContentState } from './ContentState';
import '../../styles/components/BulkUpdateModal.css';

interface BulkUpdateStatusProps {
  job: BulkUpdateJobResponse | null;
  error: string | null;
  onRetry: () => void;
}

export function BulkUpdateStatus({ job, error, onRetry }: BulkUpdateStatusProps) {
  if (error) return <ContentState kind="error" title="Unable to check the update"
    action={<button type="button" onClick={onRetry}>Check again</button>}>{error}</ContentState>;
  if (!job) return null;
  if (job.status === 'Failed' || job.status === 'Cancelled') {
    const interrupted = job.status === 'Cancelled';
    return <ContentState kind="error" title={interrupted ? 'Item update interrupted' : 'Item update failed'}>
      <p>{job.errorMessage ?? (interrupted ? 'The update stopped before all items could be processed.' : 'Unable to complete the update.')}</p>
      {job.totalItems > 0 && <p>Updated {job.processedItems} of {job.totalItems} items. Review your items before starting another update.</p>}
    </ContentState>;
  }
  if (job.status === 'Completed') return <p className="bulk-update-banner" role="status">
    Updated {job.processedItems} {job.processedItems === 1 ? 'item' : 'items'}.
    {job.failedItems > 0 && ` (${job.failedItems} skipped)`}
  </p>;

  return <div className="bulk-update-banner" role="status">
    <p className="bulk-update-banner__text">Updating item properties…</p>
    <progress className="bulk-update-modal__bar" aria-label="Items updated"
      value={job.totalItems > 0 ? job.processedItems + job.failedItems : undefined} max={job.totalItems || 1} />
    <p className="bulk-update-banner__detail">
      {job.processedItems + job.failedItems} / {job.totalItems} items
      {job.status === 'Queued' && ' (queued)'}
    </p>
  </div>;
}
