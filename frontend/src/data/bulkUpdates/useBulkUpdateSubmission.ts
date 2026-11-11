import { useEffect, useRef, useState } from 'react';
import type { bulkUpdatesApi, BulkUpdateJobResponse, EnqueueBulkUpdateRequest } from '../../api/bulkUpdates';
import { getErrorMessage } from '../../utils/errorUtils';

/** One submission at a time; leaving the dialog releases the pending request. */
export function useBulkUpdateSubmission(gateway: Pick<typeof bulkUpdatesApi, 'enqueue'>) {
  const [job, setJob] = useState<BulkUpdateJobResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const pending = useRef<AbortController | null>(null);

  useEffect(() => () => {
    pending.current?.abort();
    pending.current = null;
  }, []);

  async function submit(request: EnqueueBulkUpdateRequest) {
    if (pending.current) return;
    const controller = new AbortController();
    pending.current = controller;
    setSubmitting(true);
    setError(null);
    try {
      const result = await gateway.enqueue(request, { signal: controller.signal });
      if (!controller.signal.aborted) setJob(result);
    } catch (cause) {
      if (!controller.signal.aborted) setError(getErrorMessage(cause, 'Failed to start bulk update'));
    } finally {
      if (pending.current === controller) {
        pending.current = null;
        setSubmitting(false);
      }
    }
  }

  return { job, error, submitting, submit };
}
