import { useEffect, useState } from 'react';
import type { bulkUpdatesApi, BulkUpdateJobResponse } from '../../api/bulkUpdates';
import { getErrorMessage } from '../../utils/errorUtils';

export function isBulkUpdateActive(job: BulkUpdateJobResponse) {
  return job.status === 'Queued' || job.status === 'Running';
}

/** Poll sequentially; one effect owns every request and timer for a job. */
export function useBulkUpdateMonitor(initialJob: BulkUpdateJobResponse | null, gateway: Pick<typeof bulkUpdatesApi, 'getStatus'>) {
  const [state, setState] = useState({ source: initialJob, job: initialJob, error: null as string | null });
  const [attempt, setAttempt] = useState(0);
  if (state.source !== initialJob) setState({ source: initialJob, job: initialJob, error: null });

  useEffect(() => {
    if (!initialJob || !isBulkUpdateActive(initialJob)) return;
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout>;
    const poll = async () => {
      try {
        const job = await gateway.getStatus(initialJob.jobId, { signal: controller.signal });
        if (controller.signal.aborted) return;
        setState({ source: initialJob, job, error: null });
        if (isBulkUpdateActive(job)) timer = setTimeout(poll, 500);
      } catch (cause) {
        if (!controller.signal.aborted) setState(previous => ({ ...previous, error: getErrorMessage(cause, 'Failed to check update status') }));
      }
    };
    timer = setTimeout(poll, 500);
    return () => {
      controller.abort();
      clearTimeout(timer);
    };
  }, [initialJob, gateway, attempt]);

  function retry() {
    setState(previous => ({ ...previous, error: null }));
    setAttempt(value => value + 1);
  }

  return { job: state.job, error: state.error, retry };
}
