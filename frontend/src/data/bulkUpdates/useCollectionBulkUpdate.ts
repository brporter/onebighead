import { useCallback, useEffect, useRef, useState } from 'react';
import type { bulkUpdatesApi } from '../../api/bulkUpdates';
import { useAsyncData } from '../../utils/useAsyncData';
import { isBulkUpdateActive, useBulkUpdateMonitor } from './useBulkUpdateMonitor';

export function useCollectionBulkUpdate(
  collectionId: number | null,
  gateway: Pick<typeof bulkUpdatesApi, 'getCollectionStatus' | 'getStatus'>,
  onSettled: () => void,
) {
  const [request, setRequest] = useState({ collectionId });
  if (request.collectionId !== collectionId) setRequest({ collectionId });
  const fetchJob = useCallback((signal: AbortSignal) => gateway.getCollectionStatus(request.collectionId!, { signal }), [request, gateway]);
  const discovery = useAsyncData(collectionId === null ? null : fetchJob);
  const monitor = useBulkUpdateMonitor(discovery.data, gateway);
  const lastNotifiedJob = useRef<string | null>(null);

  useEffect(() => {
    if (monitor.job && !isBulkUpdateActive(monitor.job) && lastNotifiedJob.current !== monitor.job.jobId) {
      lastNotifiedJob.current = monitor.job.jobId;
      onSettled();
    }
  }, [monitor.job, onSettled]);

  return {
    job: monitor.job,
    error: discovery.error ?? monitor.error,
    retry: discovery.error ? () => setRequest({ collectionId }) : monitor.retry,
  };
}
