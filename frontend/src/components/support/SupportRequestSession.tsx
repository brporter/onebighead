import { useCallback } from 'react';
import type { SupportSessionPort } from '../../data/support/ports';
import type { EditorStatusListener } from '../../data/shared/useEditorStatus';
import { useAsyncData } from '../../utils/useAsyncData';
import { ContentState } from '../common/ContentState';
import { SupportConversation } from './SupportConversation';
import '../../styles/components/SupportPanel.css';

interface SupportRequestSessionProps {
  requestId: number;
  gateway: SupportSessionPort;
  onBack: () => void;
  onStatusChange?: EditorStatusListener;
}

export function SupportRequestSession({ requestId, gateway, onBack, onStatusChange }: SupportRequestSessionProps) {
  const fetch = useCallback((signal: AbortSignal) => gateway.read(requestId, { signal }), [gateway, requestId]);
  const resource = useAsyncData(fetch);
  if (resource.data) return <SupportConversation key={requestId} request={resource.data} gateway={gateway} onBack={onBack} onStatusChange={onStatusChange} />;
  return <div className="support-panel">
    <button type="button" className="support-panel__button" onClick={onBack}>← Back to requests</button>
    {resource.loading && <ContentState kind="loading" title="Loading request details…" />}
    {resource.error && <ContentState kind="error" title="Unable to load request details" action={<button type="button" className="content-state__button" onClick={resource.retry}>Try again</button>}>{resource.error}</ContentState>}
  </div>;
}
