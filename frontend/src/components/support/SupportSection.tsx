import { useState } from 'react';
import { getMySupportRequests, getSupportRequest, addSupportReply, deleteSupportRequest, markSupportRequestAsRead } from '../../api';
import type { EditorStatusListener } from '../../data/shared/useEditorStatus';
import { SupportRequestSession } from './SupportRequestSession';
import { SupportRequestList } from './SupportRequestList';
import '../../styles/components/SupportPanel.css';

const gateway = { read: getSupportRequest, reply: addSupportReply, remove: deleteSupportRequest, markRead: markSupportRequestAsRead };
interface SupportSectionProps {
  isFullPage?: boolean;
  onNewRequest?: () => void;
  refreshKey?: number;
  onStatusChange?: EditorStatusListener;
}

export function SupportSection({ onNewRequest, refreshKey, onStatusChange }: SupportSectionProps) {
  const [selectedId, setSelectedId] = useState<number | null>(null);
  if (selectedId !== null) return <SupportRequestSession requestId={selectedId} gateway={gateway} onBack={() => setSelectedId(null)} onStatusChange={onStatusChange} />;
  return <div className="support-panel">
    {onNewRequest && <div className="support-panel__actions"><button type="button" className="support-panel__button support-panel__button--primary" onClick={onNewRequest}>+ New Support Request</button></div>}
    <SupportRequestList key={refreshKey} load={getMySupportRequests} onSelect={setSelectedId} />
  </div>;
}
