import { useCallback, useState } from 'react';
import { getAdminSupportRequests, getAdminSupportRequest, addAdminSupportReply, updateSupportStatus, adminDeleteSupportRequest } from '../../api';
import type { SupportQueueQuery } from '../../data/support/ports';
import type { EditorStatusListener } from '../../data/shared/useEditorStatus';
import { SupportRequestSession } from './SupportRequestSession';
import { AdminSupportQueue } from './AdminSupportQueue';
import '../../styles/components/AdminSupportSection.css';

const gateway = { read: getAdminSupportRequest, reply: addAdminSupportReply, remove: adminDeleteSupportRequest, changeStatus: updateSupportStatus };
const queueGateway = { list: getAdminSupportRequests, remove: adminDeleteSupportRequest };

export function AdminSupportSection({ onStatusChange }: { onStatusChange?: EditorStatusListener }) {
  const [selectedId, setSelectedId] = useState<number | null>(null);
  const [query, setQuery] = useState<SupportQueueQuery>({ status: '', includeDeleted: false, page: 0 });
  const setPage = useCallback((page: number) => setQuery(previous => ({ ...previous, page })), []);
  if (selectedId !== null) return <SupportRequestSession requestId={selectedId} gateway={gateway} onBack={() => setSelectedId(null)} onStatusChange={onStatusChange} />;
  return <AdminSupportQueue query={query} gateway={queueGateway} onQueryChange={setQuery} onPageChange={setPage} onSelect={setSelectedId} onStatusChange={onStatusChange} />;
}
