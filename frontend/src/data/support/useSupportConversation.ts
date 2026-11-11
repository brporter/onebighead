import { useCallback, useState } from 'react';
import type { SupportRequest } from '../../api/support';
import { useAsyncAction } from '../../utils/useAsyncAction';
import { useAsyncData } from '../../utils/useAsyncData';
import type { SupportSessionPort } from './ports';
import { getErrorMessage } from '../../utils/errorUtils';

export function useSupportConversation(initial: SupportRequest, gateway: SupportSessionPort, onDeleted: () => void) {
  const [request, setRequest] = useState(initial);
  const [replyText, setReplyText] = useState('');
  const [refreshError, setRefreshError] = useState<string | null>(null);
  const action = useAsyncAction();
  const markRead = gateway.markRead;
  const acknowledge = useCallback(async () => { await markRead!(initial.supportRequestId); return true; }, [markRead, initial.supportRequestId]);
  const receipt = useAsyncData(markRead && initial.unreadCount > 0 ? acknowledge : null);
  const requireActive = () => { if (request.isDeleted) throw new Error('This request has been deleted.'); };

  return {
    request, replyText, setReplyText, dirty: replyText.length > 0, receipt, refreshError,
    pending: action.pending, error: action.error,
    sendReply: () => action.run(async () => {
      requireActive();
      const message = replyText.trim();
      if (!message) throw new Error('Write a reply before sending.');
      const reply = await gateway.reply(request.supportRequestId, { message });
      try {
        return { reply, refreshed: await gateway.read(request.supportRequestId), refreshError: null };
      } catch (cause) {
        return { reply, refreshed: null, refreshError: getErrorMessage(cause, 'Failed to refresh request') };
      }
    }, 'Failed to send reply', result => {
      setRequest(previous => result.refreshed ?? { ...previous, replies: [...previous.replies, result.reply], replyCount: previous.replyCount + 1 });
      setReplyText('');
      setRefreshError(result.refreshError);
    }),
    refresh: () => action.run(() => gateway.read(request.supportRequestId), 'Failed to refresh request', refreshed => {
      setRequest(refreshed);
      setRefreshError(null);
    }),
    changeStatus: (status: string) => action.run(async () => {
      requireActive();
      if (!gateway.changeStatus) throw new Error('Status changes are unavailable.');
      return gateway.changeStatus(request.supportRequestId, status);
    }, 'Failed to update status', updated => {
      setRequest(previous => ({ ...previous, status: updated.status, updatedAt: updated.updatedAt }));
    }),
    remove: () => action.run(async () => {
      requireActive();
      await gateway.remove(request.supportRequestId);
    }, 'Failed to delete request', onDeleted),
  };
}
