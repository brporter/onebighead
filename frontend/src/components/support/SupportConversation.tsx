import { useId } from 'react';
import type { SupportRequest } from '../../api/support';
import type { SupportSessionPort } from '../../data/support/ports';
import { useSupportConversation } from '../../data/support/useSupportConversation';
import { useEditorStatus, type EditorStatusListener } from '../../data/shared/useEditorStatus';
import { ContentState } from '../common/ContentState';
import { SUPPORT_STATUSES, SupportDate, SupportDeleteButton, SupportStatus } from './SupportPresentation';
import '../../styles/components/SupportPanel.css';

interface SupportConversationProps {
  request: SupportRequest;
  gateway: SupportSessionPort;
  onBack: () => void;
  onStatusChange?: EditorStatusListener;
}

export function SupportConversation({ request: initial, gateway, onBack, onStatusChange }: SupportConversationProps) {
  const id = useId();
  const conversation = useSupportConversation(initial, gateway, onBack);
  const { request, pending, dirty } = conversation;
  useEditorStatus(dirty, pending, onStatusChange);
  const back = () => {
    if (!dirty || window.confirm('Discard your unsent reply?')) onBack();
  };
  return <article className="support-conversation" aria-label={request.subject}>
    <button type="button" className="support-panel__button" disabled={pending} onClick={back}>← Back to requests</button>
    <header className="support-conversation__header">
      <h3>{request.subject}</h3>
      <div className="support-panel__meta"><SupportStatus status={request.status} /><span>Created <SupportDate value={request.createdAt} /></span></div>
      {gateway.changeStatus && <p>From: {request.email}{request.userId !== null && ' (Registered User)'}</p>}
    </header>
    <p className="support-conversation__message">{request.description}</p>
    {conversation.receipt.error && <ContentState kind="error" title="Unable to mark replies as read" action={<button type="button" className="content-state__button" onClick={conversation.receipt.retry}>Try again</button>}>{conversation.receipt.error}</ContentState>}
    {conversation.refreshError && <ContentState kind="error" title="Reply sent; unable to refresh the conversation" action={<button type="button" className="content-state__button" disabled={pending} onClick={() => { void conversation.refresh(); }}>Refresh conversation</button>}>{conversation.refreshError}</ContentState>}
    {conversation.error && <ContentState kind="error" title="Unable to update request" action={!conversation.refreshError && <button type="button" className="content-state__button" disabled={pending} onClick={() => { void conversation.refresh(); }}>Refresh conversation</button>}>{conversation.error}</ContentState>}
    {request.replies.length > 0 && <section className="support-conversation__replies" aria-label="Conversation">
      <h4>Conversation</h4>
      {request.replies.map(reply => <article className={`support-conversation__reply ${reply.isFromAdmin ? 'support-conversation__reply--admin' : ''}`} key={reply.supportReplyId}>
        <header className="support-panel__meta"><strong>{reply.isFromAdmin ? 'Support Team' : 'Requester'}</strong><SupportDate value={reply.createdAt} /></header>
        <p className="support-conversation__message">{reply.message}</p>
      </article>)}
    </section>}
    {request.isDeleted ? <ContentState kind="empty" title="This request has been deleted" /> : <form aria-label="Reply to support request" onSubmit={event => { event.preventDefault(); void conversation.sendReply(); }}>
      <fieldset disabled={pending} className="support-conversation__fields">
        {gateway.changeStatus && <label className="support-panel__field">Request status<select value={request.status} onChange={event => { void conversation.changeStatus(event.target.value); }}>
          {SUPPORT_STATUSES.map(status => <option key={status.value} value={status.value}>{status.label}</option>)}
        </select></label>}
        <label htmlFor={`${id}-reply`}>Your reply</label>
        <textarea id={`${id}-reply`} value={conversation.replyText} onChange={event => conversation.setReplyText(event.target.value)} rows={4} maxLength={4000} aria-describedby={gateway.changeStatus ? `${id}-notification` : undefined} />
        {gateway.changeStatus && <p id={`${id}-notification`} className="support-panel__hint">Sending a reply emails the requester.</p>}
        <div className="support-panel__actions">
          <SupportDeleteButton request={request} disabled={pending} onDelete={() => { void conversation.remove(); }} />
          <button type="submit" className="support-panel__button support-panel__button--primary" disabled={pending || !conversation.replyText.trim()}>Send Reply</button>
        </div>
      </fieldset>
    </form>}
    {pending && <p role="status">Updating request…</p>}
  </article>;
}
