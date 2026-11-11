import type { SupportRequest } from '../../api/support';
import '../../styles/components/SupportPanel.css';

export const SUPPORT_STATUSES = [
  { value: 'Open', label: 'Open' }, { value: 'InProgress', label: 'In progress' },
  { value: 'Resolved', label: 'Resolved' }, { value: 'Closed', label: 'Closed' },
] as const;

export function SupportStatus({ status }: { status: string }) {
  return <span className={`support-status support-status--${status.toLowerCase()}`}>{SUPPORT_STATUSES.find(option => option.value === status)?.label ?? status}</span>;
}

export function SupportDate({ value }: { value: string }) {
  const date = new Date(value);
  return <time dateTime={value}>{date.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })}</time>;
}

export function SupportDeleteButton({ request, disabled, onDelete }: { request: SupportRequest; disabled: boolean; onDelete: () => void }) {
  return <button type="button" className="support-panel__button support-panel__button--danger" aria-label={`Delete support request: ${request.subject}`} disabled={disabled} onClick={() => {
    if (window.confirm(`Delete support request "${request.subject}"?`)) onDelete();
  }}>Delete Request</button>;
}
