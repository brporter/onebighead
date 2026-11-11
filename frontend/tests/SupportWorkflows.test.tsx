import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import * as api from '../src/api';
import { SupportSection } from '../src/components/support/SupportSection';
import { AdminSupportSection } from '../src/components/support/AdminSupportSection';
import { SupportRequestSession } from '../src/components/support/SupportRequestSession';
import { SupportStatus } from '../src/components/support/SupportPresentation';
import { supportRequest, supportReply } from './testUtils/support';
import { deferred } from './testUtils/deferred';
import type { SupportReply, SupportRequest } from '../src/api/support';
import type { SupportSessionPort } from '../src/data/support/ports';

vi.mock('../src/api', () => ({
  getMySupportRequests: vi.fn(), getSupportRequest: vi.fn(), addSupportReply: vi.fn(), deleteSupportRequest: vi.fn(), markSupportRequestAsRead: vi.fn(),
  getAdminSupportRequests: vi.fn(), getAdminSupportRequest: vi.fn(), addAdminSupportReply: vi.fn(), updateSupportStatus: vi.fn(), adminDeleteSupportRequest: vi.fn(),
}));
beforeEach(() => {
  vi.resetAllMocks();
  vi.spyOn(window, 'confirm').mockReturnValue(true);
  vi.mocked(api.getMySupportRequests).mockResolvedValue([supportRequest()]);
  vi.mocked(api.getSupportRequest).mockResolvedValue(supportRequest());
  vi.mocked(api.addSupportReply).mockResolvedValue(supportReply({ supportReplyId: 3 }));
  vi.mocked(api.deleteSupportRequest).mockResolvedValue(undefined);
  vi.mocked(api.markSupportRequestAsRead).mockResolvedValue(undefined);
  vi.mocked(api.getAdminSupportRequests).mockResolvedValue({ items: [supportRequest()], total: 1, offset: 0, limit: 20 });
  vi.mocked(api.getAdminSupportRequest).mockResolvedValue(supportRequest());
  vi.mocked(api.addAdminSupportReply).mockResolvedValue(supportReply({ supportReplyId: 3, isFromAdmin: true }));
  vi.mocked(api.updateSupportStatus).mockResolvedValue(supportRequest({ status: 'Resolved' }));
  vi.mocked(api.adminDeleteSupportRequest).mockResolvedValue(undefined);
});
afterEach(() => vi.restoreAllMocks());
async function openUserRequest() {
  await userEvent.click(await screen.findByRole('button', { name: /Support request: Import help/ }));
  await screen.findByRole('heading', { name: 'Import help' });
}

it('offers list retry, distinguishes empty results and cancels a list superseded by refresh', async () => {
  vi.mocked(api.getMySupportRequests).mockRejectedValueOnce(new Error('Offline')).mockResolvedValueOnce([]);
  const newRequest = vi.fn();
  const { rerender } = render(<SupportSection onNewRequest={newRequest} refreshKey={0} />);
  expect(screen.getByRole('status')).toHaveTextContent('Loading support requests…');
  expect(await screen.findByRole('alert')).toHaveTextContent('Offline');
  expect(screen.queryByText("You haven't submitted any support requests yet.")).not.toBeInTheDocument();
  await userEvent.click(screen.getByRole('button', { name: 'Try again' }));
  expect(await screen.findByText("You haven't submitted any support requests yet.")).toBeInTheDocument();
  await userEvent.click(screen.getByRole('button', { name: '+ New Support Request' }));
  expect(newRequest).toHaveBeenCalledOnce();
  const old = deferred<SupportRequest[]>();
  vi.mocked(api.getMySupportRequests).mockReturnValueOnce(old.promise).mockResolvedValue([supportRequest({ unreadCount: 1, replyCount: 1 }), supportRequest({ supportRequestId: 2, subject: 'Earlier question', replyCount: 2 })]);
  rerender(<SupportSection onNewRequest={newRequest} refreshKey={1} />);
  const signal = vi.mocked(api.getMySupportRequests).mock.calls.at(-1)![0]!.signal!;
  rerender(<SupportSection onNewRequest={newRequest} refreshKey={2} />);
  expect(signal.aborted).toBe(true);
  expect(await screen.findByText('1 new')).toBeInTheDocument();
  expect(screen.getByText('1 reply')).toBeInTheDocument();
  expect(screen.getByText('2 replies')).toBeInTheDocument();
  await act(async () => old.reject(new Error('Old request')));
  expect(screen.queryByRole('alert')).not.toBeInTheDocument();
});

it('keeps the conversation readable when marking read fails and preserves failed replies', async () => {
  const initial = supportRequest({ status: 'Resolved', unreadCount: 1, replyCount: 2, replies: [supportReply(), supportReply({ supportReplyId: 2, isFromAdmin: true, message: 'Try the import screen.' })] });
  vi.mocked(api.getSupportRequest).mockResolvedValue(initial);
  vi.mocked(api.markSupportRequestAsRead).mockRejectedValueOnce(new Error('Read receipt failed'));
  const status = vi.fn();
  const pending = deferred<SupportReply>();
  vi.mocked(api.addSupportReply).mockReturnValueOnce(pending.promise);
  render(<SupportSection onStatusChange={status} />);
  await openUserRequest();
  expect(screen.getByText('Try the import screen.')).toBeInTheDocument();
  expect(screen.getByText('Support Team')).toBeInTheDocument();
  expect(screen.getByText('Requester')).toBeInTheDocument();
  expect(await screen.findByRole('alert')).toHaveTextContent('Unable to mark replies as read');
  await userEvent.click(screen.getByRole('button', { name: 'Try again' }));
  await waitFor(() => expect(screen.queryByRole('alert')).not.toBeInTheDocument());
  const text = screen.getByRole('textbox', { name: 'Your reply' });
  expect(text).toHaveAttribute('maxlength', '4000');
  await userEvent.type(text, '  More details  ');
  vi.mocked(window.confirm).mockReturnValueOnce(false);
  await userEvent.click(screen.getByRole('button', { name: '← Back to requests' }));
  expect(text).toHaveValue('  More details  ');
  expect(status).toHaveBeenLastCalledWith({ dirty: true, pending: false });
  fireEvent.submit(screen.getByRole('form'));
  fireEvent.submit(screen.getByRole('form'));
  expect(api.addSupportReply).toHaveBeenCalledExactlyOnceWith(1, { message: 'More details' });
  expect(text).toBeDisabled();
  for (const button of screen.getAllByRole('button')) expect(button).toBeDisabled();
  expect(status).toHaveBeenLastCalledWith({ dirty: true, pending: true });
  await act(async () => pending.reject(new Error('Reply failed')));
  expect(screen.getByRole('alert')).toHaveTextContent('Reply failed');
  expect(text).toHaveValue('  More details  ');
  vi.mocked(api.getSupportRequest).mockResolvedValue({ ...initial, status: 'Open' });
  await userEvent.click(screen.getByRole('button', { name: 'Send Reply' }));
  expect(text).toHaveValue('');
  expect(screen.getByText('Open')).toBeInTheDocument();
  vi.mocked(api.getMySupportRequests).mockResolvedValue([supportRequest({ replyCount: 3 })]);
  await userEvent.click(screen.getByRole('button', { name: '← Back to requests' }));
  expect(await screen.findByText('3 replies')).toBeInTheDocument();
  expect(status).toHaveBeenLastCalledWith({ dirty: false, pending: false });
});

it('confirms discarding an unsent reply and retries failed deletion without losing the request', async () => {
  const pending = deferred<void>();
  vi.mocked(api.deleteSupportRequest).mockReturnValueOnce(pending.promise);
  render(<SupportSection />);
  await openUserRequest();
  await userEvent.type(screen.getByRole('textbox'), 'Draft');
  await userEvent.click(screen.getByRole('button', { name: '← Back to requests' }));
  expect(window.confirm).toHaveBeenCalledWith('Discard your unsent reply?');
  await openUserRequest();
  const remove = screen.getByRole('button', { name: 'Delete support request: Import help' });
  vi.mocked(window.confirm).mockReturnValueOnce(false);
  await userEvent.click(remove);
  expect(api.deleteSupportRequest).not.toHaveBeenCalled();
  await userEvent.click(remove);
  expect(window.confirm).toHaveBeenLastCalledWith('Delete support request "Import help"?');
  expect(remove).toBeDisabled();
  expect(screen.getByRole('button', { name: '← Back to requests' })).toBeDisabled();
  await act(async () => pending.reject(new Error('Delete failed')));
  expect(screen.getByRole('alert')).toHaveTextContent('Delete failed');
  vi.mocked(api.getMySupportRequests).mockResolvedValue([]);
  await userEvent.click(remove);
  expect(await screen.findByText("You haven't submitted any support requests yet.")).toBeInTheDocument();
});

it('retries detail loads and ignores a result for the previous selection', async () => {
  const old = deferred<SupportRequest>();
  const next = deferred<SupportRequest>();
  const gateway: SupportSessionPort = { read: vi.fn().mockRejectedValueOnce(new Error('Offline')).mockReturnValueOnce(old.promise).mockReturnValueOnce(next.promise), reply: vi.fn(), remove: vi.fn() };
  const back = vi.fn();
  const { rerender, unmount } = render(<SupportRequestSession requestId={1} gateway={gateway} onBack={back} />);
  expect(await screen.findByRole('alert')).toHaveTextContent('Unable to load request details');
  await userEvent.click(screen.getByRole('button', { name: 'Try again' }));
  expect(screen.getByText('Loading request details…')).toBeInTheDocument();
  const signal = vi.mocked(gateway.read).mock.calls.at(-1)![1]!.signal!;
  await userEvent.click(screen.getByRole('button', { name: '← Back to requests' }));
  expect(back).toHaveBeenCalledOnce();
  rerender(<SupportRequestSession requestId={2} gateway={gateway} onBack={back} />);
  expect(signal.aborted).toBe(true);
  await act(async () => next.resolve(supportRequest({ supportRequestId: 2, subject: 'Second request' })));
  await act(async () => old.resolve(supportRequest()));
  expect(screen.getByRole('heading', { name: 'Second request' })).toBeInTheDocument();
  expect(screen.queryByRole('heading', { name: 'Import help' })).not.toBeInTheDocument();
  const latestSignal = vi.mocked(gateway.read).mock.calls.at(-1)![1]!.signal!;
  unmount();
  expect(latestSignal.aborted).toBe(true);
});

it('keeps admin filters and pagination when opening read-only deleted requests', async () => {
  vi.mocked(api.getAdminSupportRequests).mockResolvedValue({ items: [supportRequest(), supportRequest({ supportRequestId: 2, subject: 'Archived', userId: null, isDeleted: true })], total: 21, offset: 0, limit: 20 });
  vi.mocked(api.getAdminSupportRequest).mockResolvedValue(supportRequest({ supportRequestId: 2, subject: 'Archived', userId: null, isDeleted: true }));
  render(<AdminSupportSection />);
  const table = await screen.findByRole('table', { name: 'Support requests' });
  expect(screen.getByRole('region', { name: 'Support request queue' })).toHaveAttribute('tabindex', '0');
  expect(within(table).getByText('reader@example.com (user)')).toBeInTheDocument();
  expect(screen.queryByRole('button', { name: 'Delete support request: Archived' })).not.toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Previous' })).toBeDisabled();
  await userEvent.click(screen.getByRole('button', { name: 'Next' }));
  await screen.findByRole('table');
  expect(api.getAdminSupportRequests).toHaveBeenLastCalledWith(expect.objectContaining({ offset: 20 }), { signal: expect.any(AbortSignal) });
  expect(screen.getByRole('button', { name: 'Next' })).toBeDisabled();
  await userEvent.click(screen.getByRole('button', { name: 'Previous' }));
  await screen.findByRole('table');
  await userEvent.selectOptions(screen.getByRole('combobox', { name: 'Filter by status' }), 'Closed');
  await screen.findByRole('table');
  await userEvent.click(screen.getByRole('checkbox', { name: 'Include deleted' }));
  await screen.findByRole('table');
  expect(api.getAdminSupportRequests).toHaveBeenLastCalledWith({ status: 'Closed', includeDeleted: true, limit: 20, offset: 0 }, { signal: expect.any(AbortSignal) });
  await userEvent.click(screen.getByRole('button', { name: 'Archived' }));
  expect(await screen.findByText('This request has been deleted')).toBeInTheDocument();
  expect(screen.queryByRole('form')).not.toBeInTheDocument();
  expect(screen.queryByText(/Registered User/)).not.toBeInTheDocument();
  await userEvent.click(screen.getByRole('button', { name: '← Back to requests' }));
  await screen.findByRole('table');
  expect(screen.getByRole('combobox', { name: 'Filter by status' })).toHaveValue('Closed');
  expect(screen.getByRole('checkbox')).toBeChecked();
});

it('offers admin list recovery and corrects an empty final page after confirmed deletion', async () => {
  let removed = false;
  vi.mocked(api.getAdminSupportRequests).mockRejectedValueOnce(new Error('Queue offline')).mockImplementation(async query => ({
    items: removed && query?.offset === 20 ? [] : [supportRequest()], total: removed ? 20 : 21, offset: query?.offset ?? 0, limit: 20,
  }));
  const status = vi.fn();
  render(<AdminSupportSection onStatusChange={status} />);
  expect(await screen.findByRole('alert')).toHaveTextContent('Queue offline');
  await userEvent.click(screen.getByRole('button', { name: 'Try again' }));
  await screen.findByRole('table');
  await userEvent.click(screen.getByRole('button', { name: 'Next' }));
  await screen.findByRole('table');
  vi.mocked(api.adminDeleteSupportRequest).mockRejectedValueOnce(new Error('Delete unavailable'));
  await userEvent.click(screen.getByRole('button', { name: 'Delete support request: Import help' }));
  expect(await screen.findByRole('alert')).toHaveTextContent('Delete unavailable');
  const pending = deferred<void>();
  vi.mocked(api.adminDeleteSupportRequest).mockReturnValueOnce(pending.promise);
  await userEvent.click(screen.getByRole('button', { name: 'Delete support request: Import help' }));
  expect(screen.getByRole('combobox')).toBeDisabled();
  expect(screen.getByRole('checkbox')).toBeDisabled();
  expect(screen.getByRole('button', { name: 'Previous' })).toBeDisabled();
  expect(screen.getByRole('button', { name: 'View support request: Import help' })).toBeDisabled();
  expect(status).toHaveBeenLastCalledWith({ dirty: false, pending: true });
  removed = true;
  await act(async () => pending.resolve());
  await waitFor(() => expect(api.getAdminSupportRequests).toHaveBeenLastCalledWith(expect.objectContaining({ offset: 0 }), { signal: expect.any(AbortSignal) }));
  expect(await screen.findByText('Showing 1 of 20 requests')).toBeInTheDocument();
  expect(screen.queryByRole('navigation', { name: 'Support pages' })).not.toBeInTheDocument();
  vi.mocked(api.getAdminSupportRequests).mockResolvedValue({ items: [], total: 0, limit: 20, offset: 0 });
  await userEvent.selectOptions(screen.getByRole('combobox'), 'Resolved');
  expect(await screen.findByText('No support requests found.')).toBeInTheDocument();
});

it('serializes admin status and reply actions while preserving conversation details', async () => {
  vi.mocked(api.getAdminSupportRequest).mockResolvedValue(supportRequest({ replies: [supportReply()] }));
  const statusUpdate = deferred<SupportRequest>();
  vi.mocked(api.updateSupportStatus).mockReturnValueOnce(statusUpdate.promise);
  render(<AdminSupportSection />);
  await userEvent.click(await screen.findByRole('button', { name: 'View support request: Import help' }));
  expect(await screen.findByText(/Registered User/)).toBeInTheDocument();
  expect(screen.getByText('Sending a reply emails the requester.')).toBeInTheDocument();
  const text = screen.getByRole('textbox', { name: 'Your reply' });
  await userEvent.type(text, 'Answer');
  await userEvent.selectOptions(screen.getByRole('combobox', { name: 'Request status' }), 'Closed');
  expect(text).toBeDisabled();
  expect(screen.getByRole('combobox')).toBeDisabled();
  await act(async () => statusUpdate.resolve(supportRequest({ status: 'Resolved', replies: [] })));
  expect(screen.getByRole('combobox')).toHaveValue('Resolved');
  expect(screen.getByText('Here is more information.')).toBeInTheDocument();
  expect(text).toHaveValue('Answer');
  vi.mocked(api.getAdminSupportRequest).mockResolvedValue(supportRequest({ status: 'Resolved', replies: [supportReply(), supportReply({ supportReplyId: 3, isFromAdmin: true })] }));
  await userEvent.click(screen.getByRole('button', { name: 'Send Reply' }));
  expect(api.addAdminSupportReply).toHaveBeenCalledExactlyOnceWith(1, { message: 'Answer' });
  expect(text).toHaveValue('');
  expect(screen.getByText('Support Team')).toBeInTheDocument();
});

it('preserves an unrecognized status label', () => {
  render(<SupportStatus status="Escalated" />);
  expect(screen.getByText('Escalated')).toHaveClass('support-status--escalated');
});

it('reports a sent reply separately from refresh failure and retries only the read', async () => {
  render(<SupportSection />);
  await openUserRequest();
  vi.mocked(api.getSupportRequest).mockRejectedValueOnce(new Error('Refresh offline'));
  await userEvent.type(screen.getByRole('textbox'), 'Follow-up');
  await userEvent.click(screen.getByRole('button', { name: 'Send Reply' }));
  expect(await screen.findByRole('alert')).toHaveTextContent('Reply sent; unable to refresh the conversation');
  expect(screen.getByRole('textbox')).toHaveValue('');
  expect(screen.getByText('Here is more information.')).toBeInTheDocument();
  const refresh = deferred<SupportRequest>();
  vi.mocked(api.getSupportRequest).mockRejectedValueOnce(new Error('Still offline'));
  await userEvent.click(screen.getByRole('button', { name: 'Refresh conversation' }));
  expect(await screen.findByText('Still offline')).toBeInTheDocument();
  expect(screen.getAllByRole('button', { name: 'Refresh conversation' })).toHaveLength(1);
  vi.mocked(api.getSupportRequest).mockReturnValueOnce(refresh.promise);
  await userEvent.click(screen.getByRole('button', { name: 'Refresh conversation' }));
  expect(screen.getByRole('button', { name: 'Refresh conversation' })).toBeDisabled();
  await act(async () => refresh.resolve(supportRequest({ status: 'InProgress' })));
  expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  expect(screen.getByText('In progress')).toBeInTheDocument();
  expect(api.addSupportReply).toHaveBeenCalledOnce();
});

it('refreshes after a reply conflict without resending or discarding the draft', async () => {
  const status = vi.fn();
  render(<SupportSection onStatusChange={status} />);
  await openUserRequest();
  const text = screen.getByRole('textbox', { name: 'Your reply' });
  await userEvent.type(text, 'Keep this draft');
  vi.mocked(api.addSupportReply).mockRejectedValueOnce(new Error('This support request changed. Refresh it before sending your reply again.'));
  await userEvent.click(screen.getByRole('button', { name: 'Send Reply' }));
  expect(await screen.findByRole('alert')).toHaveTextContent('This support request changed');
  const refresh = deferred<SupportRequest>();
  vi.mocked(api.getSupportRequest).mockReturnValueOnce(refresh.promise);
  await userEvent.click(screen.getByRole('button', { name: 'Refresh conversation' }));
  expect(status).toHaveBeenLastCalledWith({ dirty: true, pending: true });
  expect(text).toBeDisabled();
  expect(screen.getByRole('button', { name: '← Back to requests' })).toBeDisabled();
  await act(async () => refresh.resolve(supportRequest({ status: 'InProgress', replies: [supportReply({ message: 'A new reply from support', isFromAdmin: true })] })));
  expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  expect(screen.getByText('A new reply from support')).toBeInTheDocument();
  expect(screen.getByText('In progress')).toBeInTheDocument();
  expect(text).toHaveValue('Keep this draft');
  expect(status).toHaveBeenLastCalledWith({ dirty: true, pending: false });
  expect(api.addSupportReply).toHaveBeenCalledOnce();
  expect(api.deleteSupportRequest).not.toHaveBeenCalled();
});
