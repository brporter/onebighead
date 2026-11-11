import { act, fireEvent, render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { SupportModal } from '../src/components/support/SupportModal';
import { createSupportRequest } from '../src/api';
import { supportRequest } from './testUtils/support';
import { deferred } from './testUtils/deferred';

vi.mock('../src/api', () => ({ createSupportRequest: vi.fn() }));
beforeEach(() => {
  vi.mocked(createSupportRequest).mockReset().mockResolvedValue(supportRequest());
  vi.spyOn(window, 'confirm').mockReturnValue(true);
});
afterEach(() => vi.restoreAllMocks());

function fillDraft() {
  fireEvent.change(screen.getByRole('textbox', { name: 'Subject' }), { target: { value: ' Help ' } });
  fireEvent.change(screen.getByRole('textbox', { name: 'Description' }), { target: { value: ' Details ' } });
}

it('provides independent labels, limits and help for anonymous composers', async () => {
  const close = vi.fn();
  const props = { isOpen: false, onClose: close };
  const { rerender } = render(<SupportModal {...props} />);
  expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
  rerender(<><SupportModal {...props} isOpen /><SupportModal {...props} isOpen userEmail={null} /></>);
  const dialogs = screen.getAllByRole('dialog');
  const inputs = dialogs.map(dialog => within(dialog).getByRole('textbox', { name: 'Email' }));
  expect(inputs[0].id).not.toBe(inputs[1].id);
  for (const dialog of dialogs) {
    expect(within(dialog).getByRole('textbox', { name: 'Email' })).toHaveAccessibleDescription("We'll send our reply to this address.");
    expect(within(dialog).getByRole('textbox', { name: 'Email' })).toHaveAttribute('maxlength', '320');
    expect(within(dialog).getByRole('textbox', { name: 'Subject' })).toHaveAttribute('maxlength', '200');
    expect(within(dialog).getByRole('textbox', { name: 'Description' })).toHaveAttribute('maxlength', '4000');
    expect(within(dialog).getByRole('textbox', { name: 'Description' })).toHaveAccessibleDescription(/4,000 characters/);
  }
  await userEvent.click(within(dialogs[0]).getByRole('button', { name: 'Cancel' }));
  expect(window.confirm).not.toHaveBeenCalled();
  expect(close).toHaveBeenCalledOnce();
});

it('locks submission and dismissal while sending, then preserves a failed draft for retry', async () => {
  const pending = deferred<ReturnType<typeof supportRequest>>();
  vi.mocked(createSupportRequest).mockReturnValueOnce(pending.promise);
  const onClose = vi.fn();
  const onSuccess = vi.fn();
  const { rerender } = render(<SupportModal isOpen userEmail="reader@example.com" onClose={onClose} onSuccess={onSuccess} />);
  fillDraft();
  fireEvent.submit(screen.getByRole('form'));
  fireEvent.submit(screen.getByRole('form'));
  expect(createSupportRequest).toHaveBeenCalledOnce();
  expect(screen.getByRole('form')).toHaveAttribute('aria-busy', 'true');
  for (const input of screen.getAllByRole('textbox')) expect(input).toBeDisabled();
  for (const button of screen.getAllByRole('button')) expect(button).toBeDisabled();
  fireEvent(screen.getByRole('dialog'), new Event('cancel', { cancelable: true }));
  fireEvent.click(screen.getByRole('dialog'));
  expect(onClose).not.toHaveBeenCalled();
  await act(async () => pending.reject(new Error('Service unavailable')));
  expect(screen.getByRole('alert')).toHaveTextContent('Service unavailable');
  expect(screen.getByRole('textbox', { name: 'Subject' })).toHaveValue(' Help ');
  expect(onSuccess).not.toHaveBeenCalled();
  await userEvent.click(screen.getByRole('button', { name: 'Submit Request' }));
  expect(screen.getByRole('status')).toHaveTextContent('Settings under Support Requests');
  expect(screen.getByRole('dialog')).toHaveAccessibleName('Request Submitted');
  expect(onSuccess).toHaveBeenCalledOnce();
  const replacement = vi.fn();
  rerender(<SupportModal isOpen userEmail="reader@example.com" onClose={onClose} onSuccess={replacement} />);
  expect(replacement).not.toHaveBeenCalled();
  await userEvent.click(screen.getAllByRole('button', { name: 'Close' })[1]);
  expect(onClose).toHaveBeenCalledOnce();
  expect(window.confirm).not.toHaveBeenCalled();
});

it.each(['Cancel', 'Close', 'Escape', 'Backdrop'])('preserves a dirty draft when %s dismissal is declined', async action => {
  const onClose = vi.fn();
  render(<SupportModal isOpen onClose={onClose} userEmail="reader@example.com" />);
  fillDraft();
  vi.mocked(window.confirm).mockReturnValue(false);
  const dismiss = () => {
    if (action === 'Escape') fireEvent(screen.getByRole('dialog'), new Event('cancel', { cancelable: true }));
    else if (action === 'Backdrop') fireEvent.click(screen.getByRole('dialog'));
    else fireEvent.click(screen.getByRole('button', { name: action }));
  };
  dismiss();
  expect(window.confirm).toHaveBeenLastCalledWith('Discard your unsent support request?');
  expect(onClose).not.toHaveBeenCalled();
  expect(screen.getByRole('textbox', { name: 'Description' })).toHaveValue(' Details ');
  vi.mocked(window.confirm).mockReturnValue(true);
  dismiss();
  expect(onClose).toHaveBeenCalledOnce();
});

it.each(['close', 'identity'])('starts a fresh composer after %s and ignores an old submission completion', async change => {
  const pending = deferred<ReturnType<typeof supportRequest>>();
  vi.mocked(createSupportRequest).mockReturnValueOnce(pending.promise);
  const props = { isOpen: true, onClose: vi.fn(), onSuccess: vi.fn(), userEmail: 'first@example.com' };
  const { rerender } = render(<SupportModal {...props} />);
  fillDraft();
  fireEvent.submit(screen.getByRole('form'));
  if (change === 'close') {
    rerender(<SupportModal {...props} isOpen={false} />);
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    rerender(<SupportModal {...props} />);
  } else rerender(<SupportModal {...props} userEmail="second@example.com" />);
  expect(screen.getByRole('textbox', { name: 'Subject' })).toHaveValue('');
  await act(async () => pending.resolve(supportRequest()));
  expect(props.onSuccess).not.toHaveBeenCalled();
  expect(screen.queryByRole('status')).not.toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Submit Request' })).toBeEnabled();
});

it('normalizes an anonymous request and announces where the reply will arrive', async () => {
  render(<SupportModal isOpen onClose={vi.fn()} />);
  fillDraft();
  fireEvent.change(screen.getByRole('textbox', { name: 'Email' }), { target: { value: 'reader@example.com' } });
  await userEvent.click(screen.getByRole('button', { name: 'Submit Request' }));
  expect(createSupportRequest).toHaveBeenCalledExactlyOnceWith({ subject: 'Help', description: 'Details', email: 'reader@example.com' });
  expect(screen.getByRole('status')).toHaveTextContent("We'll respond to the email address you provided.");
});

it('reports programmatic validation failures without sending an empty request', async () => {
  render(<SupportModal isOpen onClose={vi.fn()} />);
  fireEvent.submit(screen.getByRole('form'));
  expect(await screen.findByRole('alert')).toHaveTextContent('Enter a subject');
  expect(createSupportRequest).not.toHaveBeenCalled();
});
