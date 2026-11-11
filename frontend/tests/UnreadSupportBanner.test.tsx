import { act, render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter, useLocation } from 'react-router-dom';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { UnreadSupportBanner } from '../src/components/support/UnreadSupportBanner';
import { getUnreadSupportCount } from '../src/api';
import { deferred } from './testUtils/deferred';

const session = vi.hoisted(() => ({ user: null as { userId: number } | null }));
vi.mock('../src/contexts/useUser', () => ({ useUser: () => session }));
vi.mock('../src/api', () => ({ getUnreadSupportCount: vi.fn() }));
function Location() { const location = useLocation(); return <div aria-label="Location">{location.pathname}{location.search}</div>; }
function View({ onOpenSettings }: { onOpenSettings?: () => void }) {
  return <MemoryRouter><UnreadSupportBanner onOpenSettings={onOpenSettings} /><Location /></MemoryRouter>;
}
beforeEach(() => {
  session.user = { userId: 1 };
  sessionStorage.clear();
  vi.mocked(getUnreadSupportCount).mockReset().mockResolvedValue({ unreadCount: 1 });
});
afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals(); });

it('waits for a signed-in user, announces a singular reply, and navigates to support settings', async () => {
  session.user = null;
  const { rerender } = render(<View />);
  expect(getUnreadSupportCount).not.toHaveBeenCalled();
  session.user = { userId: 1 };
  rerender(<View />);
  expect(await screen.findByRole('status')).toHaveTextContent('You have 1 unread support reply.');
  expect(screen.getByRole('complementary', { name: 'Support replies' })).toBeInTheDocument();
  await userEvent.click(screen.getByRole('button', { name: 'View in Settings' }));
  expect(screen.getByLabelText('Location')).toHaveTextContent('/settings?section=support');
  expect(sessionStorage.getItem('supportBannerDismissed_1')).toBe('true');
  expect(screen.queryByRole('status')).not.toBeInTheDocument();
});

it('uses the supplied settings action and supports plural counts', async () => {
  vi.mocked(getUnreadSupportCount).mockResolvedValue({ unreadCount: 3 });
  const open = vi.fn();
  render(<View onOpenSettings={open} />);
  expect(await screen.findByRole('status')).toHaveTextContent('3 unread support replies');
  await userEvent.click(screen.getByRole('button', { name: 'View in Settings' }));
  expect(open).toHaveBeenCalledOnce();
  expect(screen.getByLabelText('Location')).toHaveTextContent('/');
});

it('loads another user independently of an existing dismissal and retains each preference', async () => {
  sessionStorage.setItem('supportBannerDismissed_1', 'true');
  const { rerender } = render(<View />);
  expect(getUnreadSupportCount).not.toHaveBeenCalled();
  session.user = { userId: 2 };
  rerender(<View />);
  await screen.findByRole('status');
  await userEvent.click(screen.getByRole('button', { name: 'Dismiss support notification' }));
  expect(sessionStorage.getItem('supportBannerDismissed_2')).toBe('true');
  session.user = { userId: 1 };
  rerender(<View />);
  expect(screen.queryByRole('status')).not.toBeInTheDocument();
  expect(getUnreadSupportCount).toHaveBeenCalledOnce();
});

it('clears visible counts immediately on identity change and ignores old results after logout', async () => {
  const next = deferred<{ unreadCount: number }>();
  const old = deferred<{ unreadCount: number }>();
  vi.mocked(getUnreadSupportCount).mockResolvedValueOnce({ unreadCount: 4 }).mockReturnValueOnce(old.promise).mockReturnValueOnce(next.promise);
  const { rerender, unmount } = render(<View />);
  expect(await screen.findByRole('status')).toHaveTextContent('4 unread');
  const firstSignal = vi.mocked(getUnreadSupportCount).mock.calls[0][0]!.signal!;
  session.user = { userId: 2 };
  rerender(<View />);
  expect(screen.queryByRole('status')).not.toBeInTheDocument();
  expect(firstSignal.aborted).toBe(true);
  const oldSignal = vi.mocked(getUnreadSupportCount).mock.calls[1][0]!.signal!;
  session.user = null;
  rerender(<View />);
  expect(oldSignal.aborted).toBe(true);
  session.user = { userId: 3 };
  rerender(<View />);
  await act(async () => next.resolve({ unreadCount: 2 }));
  await act(async () => old.resolve({ unreadCount: 99 }));
  expect(screen.getByRole('status')).toHaveTextContent('2 unread');
  const latestSignal = vi.mocked(getUnreadSupportCount).mock.calls[2][0]!.signal!;
  unmount();
  expect(latestSignal.aborted).toBe(true);
});

it.each([0, -1])('hides a nonpositive unread count (%s)', async unreadCount => {
  vi.mocked(getUnreadSupportCount).mockResolvedValue({ unreadCount });
  await act(async () => { render(<View />); });
  expect(screen.queryByRole('complementary')).not.toBeInTheDocument();
});

it('silently tolerates read failures without showing a stale notification', async () => {
  vi.mocked(getUnreadSupportCount).mockRejectedValue(new Error('Offline'));
  await act(async () => { render(<View />); });
  expect(screen.queryByRole('status')).not.toBeInTheDocument();
});

it('still displays and dismisses notifications when storage access is blocked', async () => {
  vi.stubGlobal('sessionStorage', {
    getItem: () => { throw new Error('Blocked'); },
    setItem: () => { throw new Error('Blocked'); },
  });
  render(<View />);
  await screen.findByRole('status');
  await userEvent.click(screen.getByRole('button', { name: 'Dismiss support notification' }));
  expect(screen.queryByRole('status')).not.toBeInTheDocument();
});
