import { beforeEach, describe, expect, it, vi } from 'vitest';
import { act, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter, Route, Routes, useNavigate } from 'react-router-dom';
import PublicLayout from '../../src/components/public/PublicLayout';
import { publicApi } from '../../src/api';
import { deferred } from '../testUtils/deferred';

const userState = vi.hoisted(() => ({ user: null as { id: number } | null, loading: false }));
vi.mock('../../src/contexts/useUser', () => ({ useUser: () => userState }));
vi.mock('../../src/api', () => ({ publicApi: { getWorkspace: vi.fn() } }));

function Navigation() {
  const navigate = useNavigate();
  return <button onClick={() => navigate('/public/other')}>Other workspace</button>;
}

function Page({ initial = '/public/library' }: { initial?: string }) {
  return <MemoryRouter initialEntries={[initial]}>
    <Navigation />
    <Routes>
      <Route path="/public/:slug?" element={<PublicLayout />}>
        <Route index element={<p>Collection content</p>} />
      </Route>
    </Routes>
  </MemoryRouter>;
}

beforeEach(() => {
  vi.clearAllMocks();
  userState.user = null;
  userState.loading = false;
  vi.mocked(publicApi.getWorkspace).mockResolvedValue({ name: 'Library', slug: 'library' });
});

describe('Public workspace layout', () => {
  it('uses shared loading states and cancels requests when leaving the layout', async () => {
    const pending = deferred<Awaited<ReturnType<typeof publicApi.getWorkspace>>>();
    vi.mocked(publicApi.getWorkspace).mockReturnValue(pending.promise);
    const { unmount } = render(<Page />);
    expect(screen.getByRole('status')).toHaveTextContent('Loading workspace');
    const signal = vi.mocked(publicApi.getWorkspace).mock.calls[0][1]!.signal!;
    expect(signal.aborted).toBe(false);

    await act(async () => pending.resolve({ name: 'Library', slug: 'library' }));
    expect(screen.getByRole('link', { name: 'Library' })).toHaveAttribute('href', '/public/library');
    expect(screen.getByRole('main')).toHaveTextContent('Collection content');
    expect(screen.getByRole('link', { name: 'Sign in' })).toHaveAttribute('href', '/signin');
    unmount();
    expect(signal.aborted).toBe(true);
  });

  it('updates account navigation after user loading completes', async () => {
    userState.loading = true;
    const { rerender } = render(<Page />);
    await screen.findByRole('link', { name: 'Library' });
    expect(screen.queryByRole('link', { name: 'Sign in' })).not.toBeInTheDocument();
    userState.loading = false;
    userState.user = { id: 1 };
    rerender(<Page />);
    expect(screen.getByRole('link', { name: 'My Collections' })).toHaveAttribute('href', '/collections');
  });

  it('reports request errors in an accessible state', async () => {
    vi.mocked(publicApi.getWorkspace).mockRejectedValue(new Error('No connection'));
    render(<Page />);
    expect(await screen.findByRole('alert')).toHaveTextContent('No connection');
  });

  it('handles a missing slug without sending a request', () => {
    render(<Page initial="/public" />);
    expect(screen.getByRole('alert')).toHaveTextContent("This workspace doesn't exist");
    expect(publicApi.getWorkspace).not.toHaveBeenCalled();
  });

  it('cancels a previous workspace request when navigating', async () => {
    const first = deferred<Awaited<ReturnType<typeof publicApi.getWorkspace>>>();
    vi.mocked(publicApi.getWorkspace).mockReturnValueOnce(first.promise)
      .mockResolvedValueOnce({ name: 'Other collection', slug: 'other' });
    render(<Page />);
    const previousSignal = vi.mocked(publicApi.getWorkspace).mock.calls[0][1]!.signal!;
    await userEvent.click(screen.getByRole('button', { name: 'Other workspace' }));
    await waitFor(() => expect(screen.getByRole('link', { name: 'Other collection' })).toHaveAttribute('href', '/public/other'));
    expect(previousSignal.aborted).toBe(true);
    await act(async () => first.resolve({ name: 'Old library', slug: 'library' }));
    expect(screen.queryByText('Old library')).not.toBeInTheDocument();
  });
});
