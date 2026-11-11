import { act, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { expect, it, vi } from 'vitest';
import { DashboardSection } from '../src/components/settings/DashboardSection';
import type { DashboardData, dashboardApi } from '../src/api/dashboard';
import { deferred } from './testUtils/deferred';

const data: DashboardData = {
  collectionCount: 3, itemCount: 25, imageCount: 8, imageTotalSizeBytes: 1024 ** 4,
  dailyViews: [
    { date: '2026-11-08', viewCount: 0 },
    { date: '2026-11-09', viewCount: 1 },
    { date: '2026-11-10', viewCount: 4 },
  ],
};

it('shows statistics and dated, accessible view counts with proportional bars', async () => {
  const request = deferred<DashboardData>();
  const gateway = { get: vi.fn<typeof dashboardApi.get>().mockReturnValue(request.promise) };
  render(<DashboardSection gateway={gateway} />);
  expect(screen.getByRole('status')).toHaveTextContent('Loading workspace statistics');
  await act(async () => request.resolve(data));
  expect(screen.queryByRole('status')).not.toBeInTheDocument();
  const statistics = screen.getByLabelText('Workspace statistics');
  expect(within(statistics).getByText('Collections').nextElementSibling).toHaveTextContent('3');
  expect(within(statistics).getByText('Items').nextElementSibling).toHaveTextContent('25');
  expect(within(statistics).getByText('Images').nextElementSibling).toHaveTextContent('8');
  expect(within(statistics).getByText('1.0 TB stored')).toBeInTheDocument();
  const views = within(screen.getByRole('list', { name: 'Daily item views' }));
  for (const [date, count, height] of [['November 8, 2026', '0 views', '0%'], ['November 9, 2026', '1 view', '25%'], ['November 10, 2026', '4 views', '100%']]) {
    expect(views.getByRole('listitem', { name: `${date}: ${count}` }).querySelector('.dashboard-chart__bar')).toHaveStyle({ height });
  }
  expect(screen.getByText('Mon')).toHaveAttribute('datetime', '2026-11-09');
});

it('reports failed reads and lets the user retry without leaving settings', async () => {
  const user = userEvent.setup();
  const gateway = { get: vi.fn<typeof dashboardApi.get>().mockRejectedValueOnce(new Error('Connection lost')).mockResolvedValue(data) };
  render(<DashboardSection gateway={gateway} />);
  expect(await screen.findByRole('alert')).toHaveTextContent('Connection lost');
  expect(screen.queryByText('Loading workspace statistics...')).not.toBeInTheDocument();
  const firstSignal = gateway.get.mock.calls[0][0]!.signal!;
  await user.click(screen.getByRole('button', { name: 'Try again' }));
  expect(await screen.findByText('1.0 TB stored')).toBeInTheDocument();
  expect(firstSignal.aborted).toBe(true);
  expect(screen.queryByRole('alert')).not.toBeInTheDocument();
});

it('distinguishes a new workspace with no history from a day with zero views', async () => {
  const gateway = { get: vi.fn<typeof dashboardApi.get>().mockResolvedValue({ ...data, dailyViews: [] }) };
  const { rerender } = render(<DashboardSection gateway={gateway} />);
  expect(await screen.findByText('No view history yet')).toBeInTheDocument();
  expect(screen.queryByRole('list')).not.toBeInTheDocument();
  const zeroGateway = { get: vi.fn<typeof dashboardApi.get>().mockResolvedValue({ ...data, dailyViews: [data.dailyViews[0]] }) };
  rerender(<DashboardSection gateway={zeroGateway} />);
  const zeroDay = await screen.findByRole('listitem', { name: 'November 8, 2026: 0 views' });
  expect(zeroDay.querySelector('.dashboard-chart__bar')).toHaveStyle({ height: '0%' });
  expect(screen.queryByText('No view history yet')).not.toBeInTheDocument();
});

it('cancels obsolete reads and never publishes a late response after changing gateways or leaving', async () => {
  const oldRequest = deferred<DashboardData>();
  const oldGateway = { get: vi.fn<typeof dashboardApi.get>().mockReturnValue(oldRequest.promise) };
  const newGateway = { get: vi.fn<typeof dashboardApi.get>().mockResolvedValue({ ...data, itemCount: 99 }) };
  const { rerender, unmount } = render(<DashboardSection gateway={oldGateway} />);
  rerender(<DashboardSection gateway={newGateway} />);
  await waitFor(() => expect(screen.getByText('99')).toBeInTheDocument());
  expect(oldGateway.get.mock.calls[0][0]!.signal!.aborted).toBe(true);
  await act(async () => oldRequest.resolve(data));
  expect(screen.getByText('99')).toBeInTheDocument();
  unmount();
  expect(newGateway.get.mock.calls[0][0]!.signal!.aborted).toBe(true);
});
