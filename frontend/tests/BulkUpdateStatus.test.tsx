import { expect, it, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { BulkUpdateStatus } from '../src/components/common/BulkUpdateStatus';
const job = { jobId: 'one', status: 'Running', totalItems: 3, processedItems: 1, failedItems: 1 };

it('renders nothing without an update', () => {
  const { container } = render(<BulkUpdateStatus job={null} error={null} onRetry={vi.fn()} />);
  expect(container).toBeEmptyDOMElement();
});

it.each(['Queued', 'Running'])('announces %s progress', status => {
  render(<BulkUpdateStatus job={{ ...job, status }} error={null} onRetry={vi.fn()} />);
  expect(screen.getByRole('status')).toHaveTextContent('2 / 3 items');
  expect(screen.getByRole('progressbar')).toHaveAttribute('value', '2');
  expect(screen.getByRole('progressbar')).toHaveAttribute('max', '3');
  expect(screen.queryByText(/\(queued\)/) !== null).toBe(status === 'Queued');
});

it('uses indeterminate progress while the total is unknown', () => {
  render(<BulkUpdateStatus job={{ ...job, totalItems: 0 }} error={null} onRetry={vi.fn()} />);
  expect(screen.getByRole('progressbar')).not.toHaveAttribute('value');
  expect(screen.getByRole('progressbar')).toHaveAttribute('max', '1');
});

it.each([
  [1, 0, 'Updated 1 item.'],
  [3, 1, 'Updated 3 items. (1 skipped)'],
])('announces completion with %s processed items', (processedItems, failedItems, message) => {
  render(<BulkUpdateStatus job={{ ...job, status: 'Completed', processedItems, failedItems }} error={null} onRetry={vi.fn()} />);
  expect(screen.getByRole('status')).toHaveTextContent(message);
});

it.each(['Invalid properties', undefined])('reports failed jobs (%s)', errorMessage => {
  render(<BulkUpdateStatus job={{ ...job, status: 'Failed', errorMessage }} error={null} onRetry={vi.fn()} />);
  expect(screen.getByRole('alert')).toHaveTextContent(errorMessage ?? 'Unable to complete the update.');
  expect(screen.getByRole('alert')).toHaveTextContent('Updated 1 of 3 items.');
});

it('omits unknown totals when failure occurs before items are selected', () => {
  render(<BulkUpdateStatus job={{ ...job, status: 'Failed', totalItems: 0, processedItems: 0 }} error={null} onRetry={vi.fn()} />);
  expect(screen.getByRole('alert')).toHaveTextContent('Unable to complete the update.');
  expect(screen.getByRole('alert')).not.toHaveTextContent('of 0 items');
});

it.each(['The update was interrupted.', undefined])('shows interrupted updates without claiming completion (%s)', errorMessage => {
  render(<BulkUpdateStatus job={{ ...job, status: 'Cancelled', errorMessage }} error={null} onRetry={vi.fn()} />);
  expect(screen.getByRole('alert')).toHaveTextContent('Item update interrupted');
  expect(screen.getByRole('alert')).toHaveTextContent(errorMessage ?? 'The update stopped before all items could be processed.');
  expect(screen.getByRole('alert')).toHaveTextContent('Updated 1 of 3 items. Review your items before starting another update.');
  expect(screen.queryByRole('progressbar')).not.toBeInTheDocument();
  expect(screen.queryByRole('button')).not.toBeInTheDocument();
});

it('offers a retry when the job status cannot be checked', async () => {
  const retry = vi.fn();
  render(<BulkUpdateStatus job={job} error="No connection" onRetry={retry} />);
  expect(screen.getByRole('alert')).toHaveTextContent('No connection');
  await userEvent.click(screen.getByRole('button', { name: 'Check again' }));
  expect(retry).toHaveBeenCalledOnce();
});
