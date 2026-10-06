import { beforeEach, afterEach, describe, expect, it, vi } from 'vitest';
import { act, fireEvent, render, screen } from '@testing-library/react';
import { BulkUpdateModal } from '../src/components/common/BulkUpdateModal';
import { bulkUpdatesApi } from '../src/api/bulkUpdates';

vi.mock('../src/api/bulkUpdates', () => ({ bulkUpdatesApi: { enqueue: vi.fn(), getStatus: vi.fn() } }));
const job = { jobId: 'job', status: 'Running', totalItems: 4, processedItems: 1, failedItems: 1 };
const props = () => ({ isOpen: true, onClose: vi.fn(), onComplete: vi.fn(), scopeOptions: [{ scope: 'Collection', collectionId: 1, count: 4, label: 'in this collection' }], oldProperties: [], newProperties: [] });

describe('BulkUpdateModal', () => {
  beforeEach(() => { vi.useFakeTimers(); vi.clearAllMocks(); vi.mocked(bulkUpdatesApi.enqueue).mockResolvedValue(job); });
  afterEach(() => vi.useRealTimers());

  it('shows native progress and prevents dismissal until the job completes', async () => {
    const p = props();
    render(<BulkUpdateModal {...p} />);
    await act(async () => {});
    await act(async () => fireEvent.click(screen.getByRole('button', { name: 'Apply to All' })));
    expect(screen.getByRole('progressbar')).toHaveAttribute('max', '4');
    expect(screen.getByRole('progressbar')).toHaveAttribute('value', '2');
    const dialog = screen.getByRole('dialog');
    fireEvent(dialog, new Event('cancel', { cancelable: true }));
    fireEvent.click(dialog);
    expect(p.onClose).not.toHaveBeenCalled();
    vi.mocked(bulkUpdatesApi.getStatus).mockResolvedValue({ ...job, status: 'Completed', processedItems: 3 });
    await act(async () => vi.advanceTimersByTimeAsync(500));
    expect(screen.getByText('Updated 3 items. (1 skipped)')).toBeInTheDocument();
    fireEvent(dialog, new Event('cancel', { cancelable: true }));
    expect(p.onComplete).toHaveBeenCalledOnce();
    expect(p.onClose).toHaveBeenCalledOnce();
  });

  it('uses indeterminate progress before the item count is known', async () => {
    vi.mocked(bulkUpdatesApi.enqueue).mockResolvedValue({ ...job, totalItems: 0 });
    render(<BulkUpdateModal {...props()} />);
    await act(async () => {});
    await act(async () => fireEvent.click(screen.getByRole('button', { name: 'Apply to All' })));
    expect(screen.getByRole('progressbar')).not.toHaveAttribute('value');
  });

  it('dismisses the prompt without reporting completion', async () => {
    const p = props();
    render(<BulkUpdateModal {...p} />);
    await act(async () => {});
    fireEvent.click(screen.getByRole('button', { name: 'Skip' }));
    expect(p.onClose).toHaveBeenCalledOnce();
    expect(p.onComplete).not.toHaveBeenCalled();
  });
});
