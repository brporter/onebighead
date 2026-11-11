import { beforeEach, afterEach, describe, expect, it, vi } from 'vitest';
import { act, fireEvent, render, screen } from '@testing-library/react';
import { BulkUpdateModal } from '../src/components/common/BulkUpdateModal';
import { bulkUpdatesApi } from '../src/api/bulkUpdates';
import { deferred } from './testUtils/deferred';

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

  it('does not render a closed dialog and resets the workflow on reopen', async () => {
    const p = props();
    const options = [
      { scope: 'Category', categoryId: 2, count: 1, label: 'in this category' },
      { scope: 'Collection', collectionId: 1, count: 2, label: 'in this collection' },
    ];
    const { rerender } = render(<BulkUpdateModal {...p} isOpen={false} scopeOptions={options} />);
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    rerender(<BulkUpdateModal {...p} scopeOptions={options} />);
    expect(screen.getByLabelText('1 item in this category')).toBeChecked();
    fireEvent.click(screen.getByLabelText('2 items in this collection'));
    expect(screen.getByLabelText('2 items in this collection')).toBeChecked();
    rerender(<BulkUpdateModal {...p} isOpen={false} scopeOptions={options} />);
    rerender(<BulkUpdateModal {...p} scopeOptions={options} />);
    expect(screen.getByLabelText('1 item in this category')).toBeChecked();
  });

  it('submits the selected scope and property mapping exactly once', async () => {
    const p = props();
    const oldProperties = [{ category: 'Book', name: 'Name' }];
    const newProperties = [{ category: 'Book', name: 'Title' }];
    const renameMappings = [{ oldCategory: 'Book', oldName: 'Name', newCategory: 'Book', newName: 'Title' }];
    render(<BulkUpdateModal {...p} oldProperties={oldProperties} newProperties={newProperties} renameMappings={renameMappings}
      excludeItemId={3} scopeOptions={[{ scope: 'Template', templateKey: 'book', count: 1, label: 'using this template' }, ...p.scopeOptions]} />);
    fireEvent.click(screen.getByLabelText('1 item using this template'));
    await act(async () => fireEvent.click(screen.getByRole('button', { name: 'Apply' })));
    expect(bulkUpdatesApi.enqueue).toHaveBeenCalledExactlyOnceWith({
      scope: 'Template', templateKey: 'book', categoryId: undefined, collectionId: undefined, excludeItemId: 3,
      oldProperties, newProperties, renameMappings,
    }, { signal: expect.any(AbortSignal) });
  });

  it.each([{ scopeOptions: [] }, { scopeOptions: [{ scope: 'Collection', collectionId: 1, count: 0, label: 'in this collection' }] }])('disables submission when no items are eligible (%s)', ({ scopeOptions }) => {
    render(<BulkUpdateModal {...props()} scopeOptions={scopeOptions} />);
    const button = screen.getByRole('button', { name: scopeOptions.length ? 'Apply to All' : 'Apply' });
    expect(button).toBeDisabled();
    fireEvent.click(button);
    expect(bulkUpdatesApi.enqueue).not.toHaveBeenCalled();
  });

  it('prevents duplicate submission and dismissal while the initial request is pending', async () => {
    const pending = deferred<typeof job>();
    vi.mocked(bulkUpdatesApi.enqueue).mockReturnValue(pending.promise);
    const p = props();
    const { unmount } = render(<BulkUpdateModal {...p} />);
    fireEvent.click(screen.getByRole('button', { name: 'Apply to All' }));
    expect(screen.getByRole('button', { name: 'Starting update…' })).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Skip' })).toBeDisabled();
    fireEvent.click(screen.getByRole('button', { name: 'Starting update…' }));
    fireEvent(screen.getByRole('dialog'), new Event('cancel', { cancelable: true }));
    expect(bulkUpdatesApi.enqueue).toHaveBeenCalledOnce();
    expect(p.onClose).not.toHaveBeenCalled();
    const signal = vi.mocked(bulkUpdatesApi.enqueue).mock.calls[0][1]!.signal!;
    unmount();
    expect(signal.aborted).toBe(true);
    await act(async () => pending.resolve(job));
  });

  it('reports enqueue errors and lets the user dismiss the prompt', async () => {
    vi.mocked(bulkUpdatesApi.enqueue).mockRejectedValue(new Error('Queue unavailable'));
    const p = props();
    render(<BulkUpdateModal {...p} />);
    await act(async () => fireEvent.click(screen.getByRole('button', { name: 'Apply to All' })));
    expect(screen.getByRole('alert')).toHaveTextContent('Queue unavailable');
    fireEvent.click(screen.getByRole('button', { name: 'Close bulk update' }));
    expect(p.onClose).toHaveBeenCalledOnce();
    expect(p.onComplete).not.toHaveBeenCalled();
  });

  it('allows status checks to resume after a polling error', async () => {
    vi.mocked(bulkUpdatesApi.getStatus).mockRejectedValueOnce(new Error('Disconnected'))
      .mockResolvedValueOnce({ ...job, status: 'Completed' });
    render(<BulkUpdateModal {...props()} />);
    await act(async () => fireEvent.click(screen.getByRole('button', { name: 'Apply to All' })));
    await act(async () => vi.advanceTimersByTimeAsync(500));
    expect(screen.getByRole('heading')).toHaveTextContent('Update status unavailable');
    fireEvent.click(screen.getByRole('button', { name: 'Check again' }));
    expect(screen.getByRole('heading')).toHaveTextContent('Updating Items');
    await act(async () => vi.advanceTimersByTimeAsync(500));
    expect(screen.getByRole('heading')).toHaveTextContent('Update complete');
  });

  it('handles immediate failure and an omitted completion callback', async () => {
    vi.mocked(bulkUpdatesApi.enqueue).mockResolvedValue({ ...job, status: 'Failed', errorMessage: 'Invalid property' });
    const p = props();
    render(<BulkUpdateModal {...p} onComplete={undefined} scopeOptions={[{ ...p.scopeOptions[0], count: 1 }]} />);
    expect(screen.getByText('1 item in this collection')).toBeInTheDocument();
    await act(async () => fireEvent.click(screen.getByRole('button', { name: 'Apply to All' })));
    expect(screen.getByRole('heading')).toHaveTextContent('Update failed');
    expect(screen.getByRole('alert')).toHaveTextContent('Invalid property');
    fireEvent.click(screen.getByRole('button', { name: 'Close' }));
    expect(p.onClose).toHaveBeenCalledOnce();
  });
});
