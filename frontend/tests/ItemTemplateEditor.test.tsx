import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, expect, it, vi } from 'vitest';
import ItemTemplateEditor from '../src/components/template/ItemTemplateEditor';
import { TemplateCard } from '../src/components/template/TemplateCard';
import { useCollectionsData as useDataHook } from '../src/contexts/useData';
import { bulkUpdatesApi } from '../src/api/bulkUpdates';
import { createMockDataContextValue, createMockItemTemplate } from './testUtils/factories';
import { deferred } from './testUtils/deferred';
import type { ItemTemplate } from '../src/utils/types';

const useData = useDataHook as () => import('./testUtils/dataTypes').DataContextValue;

vi.mock('../src/contexts/useData', async () => {
  const { mockDataHooks } = await import('./testUtils/mockDataHooks');
  return mockDataHooks({ useData: vi.fn() });
});
vi.mock('../src/api/bulkUpdates', () => ({ bulkUpdatesApi: { preview: vi.fn(), enqueue: vi.fn(), getStatus: vi.fn() } }));

const book = createMockItemTemplate({ name: 'Book', properties: [{ category: 'Details', name: 'Author' }, { category: 'Details', name: 'Year' }] });
const film = createMockItemTemplate({ itemTemplateId: 2, name: 'Film', isSystem: true, description: '', properties: [] });
let data = createMockDataContextValue();
beforeEach(() => {
  vi.clearAllMocks();
  data = createMockDataContextValue({
    fetchItemTemplates: vi.fn().mockResolvedValue([book, film]),
    createItemTemplate: vi.fn().mockResolvedValue(book),
    updateItemTemplate: vi.fn().mockResolvedValue(book),
    deleteItemTemplate: vi.fn().mockResolvedValue(undefined),
  });
  vi.mocked(useData).mockReturnValue(data);
  vi.mocked(bulkUpdatesApi.preview).mockResolvedValue({ affectedItemCount: 0 });
  vi.spyOn(window, 'confirm').mockReturnValue(true);
});

async function editBook() {
  await userEvent.click(within(await screen.findByRole('article', { name: 'Book' })).getByRole('button', { name: 'Edit' }));
}

it('loads and filters the complete catalog locally with labeled controls and independent groups', async () => {
  const close = vi.fn();
  const { container } = render(<ItemTemplateEditor onClose={close} isFullPage />);
  expect(screen.getByRole('status')).toHaveTextContent('Loading templates');
  await screen.findByRole('region', { name: 'My Templates' });
  expect(screen.getByRole('region', { name: 'System Templates' })).toBeInTheDocument();
  expect(container.firstChild).toHaveClass('template-editor--fullpage');
  await userEvent.selectOptions(screen.getByLabelText('Show'), 'workspace');
  expect(screen.queryByRole('article', { name: 'Film' })).not.toBeInTheDocument();
  await userEvent.selectOptions(screen.getByLabelText('Show'), 'system');
  expect(screen.queryByRole('article', { name: 'Book' })).not.toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Customize' })).toBeInTheDocument();
  expect(screen.queryByRole('button', { name: 'Delete' })).not.toBeInTheDocument();
  expect(data.fetchItemTemplates).toHaveBeenCalledTimes(1);
  await userEvent.click(screen.getByRole('button', { name: 'Back' }));
  expect(close).toHaveBeenCalledOnce();
});

it('recovers from a catalog error and presents empty filters without a false loading state', async () => {
  vi.mocked(data.fetchItemTemplates).mockRejectedValueOnce(new Error('Offline')).mockResolvedValue([book]);
  render(<ItemTemplateEditor onClose={vi.fn()} />);
  expect(await screen.findByRole('alert')).toHaveTextContent('Offline');
  await userEvent.click(screen.getByRole('button', { name: 'Retry' }));
  await screen.findByRole('article', { name: 'Book' });
  await userEvent.selectOptions(screen.getByLabelText('Show'), 'system');
  expect(screen.getByRole('status')).toHaveTextContent('No templates to show');
});

it('creates a template, validates the draft, reports dirty state, and reloads after saving', async () => {
  const dirty = vi.fn();
  render(<ItemTemplateEditor onClose={vi.fn()} onStatusChange={dirty} />);
  await userEvent.click(screen.getByRole('button', { name: '+ New Template' }));
  expect(screen.getByRole('heading', { name: 'Create New Template' })).toBeInTheDocument();
  await userEvent.click(screen.getByRole('button', { name: 'Create Template' }));
  expect(await screen.findByRole('alert')).toHaveTextContent('Name is required');
  await userEvent.type(screen.getByRole('textbox', { name: 'Template Name' }), ' New book ');
  await userEvent.type(screen.getByLabelText('Description'), ' My books ');
  expect(dirty).toHaveBeenLastCalledWith({ dirty: true, pending: false });
  await userEvent.click(screen.getByRole('button', { name: '+ Add Property' }));
  await userEvent.type(screen.getByRole('textbox', { name: 'Property category' }), 'Details');
  await userEvent.type(screen.getByRole('textbox', { name: 'Property name' }), 'Author');
  await userEvent.click(screen.getByRole('button', { name: '+ Add Property' }));
  await userEvent.click(screen.getAllByRole('button', { name: 'Remove property' })[1]);
  await userEvent.click(screen.getByRole('button', { name: 'Create Template' }));
  await screen.findByRole('heading', { name: 'Item Templates' });
  expect(data.createItemTemplate).toHaveBeenCalledWith({ name: 'New book', description: 'My books', properties: [{ category: 'Details', name: 'Author' }] });
  expect(data.fetchItemTemplates).toHaveBeenCalledTimes(2);
  await waitFor(() => expect(dirty).toHaveBeenLastCalledWith({ dirty: false, pending: false }));
});

it('confirms dirty cancellation, resets discarded drafts, and cancels clean forms immediately', async () => {
  render(<ItemTemplateEditor onClose={vi.fn()} />);
  await userEvent.click(screen.getByRole('button', { name: '+ New Template' }));
  await userEvent.click(screen.getByRole('button', { name: 'Cancel' }));
  expect(window.confirm).not.toHaveBeenCalled();
  await editBook();
  fireEvent.change(screen.getByRole('textbox', { name: 'Template Name' }), { target: { value: 'Draft' } });
  vi.mocked(window.confirm).mockReturnValueOnce(false);
  await userEvent.click(screen.getByRole('button', { name: 'Cancel' }));
  expect(screen.getByRole('textbox', { name: 'Template Name' })).toHaveValue('Draft');
  await userEvent.click(screen.getByRole('button', { name: 'Cancel' }));
  await editBook();
  expect(screen.getByRole('textbox', { name: 'Template Name' })).toHaveValue('Book');
});

it('keeps failed saves editable and disables the whole draft during a single pending save', async () => {
  const pending = deferred<ItemTemplate>();
  vi.mocked(data.updateItemTemplate).mockReturnValueOnce(pending.promise);
  render(<ItemTemplateEditor onClose={vi.fn()} />);
  await editBook();
  const form = screen.getByRole('form', { name: 'Template definition' });
  fireEvent.submit(form);
  fireEvent.submit(form);
  expect(data.updateItemTemplate).toHaveBeenCalledTimes(1);
  expect(form).toHaveAttribute('aria-busy', 'true');
  expect(screen.getByRole('group', { name: 'Template details' })).toHaveAttribute('inert');
  expect(screen.getByRole('textbox', { name: 'Template Name' })).toBeDisabled();
  expect(screen.getByRole('button', { name: 'Cancel' })).toBeDisabled();
  expect(screen.getByRole('button', { name: 'Saving…' })).toBeDisabled();
  await act(async () => pending.reject(new Error('Save failed')));
  expect(await screen.findByRole('alert')).toHaveTextContent('Save failed');
  expect(screen.getByRole('textbox', { name: 'Template Name' })).toBeEnabled();
  await userEvent.click(screen.getByRole('button', { name: 'Save Changes' }));
  await screen.findByRole('heading', { name: 'Item Templates' });
});

it('customizes a system template through the copy-on-edit endpoint', async () => {
  const copy = { ...film, itemTemplateId: 3, isSystem: false };
  vi.mocked(data.updateItemTemplate).mockResolvedValue(copy);
  vi.mocked(data.fetchItemTemplates).mockResolvedValueOnce([film]).mockResolvedValue([copy]);
  render(<ItemTemplateEditor onClose={vi.fn()} />);
  await userEvent.click(await screen.findByRole('button', { name: 'Customize' }));
  expect(screen.getByRole('heading', { name: 'Customize: Film' })).toBeInTheDocument();
  expect(screen.getByText('Saving creates a custom copy for this workspace.')).toBeInTheDocument();
  await userEvent.click(screen.getByRole('button', { name: 'Save Custom Copy' }));
  expect(data.updateItemTemplate).toHaveBeenCalledWith(2, { name: 'Film', description: '', properties: [] });
  await screen.findByRole('button', { name: 'Edit' });
  expect(screen.queryByRole('button', { name: 'Customize' })).not.toBeInTheDocument();
});

it('keeps the saved result visible and retries a failed related-item check without resaving', async () => {
  const preview = deferred<{ affectedItemCount: number }>();
  vi.mocked(bulkUpdatesApi.preview).mockReturnValueOnce(preview.promise).mockResolvedValue({ affectedItemCount: 2 });
  const dirty = vi.fn();
  render(<ItemTemplateEditor onClose={vi.fn()} onStatusChange={dirty} />);
  await editBook();
  fireEvent.change(screen.getAllByRole('textbox', { name: 'Property name' })[0], { target: { value: 'Writer' } });
  await userEvent.click(screen.getByRole('button', { name: 'Save Changes' }));
  expect(await screen.findByText('Template saved')).toBeInTheDocument();
  expect(screen.getByText('Checking related items…')).toBeInTheDocument();
  expect(dirty).toHaveBeenLastCalledWith({ dirty: false, pending: false });
  await act(async () => preview.reject(new Error('Preview offline')));
  expect(await screen.findByRole('alert')).toHaveTextContent('Preview offline');
  await userEvent.click(screen.getByRole('button', { name: 'Retry check' }));
  const dialog = await screen.findByRole('dialog', { name: 'Bulk property update' });
  expect(dialog).toHaveTextContent('2 items created from this template');
  expect(data.updateItemTemplate).toHaveBeenCalledTimes(1);
  await userEvent.click(within(dialog).getByRole('button', { name: 'Skip' }));
  await screen.findByRole('heading', { name: 'Item Templates' });
});

it('allows returning to the library while a post-save preview is pending', async () => {
  const pending = deferred<{ affectedItemCount: number }>();
  vi.mocked(bulkUpdatesApi.preview).mockReturnValue(pending.promise);
  render(<ItemTemplateEditor onClose={vi.fn()} />);
  await editBook();
  await userEvent.click(screen.getAllByRole('button', { name: 'Remove property' })[0]);
  await userEvent.click(screen.getByRole('button', { name: 'Save Changes' }));
  await userEvent.click(await screen.findByRole('button', { name: 'Back to templates' }));
  const signal = vi.mocked(bulkUpdatesApi.preview).mock.calls[0][1]!.signal!;
  expect(signal.aborted).toBe(true);
  await act(async () => pending.resolve({ affectedItemCount: 3 }));
  expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
  expect(screen.getByRole('heading', { name: 'Item Templates' })).toBeInTheDocument();
});

it('confirms deletion, blocks repeated actions, and permits retry after an error', async () => {
  const pending = deferred<void>();
  const status = vi.fn();
  vi.mocked(data.deleteItemTemplate).mockReturnValueOnce(pending.promise);
  render(<ItemTemplateEditor onClose={vi.fn()} onStatusChange={status} />);
  const remove = await screen.findByRole('button', { name: 'Delete' });
  vi.mocked(window.confirm).mockReturnValueOnce(false);
  await userEvent.click(remove);
  expect(data.deleteItemTemplate).not.toHaveBeenCalled();
  await userEvent.click(remove);
  expect(remove).toBeDisabled();
  expect(screen.getByRole('button', { name: '+ New Template' })).toBeDisabled();
  expect(screen.getByText('Deleting template…')).toBeInTheDocument();
  expect(status).toHaveBeenLastCalledWith({ dirty: false, pending: true });
  await act(async () => pending.reject(new Error('Delete failed')));
  expect(await screen.findByRole('alert')).toHaveTextContent('Delete failed');
  expect(status).toHaveBeenLastCalledWith({ dirty: false, pending: false });
  vi.mocked(data.fetchItemTemplates).mockResolvedValue([film]);
  await userEvent.click(remove);
  await waitFor(() => expect(screen.queryByRole('article', { name: 'Book' })).not.toBeInTheDocument());
  expect(data.deleteItemTemplate).toHaveBeenLastCalledWith(book.itemTemplateId);
});

it('renders safe category names, consistent counts, bounded previews and disabled card actions', async () => {
  const edit = vi.fn();
  const remove = vi.fn();
  const properties = ['a', 'b', 'c', 'd'].map(name => ({ category: '__proto__', name }));
  properties.push(...['B', 'C', 'D'].map(category => ({ category, name: 'Field' })));
  const { rerender } = render(<TemplateCard template={{ ...book, properties }} disabled={false} onEdit={edit} onDelete={remove} />);
  expect(screen.getByText('__proto__')).toBeInTheDocument();
  expect(screen.getByText('a, b, c +1 more')).toBeInTheDocument();
  expect(screen.getByText('+1 more categories')).toBeInTheDocument();
  await userEvent.click(screen.getByRole('button', { name: 'Edit' }));
  await userEvent.click(screen.getByRole('button', { name: 'Delete' }));
  expect(edit).toHaveBeenCalledOnce();
  expect(remove).toHaveBeenCalledOnce();
  rerender(<TemplateCard template={{ ...book, properties: [properties[0]] }} disabled onEdit={edit} onDelete={remove} />);
  expect(screen.getByRole('article')).toHaveTextContent('1 property');
  expect(screen.getByRole('article')).toHaveTextContent('1 category');
  expect(screen.getByRole('button', { name: 'Edit' })).toBeDisabled();
});
