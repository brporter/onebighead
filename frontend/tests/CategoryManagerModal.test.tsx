import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, expect, it, vi } from 'vitest';
import type { ReactNode } from 'react';
import type { DragMoveEvent } from '@dnd-kit/core';
import CategoryManagerModal from '../src/components/category/CategoryManagerModal';
import { createMockCategory as category } from './testUtils';
import { deferred } from './testUtils/deferred';
import { Visibility } from '../src/utils/types';

const mocks = vi.hoisted(() => ({ data: {} as Record<string, unknown>, publish: vi.fn(), unpublish: vi.fn(), dnd: {} as Record<string, unknown> }));
vi.mock('../src/contexts/useData', async () => {
  const { mockDataHooks } = await import('./testUtils/mockDataHooks');
  return mockDataHooks({ useData: () => mocks.data });
});
vi.mock('../src/contexts/usePublish', () => ({ usePublish: () => ({ requestPublish: mocks.publish, requestUnpublish: mocks.unpublish }) }));
vi.mock('../src/components/category/CategoryTemplateSelector', () => ({ default: () => <p>Templates</p> }));
vi.mock('@dnd-kit/core', () => ({
  DndContext: (props: Record<string, unknown> & { children: ReactNode }) => { mocks.dnd = props; return props.children; },
  DragOverlay: ({ children }: { children: ReactNode }) => children,
  PointerSensor: vi.fn(), KeyboardSensor: vi.fn(), useSensor: vi.fn(), useSensors: vi.fn(),
  MeasuringStrategy: { Always: 'always' }, pointerWithin: vi.fn(), closestCenter: vi.fn(),
  useDroppable: () => ({ setNodeRef: vi.fn(), isOver: false }),
}));
vi.mock('@dnd-kit/sortable', () => ({
  SortableContext: ({ children }: { children: ReactNode }) => children,
  sortableKeyboardCoordinates: vi.fn(), useSortable: ({ disabled }: { disabled: boolean }) => ({
    attributes: { role: 'button', tabIndex: disabled ? -1 : 0, 'aria-disabled': disabled },
    listeners: {}, setNodeRef: vi.fn(), isDragging: false,
  }),
}));
const categories = [category({ categoryId: 1, collectionId: 1, name: 'Books', sortOrder: 0 }),
  category({ categoryId: 2, collectionId: 1, name: 'Cameras', sortOrder: 1, visibility: Visibility.Public }),
  category({ categoryId: 3, collectionId: 2, name: 'Other collection' })];
const load = vi.fn();
const create = vi.fn();
const update = vi.fn();
const remove = vi.fn();
const reorder = vi.fn();
const onClose = vi.fn();
const props = { collectionId: 1, isOpen: true, onClose };
const click = async (name: string) => userEvent.click(screen.getByRole('button', { name }));
const ready = () => screen.findByRole('button', { name: 'Add category' });
const edit = async () => { await ready(); await click('Books'); };
const changeName = (value: string) => fireEvent.change(screen.getByRole('textbox', { name: /Name/ }), { target: { value } });
function drop(y: number) {
  const event: DragMoveEvent = {
    active: { id: '1', data: { current: {} }, rect: { current: { initial: null, translated: null } } },
    over: { id: '2', rect: new DOMRect(0, 0, 100, 100), disabled: false, data: { current: {} } },
    activatorEvent: new MouseEvent('pointerdown', { clientY: y }), delta: { x: 0, y: 0 }, collisions: null,
  };
  act(() => (mocks.dnd.onDragEnd as (event: DragMoveEvent) => void)(event));
}

beforeEach(() => {
  vi.clearAllMocks();
  load.mockReset().mockResolvedValue(undefined);
  create.mockReset().mockResolvedValue(4);
  update.mockReset().mockResolvedValue(undefined);
  remove.mockReset().mockResolvedValue(undefined);
  reorder.mockReset().mockResolvedValue(undefined);
  mocks.data = { categories, loadCategoriesForCollection: load, addCategory: create, updateCategory: update, deleteCategory: remove, reorderCategories: reorder };
});

it('loads only when open, shows scoped categories, and aborts reads when the session closes', async () => {
  const { rerender } = render(<CategoryManagerModal {...props} isOpen={false} />);
  expect(load).not.toHaveBeenCalled();
  rerender(<CategoryManagerModal {...props} />);
  await ready();
  expect(load).toHaveBeenCalledWith(1, { signal: expect.any(AbortSignal), throwOnError: true });
  expect(screen.queryByText('Other collection')).not.toBeInTheDocument();
  expect(screen.queryByRole('form', { name: 'Category details' })).not.toBeInTheDocument();
  const signal = load.mock.calls[0][1].signal;
  rerender(<CategoryManagerModal {...props} isOpen={false} />);
  expect(signal.aborted).toBe(true);
});

it('shows read failures and retries without presenting stale categories as loaded', async () => {
  load.mockRejectedValueOnce(new Error('Offline'));
  render(<CategoryManagerModal {...props} />);
  expect(await screen.findByRole('alert')).toHaveTextContent('Offline');
  expect(screen.queryByRole('button', { name: 'Books' })).not.toBeInTheDocument();
  await click('Try again');
  await ready();
});

it('discards the actual draft, mounts only one panel, and distinguishes back from close', async () => {
  render(<CategoryManagerModal {...props} />);
  await edit();
  expect(screen.queryByRole('button', { name: 'Add category' })).not.toBeInTheDocument();
  const name = screen.getByRole('textbox', { name: /Name/ });
  expect(name).toHaveFocus();
  name.closest('.categoryManager__body')!.scrollTop = 250;
  changeName('Unsaved');
  await click('Cancel');
  await click('Keep Editing');
  expect(screen.getByRole('textbox', { name: /Name/ })).toHaveValue('Unsaved');
  await click('Cancel');
  fireEvent(screen.getByRole('dialog', { name: 'Discard Changes' }), new Event('cancel', { cancelable: true }));
  expect(screen.queryByRole('dialog', { name: 'Discard Changes' })).not.toBeInTheDocument();
  await click('Cancel');
  await click('Discard');
  const add = screen.getByRole('button', { name: 'Add category' });
  expect(add).toHaveFocus();
  expect(add.closest('.categoryManager__body')!.scrollTop).toBe(0);
  await edit();
  expect(screen.getByRole('textbox', { name: /Name/ })).toHaveValue('Books');
  await click('Close');
  expect(onClose).toHaveBeenCalledTimes(1);
});

it('closes after confirmed discard and resets state on collection changes and reopening', async () => {
  const { rerender } = render(<CategoryManagerModal {...props} />);
  await edit();
  changeName('Draft');
  await click('Close');
  await click('Discard');
  expect(onClose).toHaveBeenCalledOnce();
  rerender(<CategoryManagerModal {...props} collectionId={2} />);
  await screen.findByRole('button', { name: 'Other collection' });
  expect(screen.queryByRole('textbox')).not.toBeInTheDocument();
  rerender(<CategoryManagerModal {...props} isOpen={false} />);
  rerender(<CategoryManagerModal {...props} />);
  await edit();
  expect(screen.getByRole('textbox', { name: /Name/ })).toHaveValue('Books');
});

it('keeps failed edits editable and prevents duplicate submissions or dismissal during a write', async () => {
  update.mockRejectedValueOnce(new Error('Write failed'));
  render(<CategoryManagerModal {...props} />);
  await edit();
  changeName('Updated');
  await click('Save Changes');
  expect(await screen.findByRole('alert')).toHaveTextContent('Write failed');
  expect(screen.getByRole('textbox', { name: /Name/ })).toBeEnabled();
  const pending = deferred<void>();
  update.mockReturnValueOnce(pending.promise);
  changeName('Corrected');
  fireEvent.submit(screen.getByRole('form', { name: 'Category details' }));
  fireEvent.submit(screen.getByRole('form', { name: 'Category details' }));
  expect(screen.getByRole('textbox', { name: /Name/ })).toBeDisabled();
  fireEvent(screen.getByRole('dialog', { name: 'Category Manager' }), new Event('cancel', { cancelable: true }));
  expect(onClose).not.toHaveBeenCalled();
  expect(update).toHaveBeenCalledTimes(2);
  await act(async () => { pending.resolve(); });
  await ready();
  expect(update).toHaveBeenLastCalledWith(1, expect.objectContaining({ name: 'Corrected' }));
});

it('quick creates once and resumes the failed order step with the saved draft locked', async () => {
  reorder.mockRejectedValueOnce(new Error('Ordering failed'));
  render(<CategoryManagerModal {...props} />);
  await ready();
  await click('Add category');
  changeName('New category');
  await click('Save');
  expect(await screen.findByRole('alert')).toHaveTextContent('Your change was saved');
  expect(screen.getByRole('textbox', { name: 'Name' })).toHaveValue('New category');
  expect(screen.getByRole('textbox', { name: 'Name' })).toBeDisabled();
  await click('Finish saving');
  await ready();
  expect(create).toHaveBeenCalledTimes(1);
  expect(reorder).toHaveBeenCalledTimes(2);
});

it('retries a failed create, carries the name into details, and creates from the full form', async () => {
  create.mockRejectedValueOnce(new Error('Create failed'));
  render(<CategoryManagerModal {...props} />);
  await ready();
  await click('Add category');
  changeName('Quick');
  await click('Save');
  await screen.findByRole('alert');
  await click('Try again');
  await ready();
  expect(create).toHaveBeenCalledTimes(2);
  await click('Add category');
  changeName('Detailed');
  await click('More Details...');
  expect(screen.getByRole('textbox', { name: /Name/ })).toHaveValue('Detailed');
  await click('Create');
  await ready();
  expect(create).toHaveBeenLastCalledWith(expect.objectContaining({ collectionId: 1, name: 'Detailed' }));
});

it('allows cancelling an empty quick form and guards a dirty quick form', async () => {
  render(<CategoryManagerModal {...props} />);
  await ready();
  await click('Add category');
  await click('Cancel');
  await ready();
  await click('Add category');
  changeName('Draft');
  await click('Cancel');
  await click('Discard');
  await ready();
  await click('Add category');
  expect(screen.getByRole('textbox', { name: 'Name' })).toHaveValue('');
});

it('explains that leaving a partially saved operation does not undo it', async () => {
  load.mockResolvedValueOnce(undefined).mockRejectedValueOnce(new Error('Refresh failed'));
  render(<CategoryManagerModal {...props} />);
  await edit();
  changeName('Saved');
  await click('Save Changes');
  await screen.findByRole('alert');
  await click('Close');
  expect(screen.getByRole('dialog', { name: 'Leave saved changes' })).toHaveTextContent('Leaving will not undo them');
  await click('Keep Editing');
  await click('Close');
  await click('Leave');
  expect(onClose).toHaveBeenCalledOnce();
  expect(update).toHaveBeenCalledOnce();
});

it('deletes after confirmation and resumes refresh without deleting twice', async () => {
  render(<CategoryManagerModal {...props} />);
  await edit();
  await click('Delete');
  fireEvent(screen.getByRole('dialog', { name: 'Delete Category' }), new Event('cancel', { cancelable: true }));
  await click('Delete');
  await userEvent.click(within(screen.getByRole('dialog', { name: 'Delete Category' })).getByRole('button', { name: 'Cancel' }));
  await click('Delete');
  load.mockRejectedValueOnce(new Error('Reload failed'));
  await userEvent.click(within(screen.getByRole('dialog', { name: 'Delete Category' })).getByRole('button', { name: 'Delete' }));
  await screen.findByRole('alert');
  await click('Finish saving');
  await ready();
  expect(remove).toHaveBeenCalledExactlyOnceWith(1);
});

it('delegates publication and unpublication while preserving category editing', async () => {
  render(<CategoryManagerModal {...props} />);
  await edit();
  await click('Publish');
  expect(mocks.publish).toHaveBeenCalledWith([{ type: 'category', id: 1 }]);
  await click('← Back to Categories');
  await click('Cameras');
  await click('Unpublish');
  expect(mocks.unpublish).toHaveBeenCalledWith([{ type: 'category', id: 2 }]);
});

it.each([50, 95])('applies tree move intent at pointer position %s', async y => {
  render(<CategoryManagerModal {...props} />);
  await ready();
  drop(y);
  await waitFor(() => expect(reorder).toHaveBeenCalledTimes(1));
  await waitFor(() => expect(screen.queryByText('Saving category changes…')).not.toBeInTheDocument());
  if (y === 50) expect(update).toHaveBeenCalledWith(1, expect.objectContaining({ parentCategoryId: 2 }));
  else expect(update).not.toHaveBeenCalled();
});

it('closes directly from the category list', async () => {
  render(<CategoryManagerModal {...props} />);
  await ready();
  await userEvent.click(screen.getAllByRole('button', { name: 'Close' })[1]);
  expect(onClose).toHaveBeenCalledOnce();
});

it('starts a fresh draft after a failed tree reorder instead of retrying the old operation', async () => {
  reorder.mockRejectedValueOnce(new Error('Order failed'));
  render(<CategoryManagerModal {...props} />);
  await ready();
  drop(95);
  await screen.findByRole('alert');
  await click('Add category');
  expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  expect(screen.getAllByRole('button', { name: 'Close' })).toHaveLength(1);
  changeName('New draft');
  await click('Save');
  await ready();
  expect(create).toHaveBeenCalledOnce();
});
