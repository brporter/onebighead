import { act, fireEvent, render, screen } from '@testing-library/react';
import { beforeEach, expect, it, vi } from 'vitest';
import type { ReactNode } from 'react';
import type { CollisionDetection, DragMoveEvent } from '@dnd-kit/core';
import CategoryManagerTree from '../src/components/category/CategoryManagerTree';
import { createMockCategory as category } from './testUtils';

const dnd = vi.hoisted(() => ({ handlers: {} as Record<string, unknown>, pointer: vi.fn(() => ['pointer']), keyboard: vi.fn(() => ['keyboard']), rootOver: false, dragging: false }));
vi.mock('@dnd-kit/core', () => ({
  DndContext: (props: Record<string, unknown> & { children: ReactNode }) => { dnd.handlers = props; return <>{props.children}</>; },
  DragOverlay: ({ children }: { children: ReactNode }) => <div data-testid="drag-preview">{children}</div>,
  PointerSensor: vi.fn(), KeyboardSensor: vi.fn(), useSensor: vi.fn(), useSensors: vi.fn(),
  MeasuringStrategy: { Always: 'always' }, pointerWithin: dnd.pointer, closestCenter: dnd.keyboard,
  useDroppable: () => ({ setNodeRef: vi.fn(), isOver: dnd.rootOver }),
}));
vi.mock('@dnd-kit/sortable', () => ({
  SortableContext: ({ children }: { children: ReactNode }) => children,
  sortableKeyboardCoordinates: vi.fn(),
  useSortable: ({ disabled, animateLayoutChanges }: { disabled: boolean; animateLayoutChanges: () => boolean }) => ({
    attributes: { role: 'button', tabIndex: disabled ? -1 : 0, 'aria-disabled': disabled },
    listeners: {}, setNodeRef: vi.fn(), isDragging: dnd.dragging && !animateLayoutChanges(),
  }),
}));

const categories = [category({ categoryId: 1, name: 'Books', sortOrder: 0, parentCategoryId: null }),
  category({ categoryId: 2, name: 'Cameras', sortOrder: 1, parentCategoryId: null }),
  category({ categoryId: 3, name: 'Film', sortOrder: 0, parentCategoryId: 2 }),
  category({ categoryId: 4, name: 'System', isSystem: true })];
const onReorder = vi.fn();
const onReparent = vi.fn();
const props = { categories, onReorder, onReparent, onEditCategory: vi.fn(), onAdd: vi.fn() };
const event = (active: number, target: number | string | null, y = 50, keyboard = false, delta = 0): DragMoveEvent => ({
  active: { id: String(active), data: { current: {} }, rect: { current: { initial: null, translated: null } } },
  over: target === null ? null : { id: String(target), rect: new DOMRect(0, 0, 100, 100), disabled: false, data: { current: {} } },
  activatorEvent: keyboard ? new KeyboardEvent('keydown', { key: 'ArrowDown' }) : new MouseEvent('pointerdown', { clientY: y }),
  delta: { x: 0, y: delta }, collisions: null,
});
function dispatch(name: string, input?: DragMoveEvent) { act(() => (dnd.handlers[name] as (value?: DragMoveEvent) => void)(input)); }
beforeEach(() => { vi.clearAllMocks(); dnd.rootOver = false; dnd.dragging = false; });

it('previews pointer nesting and uses the final geometry when committing the move', () => {
  dnd.dragging = true;
  const { container } = render(<CategoryManagerTree {...props} />);
  expect(screen.getByRole('button', { name: 'Move Books' })).toBeInTheDocument();
  dispatch('onDragStart', event(1, null));
  expect(screen.getByTestId('drag-preview')).toHaveTextContent('Books');
  dispatch('onDragMove', event(1, 2));
  expect(container.querySelector('[data-category-id="2"]')).toHaveClass('catTree__row--dropTarget');
  dispatch('onDragEnd', event(1, 2));
  expect(onReparent).toHaveBeenCalledExactlyOnceWith(1, 2, undefined, undefined);
  expect(screen.getByTestId('drag-preview')).toBeEmptyDOMElement();
});

it('supports keyboard sibling ordering in both directions and keyboard promotion to root', () => {
  const { container } = render(<CategoryManagerTree {...props} />);
  dispatch('onDragStart', event(1, null, 0, true));
  dispatch('onDragOver', event(1, 2, 0, true, 10));
  expect(container.querySelector('[data-category-id="2"]')).toHaveClass('catTree__row--insertAfter');
  dispatch('onDragEnd', event(1, 2, 0, true, 10));
  expect(onReorder).toHaveBeenCalledWith([{ categoryId: 2, sortOrder: 0 }, { categoryId: 1, sortOrder: 1 }]);
  dispatch('onDragStart', event(2, null, 0, true));
  dispatch('onDragMove', event(2, 1, 0, true, -10));
  expect(container.querySelector('[data-category-id="1"]')).toHaveClass('catTree__row--insertBefore');
  dispatch('onDragEnd', event(2, 1, 0, true, -10));
  expect(onReorder).toHaveBeenCalledTimes(2);
  dispatch('onDragStart', event(3, null, 0, true));
  dispatch('onDragEnd', event(3, 'root-drop-zone', 0, true, -10));
  expect(onReparent).toHaveBeenCalledExactlyOnceWith(3, null, undefined, undefined);
});

it('clears invalid targets and cancelled drags without applying mutations', () => {
  const { container } = render(<CategoryManagerTree {...props} />);
  dispatch('onDragStart', event(1, null));
  dispatch('onDragMove', event(1, 2));
  dispatch('onDragMove', event(1, null));
  expect(container.querySelector('.catTree__row--dropTarget')).not.toBeInTheDocument();
  dispatch('onDragMove', event(1, 1));
  dispatch('onDragCancel');
  expect(screen.getByTestId('drag-preview')).toBeEmptyDOMElement();
  dispatch('onDragEnd', event(1, null));
  dispatch('onDragStart', event(99, null));
  dispatch('onDragEnd', event(99, 2));
  const unsupported = { ...event(1, 2), activatorEvent: new Event('unknown') };
  dispatch('onDragMove', unsupported);
  dispatch('onDragEnd', unsupported);
  expect(onReorder).not.toHaveBeenCalled();
  expect(onReparent).not.toHaveBeenCalled();
});

it('disables editing and drag mutations while pending, including a drag already in progress', () => {
  const { rerender } = render(<CategoryManagerTree {...props} />);
  dispatch('onDragStart', event(1, null));
  rerender(<CategoryManagerTree {...props} disabled />);
  expect(screen.getByRole('button', { name: 'Add category' })).toBeDisabled();
  expect(screen.getByRole('button', { name: 'Cameras' })).toBeDisabled();
  expect(screen.getByRole('button', { name: 'Move Books' })).toHaveAttribute('aria-disabled', 'true');
  fireEvent.click(screen.getByRole('button', { name: 'Cameras' }));
  dispatch('onDragStart', event(2, null));
  dispatch('onDragEnd', event(1, 2));
  expect(props.onEditCategory).not.toHaveBeenCalled();
  expect(onReparent).not.toHaveBeenCalled();
});

it('selects keyboard collision detection when there are no pointer coordinates', () => {
  render(<CategoryManagerTree {...props} />);
  const detect = dnd.handlers.collisionDetection as CollisionDetection;
  const pointer = { pointerCoordinates: { x: 1, y: 2 } } as Parameters<CollisionDetection>[0];
  const keyboard = { pointerCoordinates: null } as Parameters<CollisionDetection>[0];
  expect(detect(pointer)).toEqual(['pointer']);
  expect(detect(keyboard)).toEqual(['keyboard']);
  expect(dnd.pointer).toHaveBeenCalledWith(pointer);
  expect(dnd.keyboard).toHaveBeenCalledWith(keyboard);
});
