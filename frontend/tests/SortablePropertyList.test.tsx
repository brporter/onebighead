import { useState, type ReactNode } from 'react';
import { act, fireEvent, render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, expect, it, vi } from 'vitest';
import type { DndContextProps, DragEndEvent, DragStartEvent } from '@dnd-kit/core';
import { SortablePropertyList, type BaseProperty, type FieldConfig } from '../src/components/common/SortablePropertyList';

const dnd = vi.hoisted(() => ({ props: {} as DndContextProps, dragging: false }));
vi.mock('@dnd-kit/core', async importOriginal => ({
  ...await importOriginal<typeof import('@dnd-kit/core')>(),
  DndContext: (props: DndContextProps) => { dnd.props = props; return props.children; },
  DragOverlay: ({ children }: { children: ReactNode }) => <div data-testid="overlay">{children}</div>,
}));
vi.mock('@dnd-kit/sortable', async importOriginal => ({
  ...await importOriginal<typeof import('@dnd-kit/sortable')>(),
  SortableContext: ({ children }: { children: ReactNode }) => children,
  useSortable: () => ({ attributes: {}, listeners: {}, setNodeRef: vi.fn(), transform: null, transition: undefined, isDragging: dnd.dragging }),
}));

const classes = { list: 'list', categoryHeader: 'category', row: 'row', rowDragging: 'dragging', rowOverlay: 'overlay', input: 'input', removeButton: 'remove' };
const fields: FieldConfig[] = [{ field: 'category', label: 'Category', placeholder: 'Category', className: 'category-input' }, { field: 'name', label: 'Name', placeholder: 'Name', datalistId: 'suggestions' }];
const initial = [{ id: 'a', category: 'Details', name: 'Author' }, { id: 'b', category: 'Details', name: 'Year' }];
beforeEach(() => { dnd.dragging = false; });

function Editor({ starting = initial, onBlur, onTab }: { starting?: BaseProperty[]; onBlur?: (id: string, field: keyof BaseProperty) => void; onTab?: (id: string) => void }) {
  const [properties, setProperties] = useState(starting);
  return <SortablePropertyList properties={properties} fields={fields} classNames={classes}
    onPropertiesChange={setProperties} onFieldChange={(id, field, value) => setProperties(previous => previous.map(property => property.id === id ? { ...property, [field]: value } : property))}
    onRemove={id => setProperties(previous => previous.filter(property => property.id !== id))} onFieldBlur={onBlur} onCategoryTab={onTab} />;
}

it('preserves input identity and typing when a changed category regroups a row on mouse blur', async () => {
  const blur = vi.fn();
  render(<Editor onBlur={blur} />);
  const category = screen.getAllByRole('textbox', { name: 'Category' })[0];
  const name = screen.getAllByRole('combobox', { name: 'Name' })[0];
  await userEvent.clear(category);
  await userEvent.type(category, 'Books');
  await userEvent.type(name, ' Last');
  expect(name).toBeInTheDocument();
  expect(name).toHaveFocus();
  expect(name).toHaveValue('Author Last');
  expect(screen.getByText('Books')).toBeInTheDocument();
  expect(blur).toHaveBeenCalledWith('a', 'category');
  expect(name).toHaveAttribute('list', 'suggestions');
  fireEvent.blur(name);
  expect(blur).toHaveBeenCalledWith('a', 'name');
});

it('restores forward tab focus within its own list and respects other keys and reverse tabbing', async () => {
  const tab = vi.fn();
  const { container } = render(<><div data-testid="first"><Editor onTab={tab} /></div><div data-testid="second"><Editor /></div></>);
  const second = within(screen.getByTestId('second'));
  const category = second.getAllByRole('textbox', { name: 'Category' })[0];
  fireEvent.change(category, { target: { value: '' } });
  fireEvent.keyDown(category, { key: 'ArrowLeft' });
  fireEvent.keyDown(category, { key: 'Tab', shiftKey: true });
  fireEvent.keyDown(category, { key: 'Tab' });
  fireEvent.blur(category);
  expect(second.getByDisplayValue('Author')).toHaveFocus();
  expect(tab).not.toHaveBeenCalled();
  const firstCategory = within(screen.getByTestId('first')).getAllByRole('textbox', { name: 'Category' })[0];
  fireEvent.keyDown(firstCategory, { key: 'Tab' });
  fireEvent.blur(firstCategory);
  expect(tab).toHaveBeenCalledWith('a');
  expect(container.querySelectorAll('.category-input')).toHaveLength(4);
});

it('cleans removed rows, maintains empty categories, and restores actual fields after drag reordering', async () => {
  const { container } = render(<Editor starting={[{ id: 'a', category: '', name: '' }, { id: 'b', category: '', name: 'Second' }]} />);
  act(() => dnd.props.onDragStart!({ active: { id: 'b' } } as DragStartEvent));
  expect(within(screen.getByTestId('overlay')).getByDisplayValue('Second')).toHaveAttribute('readonly');
  act(() => dnd.props.onDragEnd!({ active: { id: 'a' }, over: { id: 'b' } } as DragEndEvent));
  expect(container.querySelectorAll('.list [data-field="name"]')[0]).toHaveValue('Second');
  expect(container.querySelector('.list [data-field="category"]')).toHaveValue('');
  expect(screen.getByTestId('overlay')).toBeEmptyDOMElement();
  await userEvent.click(screen.getAllByRole('button', { name: 'Remove property' })[1]);
  expect(screen.getAllByRole('button', { name: 'Remove property' })).toHaveLength(1);
  expect(screen.getByText('Uncategorized')).toBeInTheDocument();
});

it('renders dragging state, handles cancellation and removed active rows, and retains named categories on reorder', () => {
  dnd.dragging = true;
  const change = vi.fn();
  const props = { properties: initial, fields, classNames: classes, onPropertiesChange: change, onFieldChange: vi.fn(), onRemove: vi.fn() };
  const { container, rerender } = render(<SortablePropertyList {...props} />);
  expect(container.querySelectorAll('.dragging')).toHaveLength(2);
  act(() => dnd.props.onDragStart!({ active: { id: 'a' } } as DragStartEvent));
  expect(screen.getByTestId('overlay')).not.toBeEmptyDOMElement();
  act(() => dnd.props.onDragCancel!({} as Parameters<NonNullable<DndContextProps['onDragCancel']>>[0]));
  expect(screen.getByTestId('overlay')).toBeEmptyDOMElement();
  act(() => dnd.props.onDragStart!({ active: { id: 'a' } } as DragStartEvent));
  rerender(<SortablePropertyList {...props} properties={[initial[1]]} />);
  expect(screen.getByTestId('overlay')).toBeEmptyDOMElement();
  rerender(<SortablePropertyList {...props} />);
  act(() => dnd.props.onDragEnd!({ active: { id: 'a' }, over: { id: 'b' } } as DragEndEvent));
  expect(change).toHaveBeenCalledWith([initial[1], initial[0]]);
});

it('permits field sets without a name input and without optional callbacks', () => {
  const { rerender } = render(<SortablePropertyList properties={initial} fields={[fields[0]]} classNames={classes}
    onPropertiesChange={vi.fn()} onFieldChange={vi.fn()} onRemove={vi.fn()} />);
  const category = screen.getAllByRole('textbox')[0];
  fireEvent.keyDown(category, { key: 'Tab' });
  fireEvent.blur(category);
  expect(screen.queryByRole('textbox', { name: 'Name' })).not.toBeInTheDocument();
  rerender(<SortablePropertyList properties={[]} fields={[fields[0]]} classNames={classes}
    onPropertiesChange={vi.fn()} onFieldChange={vi.fn()} onRemove={vi.fn()} />);
  expect(screen.queryByRole('textbox')).not.toBeInTheDocument();
});

it('does not erase an actual category named Uncategorized when reordering', () => {
  const properties = initial.map(property => ({ ...property, category: 'Uncategorized' }));
  const change = vi.fn();
  render(<SortablePropertyList properties={properties} fields={fields} classNames={classes}
    onPropertiesChange={change} onFieldChange={vi.fn()} onRemove={vi.fn()} />);
  act(() => dnd.props.onDragEnd!({ active: { id: 'a' }, over: { id: 'b' } } as DragEndEvent));
  expect(change).toHaveBeenCalledWith([properties[1], properties[0]]);
});
