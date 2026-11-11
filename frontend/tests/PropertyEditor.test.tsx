import { StrictMode, useState } from 'react';
import { act, fireEvent, render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, expect, it, vi } from 'vitest';
import type { DndContextProps, DragEndEvent } from '@dnd-kit/core';
import PropertyEditor from '../src/components/item/PropertyEditor';
import { createItemProperty, type ItemPropertyDraft } from '../src/data/items/itemDraft';

const dnd = vi.hoisted(() => ({ props: {} as DndContextProps }));
vi.mock('@dnd-kit/core', async importOriginal => ({
  ...await importOriginal<typeof import('@dnd-kit/core')>(),
  DndContext: (props: DndContextProps) => { dnd.props = props; return props.children; },
}));
const suggestions = vi.hoisted(() => ({
  propertyCategorySuggestions: ['General', 'Technical'], propertyNameSuggestions: ['Color', 'Size'],
  addLocalCategorySuggestion: vi.fn(), addLocalNameSuggestion: vi.fn(),
}));
vi.mock('../src/contexts/useData', () => ({ useSuggestionsData: () => suggestions }));
beforeEach(() => vi.clearAllMocks());

const initial = [
  { id: 'first', category: 'General', name: 'Color', value: 'Red' },
  { id: 'second', category: 'General', name: 'Size', value: 'Small' },
  { id: 'third', category: 'Technical', name: 'Voltage', value: '12V' },
];
function Editor({ starting = initial }: { starting?: ItemPropertyDraft[] }) {
  const [properties, setProperties] = useState(starting);
  return <PropertyEditor properties={properties} onChange={setProperties} />;
}

it('labels its section and fields and keeps suggestion lists separate across editor instances', () => {
  render(<><Editor /><Editor /></>);
  const sections = screen.getAllByRole('region', { name: 'Properties' });
  expect(sections).toHaveLength(2);
  const lists = new Set<string>();
  for (const section of sections) {
    expect(within(section).getByRole('heading', { name: 'Properties' })).toBeInTheDocument();
    for (const [label, expected] of [['Property category', ['General', 'Technical']], ['Property name', ['Color', 'Size']]] as const) {
      const inputs = within(section).getAllByRole('combobox', { name: label });
      const listId = inputs[0].getAttribute('list')!;
      lists.add(listId);
      expect(inputs.every(input => input.getAttribute('list') === listId)).toBe(true);
      expect([...document.getElementById(listId)!.querySelectorAll('option')].map(option => option.value)).toEqual(expected);
    }
    expect(within(section).getAllByRole('textbox', { name: 'Property value' })).toHaveLength(3);
    expect(within(section).getAllByRole('button', { name: 'Remove property' })).toHaveLength(3);
  }
  expect(lists.size).toBe(4);
});

it('adds independent rows and focuses the new category within the selected editor in StrictMode', async () => {
  render(<StrictMode><Editor starting={[]} /><Editor starting={[]} /></StrictMode>);
  const sections = screen.getAllByRole('region', { name: 'Properties' });
  const second = within(sections[1]);
  await userEvent.click(second.getByRole('button', { name: '+ Add Property' }));
  expect(second.getByRole('combobox', { name: 'Property category' })).toHaveFocus();
  const first = second.getByRole('combobox', { name: 'Property category' });
  await userEvent.click(second.getByRole('button', { name: '+ Add Property' }));
  const categories = second.getAllByRole('combobox', { name: 'Property category' });
  expect(categories[1]).toHaveFocus();
  expect(categories[1].getAttribute('data-property-id')).not.toBe(first.getAttribute('data-property-id'));
  expect(within(sections[0]).queryByRole('combobox')).not.toBeInTheDocument();
  expect(within(sections[0]).getByText(/No properties yet/)).toBeInTheDocument();
});

it('preserves the focused input and row identity during category regrouping and field editing', async () => {
  render(<Editor />);
  const category = screen.getAllByRole('combobox', { name: 'Property category' })[0];
  const name = screen.getByDisplayValue('Color');
  const value = screen.getByDisplayValue('Red');
  await userEvent.click(category);
  fireEvent.change(category, { target: { value: 'Appearance' } });
  await userEvent.type(name, ' finish');
  expect(name).toHaveValue('Color finish');
  expect(name).toHaveFocus();
  expect(name).toHaveAttribute('data-property-id', 'first');
  expect(screen.getByText('Appearance')).toBeInTheDocument();
  await userEvent.clear(value);
  await userEvent.type(value, 'Blue');
  expect(value).toHaveValue('Blue');
  expect(value).toHaveFocus();
  expect(initial[0]).toEqual({ id: 'first', category: 'General', name: 'Color', value: 'Red' });
});

it('records meaningful category and name suggestions only when those fields blur', () => {
  render(<Editor />);
  const category = screen.getAllByRole('combobox', { name: 'Property category' })[0];
  const name = screen.getByDisplayValue('Color');
  const value = screen.getByDisplayValue('Red');
  fireEvent.blur(category);
  fireEvent.blur(name);
  expect(suggestions.addLocalCategorySuggestion).toHaveBeenCalledWith('General');
  expect(suggestions.addLocalNameSuggestion).toHaveBeenCalledWith('Color');
  vi.clearAllMocks();
  fireEvent.change(category, { target: { value: '   ' } });
  fireEvent.change(name, { target: { value: '' } });
  fireEvent.blur(category);
  fireEvent.blur(name);
  fireEvent.blur(value);
  expect(suggestions.addLocalCategorySuggestion).not.toHaveBeenCalled();
  expect(suggestions.addLocalNameSuggestion).not.toHaveBeenCalled();
});

it('removes one duplicate row without changing the surviving row identity', async () => {
  const duplicate = { category: 'General', name: 'Color', value: 'Red' };
  render(<Editor starting={[createItemProperty(duplicate), createItemProperty(duplicate)]} />);
  const surviving = screen.getAllByDisplayValue('Red')[1];
  const identity = surviving.getAttribute('data-property-id');
  await userEvent.click(screen.getAllByRole('button', { name: 'Remove property' })[0]);
  expect(screen.getByDisplayValue('Red')).toBe(surviving);
  expect(surviving).toHaveAttribute('data-property-id', identity);
  await userEvent.click(screen.getByRole('button', { name: 'Remove property' }));
  expect(screen.getByText(/No properties yet/)).toBeInTheDocument();
});

it('keeps surviving input identity and focus when the parent removes, reorders or inserts rows', () => {
  const onChange = vi.fn();
  const { rerender } = render(<PropertyEditor properties={initial} onChange={onChange} />);
  const focused = screen.getByDisplayValue('Small');
  focused.focus();
  rerender(<PropertyEditor properties={[initial[2], initial[1]]} onChange={onChange} />);
  expect(screen.getByDisplayValue('Small')).toBe(focused);
  expect(focused).toHaveFocus();
  rerender(<PropertyEditor properties={[createItemProperty(), initial[1], initial[2]]} onChange={onChange} />);
  expect(focused).toHaveFocus();
  expect(screen.getByDisplayValue('Small')).toHaveAttribute('data-property-id', 'second');
  expect(onChange).not.toHaveBeenCalled();
});

it('reorders rows within a category while keeping values, identity and subsequent edits together', () => {
  const { container } = render(<Editor />);
  const red = screen.getByDisplayValue('Red');
  act(() => dnd.props.onDragEnd!({ active: { id: 'first' }, over: { id: 'second' } } as DragEndEvent));
  expect([...container.querySelectorAll('[data-field="value"]')].map(input => (input as HTMLInputElement).value)).toEqual(['Small', 'Red', '12V']);
  expect(screen.getByDisplayValue('Red')).toBe(red);
  fireEvent.change(red, { target: { value: 'Blue' } });
  expect(screen.getByDisplayValue('Blue')).toHaveAttribute('data-property-id', 'first');
});

it('leaves focus alone when a parent declines the added row', async () => {
  const onChange = vi.fn();
  const { rerender } = render(<PropertyEditor properties={initial} onChange={onChange} />);
  await userEvent.click(screen.getByRole('button', { name: '+ Add Property' }));
  expect(onChange).toHaveBeenCalledWith([...initial, expect.objectContaining({ category: '', name: '', value: '' })]);
  rerender(<PropertyEditor properties={initial} onChange={onChange} />);
  expect(screen.getByRole('button', { name: '+ Add Property' })).toHaveFocus();
});
