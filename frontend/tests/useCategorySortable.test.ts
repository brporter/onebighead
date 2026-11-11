import { renderHook } from '@testing-library/react';
import type { DragEndEvent } from '@dnd-kit/core';
import { expect, it, vi } from 'vitest';
import { groupByCategory, useCategorySortable } from '../src/hooks/useCategorySortable';

it('groups by first category occurrence, retains item order and supports empty categories', () => {
  const items = [{ id: '1', category: 'B' }, { id: '2', category: '' }, { id: '3', category: 'A' }, { id: '4', category: 'B' }];
  expect(groupByCategory(items)).toEqual([
    { category: 'B', items: [items[0], items[3]] },
    { category: 'Uncategorized', items: [items[1]] },
    { category: 'A', items: [items[2]] },
  ]);
});

it('reorders only valid drops within the same category', () => {
  const items = [{ id: '1', category: 'A' }, { id: '2', category: 'A' }, { id: '3', category: 'B' }];
  const onChange = vi.fn();
  const { result } = renderHook(() => useCategorySortable(items, onChange));
  const drop = (active: string, over: string | null) => result.current.handleDragEnd({ active: { id: active }, over: over === null ? null : { id: over } } as DragEndEvent);
  drop('1', null);
  drop('1', '1');
  drop('1', '3');
  drop('missing', '2');
  drop('1', 'missing');
  expect(onChange).not.toHaveBeenCalled();
  drop('1', '2');
  expect(onChange).toHaveBeenCalledWith([items[1], items[0], items[2]]);
  expect(result.current.sensors).toHaveLength(2);
  expect(items.map(item => item.id)).toEqual(['1', '2', '3']);
});
