import { act, renderHook, waitFor } from '@testing-library/react';
import { expect, it, vi } from 'vitest';
import { useCategoryManager } from '../../src/data/categories/useCategoryManager';
import { createMockCategory } from '../testUtils';

it('prevents a second operation after a confirmed write and ignores confirmations without a navigation target', async () => {
  const port = { categories: [createMockCategory()], loadCategoriesForCollection: vi.fn().mockResolvedValue(undefined),
    addCategory: vi.fn().mockResolvedValue(2), updateCategory: vi.fn(), deleteCategory: vi.fn(), reorderCategories: vi.fn().mockRejectedValue(new Error('Offline')) };
  const close = vi.fn();
  const { result } = renderHook(() => useCategoryManager(1, port, close));
  await waitFor(() => expect(result.current.resource.loading).toBe(false));
  act(() => result.current.confirmLeave());
  expect(close).not.toHaveBeenCalled();
  await act(async () => { await result.current.execute({ type: 'quick-create', name: 'New' }); });
  expect(result.current.saved).toBe(true);
  await act(async () => { await result.current.execute({ type: 'delete', categoryId: 2 }); });
  expect(port.deleteCategory).not.toHaveBeenCalled();
  act(() => result.current.leave('close'));
  expect(result.current.destination).toBe('close');
  act(() => result.current.confirmLeave());
  expect(close).toHaveBeenCalledOnce();
});
