import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, expect, it, vi } from 'vitest';
import TemplateSelector from '../src/components/template/TemplateSelector';
import { useCollectionsData as useDataHook } from '../src/contexts/useData';
import { createMockCategory, createMockDataContextValue, createMockItemTemplate } from './testUtils/factories';
import { deferred } from './testUtils/deferred';
import type { ItemTemplate } from '../src/utils/types';

const useData = useDataHook as () => import('./testUtils/dataTypes').DataContextValue;

vi.mock('../src/contexts/useData', async () => {
  const { mockDataHooks } = await import('./testUtils/mockDataHooks');
  return mockDataHooks({ useData: vi.fn() });
});

const first = createMockItemTemplate({ name: 'Book', properties: Array.from({ length: 6 }, (_, i) => ({ category: 'Details', name: `Field ${i}` })) });
const second = createMockItemTemplate({ itemTemplateId: 2, templateKey: 'second', name: 'Film', description: '', isSystem: true });
const data = createMockDataContextValue();
const props = { collectionId: 1, isOpen: true, onClose: vi.fn(), onSelect: vi.fn() };
beforeEach(() => {
  vi.clearAllMocks();
  data.categories = [createMockCategory({ name: 'Books' })];
  data.fetchItemTemplates = vi.fn().mockResolvedValue([second]);
  data.loadCollectionTemplates = vi.fn().mockResolvedValue([first]);
  data.getCategoryTemplates = vi.fn().mockResolvedValue([1]);
  vi.mocked(useData).mockReturnValue(data);
});

it('opens an accessible dialog and switches between recommendation, collection and library sources', async () => {
  render(<TemplateSelector {...props} categoryId={1} />);
  expect(screen.getByRole('dialog', { name: 'Choose a Template' })).toBeInTheDocument();
  expect(await screen.findByRole('button', { name: 'Recommended (1)' })).toHaveAttribute('aria-pressed', 'true');
  expect(screen.getByText('Templates recommended for "Books"')).toBeInTheDocument();
  expect(screen.getByText('+1 more')).toBeInTheDocument();
  await userEvent.click(screen.getByRole('button', { name: 'Library (1)' }));
  expect(screen.getByRole('button', { name: /Film/ })).toBeInTheDocument();
  expect(screen.queryByRole('button', { name: /^Book/ })).not.toBeInTheDocument();
  await userEvent.click(screen.getByRole('button', { name: 'Collection (1)' }));
  expect(screen.getByRole('button', { name: /^Book/ })).toBeInTheDocument();
  await userEvent.click(screen.getByRole('button', { name: 'Recommended (1)' }));
  await userEvent.click(screen.getByRole('button', { name: /^Book/ }));
  expect(props.onSelect).toHaveBeenCalledWith({ templateKey: first.templateKey,
    properties: first.properties.map(property => ({ ...property, value: '' })) });
});

it('defaults to collection templates without a category and allows a blank item while loading', async () => {
  const pending = deferred<ItemTemplate[]>();
  vi.mocked(data.fetchItemTemplates).mockReturnValue(pending.promise);
  render(<TemplateSelector {...props} />);
  expect(screen.getByRole('status')).toHaveTextContent('Loading templates...');
  await userEvent.click(screen.getByRole('button', { name: 'Start from scratch' }));
  expect(props.onSelect).toHaveBeenCalledWith({ templateKey: null, properties: [] });
  await act(async () => pending.resolve([]));
  expect(screen.getByRole('button', { name: 'Collection (1)' })).toHaveAttribute('aria-pressed', 'true');
  expect(data.getCategoryTemplates).not.toHaveBeenCalled();
});

it('handles empty catalogs and recommendations without a matching category', async () => {
  data.categories = [];
  const { rerender } = render(<TemplateSelector {...props} categoryId={2} />);
  expect(await screen.findByRole('button', { name: 'Recommended (1)' })).toBeInTheDocument();
  expect(screen.queryByText(/Templates recommended for/)).not.toBeInTheDocument();
  vi.mocked(data.loadCollectionTemplates).mockResolvedValue([]);
  vi.mocked(data.fetchItemTemplates).mockResolvedValue([]);
  rerender(<TemplateSelector {...props} collectionId={2} />);
  expect(await screen.findByText('No templates available in the library.')).toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Library (0)' })).toHaveAttribute('aria-pressed', 'true');
});

it.each(['catalog', 'recommendations'])('recovers from %s errors and still allows starting from scratch', async source => {
  const method = source === 'catalog' ? data.fetchItemTemplates : data.getCategoryTemplates;
  vi.mocked(method).mockRejectedValueOnce(new Error('Offline'));
  render(<TemplateSelector {...props} categoryId={1} />);
  expect(await screen.findByRole('alert')).toHaveTextContent('Offline');
  expect(screen.getByRole('button', { name: 'Start from scratch' })).toBeEnabled();
  await userEvent.click(screen.getByRole('button', { name: 'Try again' }));
  expect(await screen.findByRole('button', { name: 'Recommended (1)' })).toBeInTheDocument();
  expect(screen.queryByRole('alert')).not.toBeInTheDocument();
});

it('dismisses with Close, Escape or the backdrop but not a click inside the dialog content', async () => {
  render(<TemplateSelector {...props} />);
  await screen.findByRole('button', { name: 'Collection (1)' });
  const dialog = screen.getByRole('dialog');
  await userEvent.click(within(dialog).getByRole('heading'));
  expect(props.onClose).not.toHaveBeenCalled();
  await userEvent.click(screen.getByRole('button', { name: 'Close' }));
  fireEvent(dialog, new Event('cancel', { bubbles: true, cancelable: true }));
  fireEvent.click(dialog);
  expect(props.onClose).toHaveBeenCalledTimes(3);
});

it('does not load while closed, aborts when dismissed, and resets source selection on reopening', async () => {
  const { rerender } = render(<TemplateSelector {...props} isOpen={false} />);
  expect(data.fetchItemTemplates).not.toHaveBeenCalled();
  rerender(<TemplateSelector {...props} />);
  await userEvent.click(await screen.findByRole('button', { name: 'Library (1)' }));
  const signal = vi.mocked(data.fetchItemTemplates).mock.calls[0][0]!.signal!;
  rerender(<TemplateSelector {...props} isOpen={false} />);
  expect(signal.aborted).toBe(true);
  expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
  rerender(<TemplateSelector {...props} />);
  await waitFor(() => expect(screen.getByRole('button', { name: 'Collection (1)' })).toHaveAttribute('aria-pressed', 'true'));
});
