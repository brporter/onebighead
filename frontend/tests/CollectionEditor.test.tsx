import { act, fireEvent, render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, expect, it, vi } from 'vitest';
import { CollectionEditor } from '../src/components/collection/CollectionEditor';
import type { EditorStatusListener } from '../src/data/shared/useEditorStatus';
import { createMockCollection } from './testUtils/factories';
import { deferred } from './testUtils/deferred';

vi.mock('../src/contexts/usePublish', () => ({ usePublish: () => ({ requestPublish: vi.fn(), requestUnpublish: vi.fn() }) }));
vi.mock('../src/components/collection/CollectionTemplateEditor', () => ({ default: ({ onClose, onStatusChange }: { onClose: () => void; onStatusChange: EditorStatusListener }) => <>
  <button onClick={() => onStatusChange({ dirty: true, pending: false })}>Change template</button>
  <button onClick={() => onStatusChange({ dirty: true, pending: true })}>Save template</button>
  <button onClick={() => { onStatusChange({ dirty: false, pending: false }); onClose(); }}>Back to draft</button>
</> }));
afterEach(() => vi.restoreAllMocks());

it('labels the fields, keeps a failed draft, and disables all competing actions during a single save', async () => {
  const user = userEvent.setup();
  const pending = deferred<void>();
  const save = vi.fn().mockReturnValueOnce(pending.promise).mockResolvedValue(undefined);
  const close = vi.fn();
  const status = vi.fn();
  render(<CollectionEditor collection={createMockCollection({ name: 'Library' })} saveCollection={save} onClose={close} onStatusChange={status} />);
  await user.type(screen.getByRole('textbox', { name: 'Description' }), 'Description');
  await user.clear(screen.getByRole('textbox', { name: 'Hero Image URL' }));
  await user.type(screen.getByRole('textbox', { name: 'Hero Image URL' }), 'https://example.com/new.jpg');
  await user.click(screen.getByRole('button', { name: 'Save Changes' }));
  fireEvent.submit(screen.getByRole('form'));
  expect(save).toHaveBeenCalledOnce();
  for (const input of screen.getAllByRole('textbox')) expect(input).toBeDisabled();
  for (const button of screen.getAllByRole('button')) expect(button).toBeDisabled();
  expect(status).toHaveBeenLastCalledWith({ dirty: true, pending: true });
  await act(async () => pending.reject(new Error('Save failed')));
  expect(screen.getByRole('alert')).toHaveTextContent('Save failed');
  expect(screen.getByRole('textbox', { name: 'Hero Image URL' })).toHaveValue('https://example.com/new.jpg');
  await user.click(screen.getByRole('button', { name: 'Save Changes' }));
  expect(close).toHaveBeenCalledOnce();
});

it('retains collection changes during template editing and reports the nested editor state', async () => {
  const user = userEvent.setup();
  const status = vi.fn();
  render(<CollectionEditor collection={createMockCollection({ name: 'Library' })} saveCollection={vi.fn()} onClose={vi.fn()} onStatusChange={status} />);
  await user.click(screen.getByRole('button', { name: 'Manage Templates' }));
  await user.click(screen.getByRole('button', { name: 'Change template' }));
  expect(status).toHaveBeenLastCalledWith({ dirty: true, pending: false });
  await user.click(screen.getByRole('button', { name: 'Save template' }));
  expect(status).toHaveBeenLastCalledWith({ dirty: true, pending: true });
  await user.click(screen.getByRole('button', { name: 'Back to draft' }));
  expect(status).toHaveBeenLastCalledWith({ dirty: false, pending: false });
  await user.type(screen.getByRole('textbox', { name: 'Name' }), ' revised');
  await user.click(screen.getByRole('button', { name: 'Manage Templates' }));
  await user.click(screen.getByRole('button', { name: 'Back to draft' }));
  expect(screen.getByRole('textbox', { name: 'Name' })).toHaveValue('Library revised');
});

it('keeps the form when discarding is declined', async () => {
  const user = userEvent.setup();
  vi.spyOn(window, 'confirm').mockReturnValue(false);
  const close = vi.fn();
  render(<CollectionEditor collection={createMockCollection()} saveCollection={vi.fn()} onClose={close} onStatusChange={vi.fn()} />);
  await user.type(screen.getByRole('textbox', { name: 'Name' }), ' revised');
  await user.click(screen.getByRole('button', { name: 'Cancel' }));
  expect(close).not.toHaveBeenCalled();
});
