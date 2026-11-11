import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { expect, it, vi } from 'vitest';
import type { ComponentProps } from 'react';
import { TemplateDefinitionForm } from '../src/components/template/TemplateDefinitionForm';
import type { SortablePropertyList } from '../src/components/common/SortablePropertyList';
import type { TemplatePropertyDraft } from '../src/data/templates/templateDefinition';
import { createMockItemTemplate } from './testUtils/factories';

// Exercise the form's reorder contract independently of drag-sensor geometry.
vi.mock('../src/components/common/SortablePropertyList', () => ({
  SortablePropertyList: ({ properties, onPropertiesChange }: ComponentProps<typeof SortablePropertyList<TemplatePropertyDraft>>) =>
    <button type="button" onClick={() => onPropertiesChange([...properties].reverse())}>Reverse properties</button>,
}));

it('saves reordered property identifiers and clears dirty state when the form is abandoned', async () => {
  const template = createMockItemTemplate({ properties: [{ category: 'Details', name: 'First' }, { category: 'Details', name: 'Second' }] });
  const commands = { createItemTemplate: vi.fn(), updateItemTemplate: vi.fn().mockResolvedValue(template) };
  const previews = { preview: vi.fn().mockResolvedValue({ affectedItemCount: 0 }) };
  const dirty = vi.fn();
  const done = vi.fn();
  const { unmount } = render(<TemplateDefinitionForm template={template} commands={commands} previews={previews}
    onSaved={vi.fn()} onDone={done} onStatusChange={dirty} />);
  await userEvent.click(screen.getByRole('button', { name: 'Reverse properties' }));
  expect(dirty).toHaveBeenLastCalledWith({ dirty: true, pending: false });
  fireEvent.submit(screen.getByRole('form'));
  await waitFor(() => expect(done).toHaveBeenCalledOnce());
  expect(commands.updateItemTemplate).toHaveBeenCalledWith(template.itemTemplateId, expect.objectContaining({ properties: [...template.properties].reverse() }));
  expect(previews.preview).toHaveBeenCalledOnce();
  unmount();
  expect(dirty).toHaveBeenLastCalledWith({ dirty: false, pending: false });
});
