import { useState } from 'react';
import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { expect, it, vi } from 'vitest';
import ThemeCard from '../src/components/collection/ThemeCard';
import { SetupThemePicker } from '../src/components/collection/SetupThemePicker';
import { createMockCollectionTheme as theme, createMockThemeTemplate as template } from './testUtils/factories';

it('labels each choice, exposes exclusive selection, and supports keyboard activation', async () => {
  const user = userEvent.setup();
  const choices = [theme({ name: 'General', description: 'Start with your own fields' }), theme({ themeId: 2, name: 'Books', description: 'Catalog your library', iconName: 'book' })];
  function Picker() {
    const [selectedId, select] = useState(1);
    return <SetupThemePicker themes={choices} loading={false} error={null} retry={vi.fn()} selectedId={selectedId} select={select} />;
  }
  render(<Picker />);
  const group = screen.getByRole('group', { name: 'Collection themes' });
  const general = within(group).getByRole('button', { name: 'General', pressed: true });
  const books = within(group).getByRole('button', { name: 'Books', pressed: false });
  expect(books).toHaveAccessibleDescription('Catalog your library');
  expect(books.getAttribute('aria-labelledby')).not.toBe(general.getAttribute('aria-labelledby'));
  expect(within(books).getByText('📚')).toHaveAttribute('aria-hidden', 'true');
  await user.tab();
  expect(general).toHaveFocus();
  await user.tab();
  await user.keyboard(' ');
  expect(books).toHaveAttribute('aria-pressed', 'true');
  expect(general).toHaveAttribute('aria-pressed', 'false');
  await user.tab({ shift: true });
  await user.keyboard('{Enter}');
  expect(general).toHaveAttribute('aria-pressed', 'true');
  expect(books).toHaveAttribute('aria-pressed', 'false');
});

it('only truncates an actual property list and uses a safe fallback for unknown icons', () => {
  const properties = ['Author', 'Publisher', 'Year', 'ISBN'].map(name => ({ category: '', name }));
  const source = theme({ name: 'Books', iconName: 'toString', templates: [template({ properties })] });
  const { rerender } = render(<ThemeCard theme={source} isSelected={false} onSelect={vi.fn()} />);
  expect(screen.getByText('Author, Publisher, Year…')).toBeInTheDocument();
  expect(screen.getByText('📦')).toHaveAttribute('aria-hidden', 'true');
  rerender(<ThemeCard theme={{ ...source, templates: [template({ properties: properties.slice(0, 3) })] }} isSelected onSelect={vi.fn()} />);
  expect(screen.getByText('Author, Publisher, Year')).toBeInTheDocument();
  expect(screen.queryByText(/…/)).not.toBeInTheDocument();
  rerender(<ThemeCard theme={{ ...source, templates: [template()] }} isSelected onSelect={vi.fn()} />);
  expect(screen.queryByText(/Author/)).not.toBeInTheDocument();
});

it('inherits the setup form lock and does not submit the surrounding form', async () => {
  const user = userEvent.setup();
  const select = vi.fn();
  const submit = vi.fn(event => event.preventDefault());
  const view = (locked: boolean) => <form onSubmit={submit}><fieldset disabled={locked}>
    <ThemeCard theme={theme({ name: 'General' })} isSelected={false} onSelect={select} />
  </fieldset></form>;
  const { rerender } = render(view(true));
  await user.click(screen.getByRole('button', { name: 'General' }));
  expect(select).not.toHaveBeenCalled();
  rerender(view(false));
  await user.click(screen.getByRole('button', { name: 'General' }));
  expect(select).toHaveBeenCalledOnce();
  expect(submit).not.toHaveBeenCalled();
});
