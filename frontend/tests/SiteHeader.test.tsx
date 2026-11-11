import { expect, it, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { SiteHeader } from '../src/components/common/SiteHeader';

vi.mock('../src/components/common/WorkspaceSwitcher', () => ({
  WorkspaceSwitcher: () => <button>Switch workspace</button>,
}));

it('shows branding, workspace selection and supplied actions without a page title', () => {
  render(<SiteHeader><button>Account</button></SiteHeader>);
  expect(screen.getByRole('link', { name: 'OneBigHead' })).toHaveAttribute('href', '/');
  expect(screen.getByRole('button', { name: 'Switch workspace' })).toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Account' })).toBeInTheDocument();
  expect(screen.queryByRole('heading')).not.toBeInTheDocument();
});

it('shows a page title, supporting text and a functional back action', async () => {
  const onClick = vi.fn();
  const { rerender } = render(<SiteHeader title="Settings" subtitle="Manage your workspace"
    showWorkspaceSwitcher={false} backLink={{ label: 'Collections', onClick }} />);
  expect(screen.getByRole('heading', { level: 1, name: 'Settings' })).toBeInTheDocument();
  expect(screen.getByText('Manage your workspace')).toBeInTheDocument();
  expect(screen.queryByRole('button', { name: 'Switch workspace' })).not.toBeInTheDocument();
  await userEvent.click(screen.getByRole('button', { name: /Collections/ }));
  expect(onClick).toHaveBeenCalledOnce();
  rerender(<SiteHeader title="Settings" />);
  expect(screen.getByRole('heading', { name: 'Settings' })).toBeInTheDocument();
  expect(screen.queryByText('Manage your workspace')).not.toBeInTheDocument();
  expect(screen.queryByRole('button', { name: /Collections/ })).not.toBeInTheDocument();
});

it('allows a back action without reserving space for an absent title', () => {
  render(<SiteHeader backLink={{ label: 'Back to collection', onClick: vi.fn() }} />);
  expect(screen.getByRole('button', { name: /Back to collection/ })).toBeInTheDocument();
  expect(screen.queryByRole('heading')).not.toBeInTheDocument();
});
