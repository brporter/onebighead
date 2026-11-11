import { useState } from 'react';
import { act, render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { createMemoryRouter, Link, RouterProvider, useNavigate } from 'react-router-dom';
import { afterEach, expect, it, vi } from 'vitest';
import { useSettingsSection } from '../../src/data/settings/useSettingsSection';
import { useUnsavedNavigation } from '../../src/data/shared/useUnsavedNavigation';

afterEach(() => vi.restoreAllMocks());

function Harness({ admin }: { admin: boolean }) {
  const { activeSection, navItems, setSection } = useSettingsSection(admin);
  const [dirty, setDirty] = useState(false);
  const [pending, setPending] = useState(false);
  const completeNavigation = useUnsavedNavigation(dirty, pending);
  const navigate = useNavigate();
  return <>
    <output aria-label="Current section">{activeSection}</output>
    <nav aria-label="Settings">{navItems.map(item => <button key={item.id} onClick={() => setSection(item.id)}>{item.label}</button>)}</nav>
    <button onClick={() => setSection('export')}>Request export</button>
    <button onClick={() => setDirty(!dirty)}>Toggle dirty</button>
    <button onClick={() => setPending(!pending)}>Toggle pending</button>
    <button onClick={() => completeNavigation(() => { void navigate('/collections'); })}>Finish and leave</button>
    <button onClick={() => {
      try { completeNavigation(() => { throw new Error('Navigation failed'); }); } catch { /* The next attempt must still be guarded. */ }
    }}>Failed completion</button>
    <Link to="/collections">Leave settings</Link>
    <Link to="#details">Jump to details</Link>
  </>;
}

function setup(admin = true, entry = '/settings?section=collections&filter=mine') {
  const router = createMemoryRouter([
    { path: '/settings', element: <Harness admin={admin} /> },
    { path: '/collections', element: <h1>Collection overview</h1> },
  ], { initialEntries: [entry] });
  return { ...render(<RouterProvider router={router} />), router, user: userEvent.setup() };
}

it('tracks URL changes and history, preserves unrelated query parameters and ignores the current section', async () => {
  const { router, user } = setup();
  const key = router.state.location.key;
  await user.click(screen.getByRole('button', { name: 'Collections' }));
  expect(router.state.location.key).toBe(key);
  await user.click(screen.getByRole('button', { name: 'Support' }));
  expect(router.state.location.search).toBe('?section=support&filter=mine');
  expect(screen.getByLabelText('Current section')).toHaveTextContent('support');
  await act(() => router.navigate(-1));
  expect(screen.getByLabelText('Current section')).toHaveTextContent('collections');
  await act(() => router.navigate(1));
  expect(screen.getByLabelText('Current section')).toHaveTextContent('support');
});

it.each(['/settings', '/settings?section=unknown', '/settings?section=export'])('uses an available section for a member opening %s', async entry => {
  const { router, user } = setup(false, entry);
  expect(screen.getByLabelText('Current section')).toHaveTextContent('dashboard');
  expect(screen.queryByRole('button', { name: 'Data Export' })).not.toBeInTheDocument();
  const key = router.state.location.key;
  await user.click(screen.getByRole('button', { name: 'Request export' }));
  expect(router.state.location.key).toBe(key);
});

it('confirms dirty history and route changes, keeps rejected drafts and allows hash-only movement', async () => {
  const confirm = vi.spyOn(window, 'confirm').mockReturnValue(false);
  const { router, user } = setup();
  await user.click(screen.getByRole('button', { name: 'Support' }));
  await user.click(screen.getByRole('button', { name: 'Toggle dirty' }));
  await act(() => router.navigate(-1));
  expect(screen.getByLabelText('Current section')).toHaveTextContent('support');
  expect(confirm).toHaveBeenCalledOnce();
  await act(() => router.navigate({ pathname: '/settings', search: '?section=support&filter=mine', hash: '#details' }));
  expect(router.state.location.hash).toBe('#details');
  expect(confirm).toHaveBeenCalledOnce();
  confirm.mockReturnValue(true);
  await user.click(screen.getByRole('link', { name: 'Leave settings' }));
  expect(screen.getByRole('heading', { name: 'Collection overview' })).toBeInTheDocument();
  expect(confirm).toHaveBeenCalledTimes(2);
});

it('blocks pending mutations without asking to discard and releases navigation after they finish', async () => {
  const confirm = vi.spyOn(window, 'confirm');
  const { user } = setup();
  await user.click(screen.getByRole('button', { name: 'Toggle pending' }));
  await user.click(screen.getByRole('button', { name: 'Support' }));
  expect(screen.getByLabelText('Current section')).toHaveTextContent('collections');
  expect(confirm).not.toHaveBeenCalled();
  const closing = new Event('beforeunload', { cancelable: true });
  window.dispatchEvent(closing);
  expect(closing.defaultPrevented).toBe(true);
  await user.click(screen.getByRole('button', { name: 'Toggle pending' }));
  await user.click(screen.getByRole('link', { name: 'Leave settings' }));
  expect(screen.getByRole('heading')).toHaveTextContent('Collection overview');
});

it('warns on browser unload only while a draft needs protecting and removes the listener on unmount', async () => {
  const { user, unmount } = setup();
  function beforeUnload() {
    const event = new Event('beforeunload', { cancelable: true });
    window.dispatchEvent(event);
    return event.defaultPrevented;
  }
  expect(beforeUnload()).toBe(false);
  await user.click(screen.getByRole('button', { name: 'Toggle dirty' }));
  expect(beforeUnload()).toBe(true);
  await user.click(screen.getByRole('button', { name: 'Toggle dirty' }));
  expect(beforeUnload()).toBe(false);
  await user.click(screen.getByRole('button', { name: 'Toggle dirty' }));
  unmount();
  expect(beforeUnload()).toBe(false);
});

it('allows completion to navigate while editor status is still pending and dirty', async () => {
  const confirm = vi.spyOn(window, 'confirm');
  const { user } = setup();
  await user.click(screen.getByRole('button', { name: 'Toggle dirty' }));
  await user.click(screen.getByRole('button', { name: 'Toggle pending' }));
  await user.click(screen.getByRole('button', { name: 'Finish and leave' }));
  expect(screen.getByRole('heading', { name: 'Collection overview' })).toBeInTheDocument();
  expect(confirm).not.toHaveBeenCalled();
});

it('restores protection after a completion callback throws', async () => {
  const confirm = vi.spyOn(window, 'confirm').mockReturnValue(false);
  const { user } = setup();
  await user.click(screen.getByRole('button', { name: 'Toggle dirty' }));
  await user.click(screen.getByRole('button', { name: 'Failed completion' }));
  await user.click(screen.getByRole('link', { name: 'Leave settings' }));
  expect(confirm).toHaveBeenCalledOnce();
  expect(screen.queryByRole('heading', { name: 'Collection overview' })).not.toBeInTheDocument();
});
