import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { beforeEach, expect, it, vi } from 'vitest';
import { MemoryRouter } from 'react-router-dom';
import { UserProvider } from '../src/contexts/UserContext';
import UserButton from '../src/components/user/UserButton';
import TermsView from '../src/views/TermsView';
import RequireAuth from '../src/components/common/RequireAuth';
import { authApi } from '../src/api';
import { createMockCurrentUser } from './testUtils';
import { deferred } from './testUtils/deferred';

vi.mock('../src/api', async importOriginal => ({
  ...await importOriginal<typeof import('../src/api')>(),
  authApi: { getCurrentUser: vi.fn(), logout: vi.fn(), acceptTerms: vi.fn() },
}));

beforeEach(() => {
  vi.resetAllMocks();
  vi.stubGlobal('location', { href: '' });
  vi.mocked(authApi.getCurrentUser).mockResolvedValue(createMockCurrentUser({ hasAcceptedTerms: true, hasCompletedWelcome: true }));
});

it.each(['header', 'terms'] as const)('surfaces provider logout failures in the %s and redirects only on successful retry', async surface => {
  const retry = deferred<void>();
  vi.mocked(authApi.logout).mockRejectedValueOnce(new Error('Offline')).mockReturnValueOnce(retry.promise);
  render(<UserProvider><MemoryRouter><RequireAuth>
    {surface === 'header' ? <UserButton /> : <TermsView />}
  </RequireAuth></MemoryRouter></UserProvider>);
  fireEvent.click(await screen.findByRole('button', { name: 'Sign Out' }));
  expect(await screen.findByRole('alert')).toHaveTextContent('Offline');
  expect(window.location.href).toBe('');
  fireEvent.click(screen.getByRole('button', { name: 'Sign Out' }));
  expect(screen.getByRole('button', { name: 'Signing out…' })).toBeDisabled();
  await act(async () => retry.resolve());
  // The route guard agrees with the explicit sign-out destination.
  await waitFor(() => expect(window.location.href).toBe('/'));
  expect(authApi.logout).toHaveBeenCalledTimes(2);
});
