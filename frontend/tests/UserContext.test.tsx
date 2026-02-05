import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, act, waitFor } from '@testing-library/react';
import { UserProvider, useUser } from '../src/contexts/UserContext';
import type { CurrentUser } from '../src/utils/types';

vi.mock('../src/api', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../src/api')>();
  return {
    ...actual,
    authApi: {
      getCurrentUser: vi.fn(),
      logout: vi.fn(),
    },
  };
});

import { authApi } from '../src/api';

const mockUser: CurrentUser = {
  userId: 1,
  email: 'test@example.com',
  workspaceId: 1,
  isSystemAdministrator: false,
};

function TestConsumer({
  onData
}: {
  onData: (data: ReturnType<typeof useUser>) => void
}) {
  const data = useUser();
  onData(data);
  return <div>Test Consumer</div>;
}

describe('UserContext', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('should fetch user on mount via authApi', async () => {
    vi.mocked(authApi.getCurrentUser).mockResolvedValue(mockUser);

    let capturedData: ReturnType<typeof useUser> | null = null;

    render(
      <UserProvider>
        <TestConsumer onData={(data) => { capturedData = data; }} />
      </UserProvider>
    );

    await waitFor(() => {
      expect(capturedData!.loading).toBe(false);
    });

    expect(authApi.getCurrentUser).toHaveBeenCalledTimes(1);
    expect(capturedData!.user).toEqual(mockUser);
    expect(capturedData!.error).toBeNull();
  });

  it('should set user to null when authApi returns null (401)', async () => {
    vi.mocked(authApi.getCurrentUser).mockResolvedValue(null);

    let capturedData: ReturnType<typeof useUser> | null = null;

    render(
      <UserProvider>
        <TestConsumer onData={(data) => { capturedData = data; }} />
      </UserProvider>
    );

    await waitFor(() => {
      expect(capturedData!.loading).toBe(false);
    });

    expect(capturedData!.user).toBeNull();
    expect(capturedData!.error).toBeNull();
  });

  it('should set error state when fetch fails', async () => {
    vi.mocked(authApi.getCurrentUser).mockRejectedValue(new Error('Network error'));

    let capturedData: ReturnType<typeof useUser> | null = null;

    render(
      <UserProvider>
        <TestConsumer onData={(data) => { capturedData = data; }} />
      </UserProvider>
    );

    await waitFor(() => {
      expect(capturedData!.loading).toBe(false);
    });

    expect(capturedData!.user).toBeNull();
    expect(capturedData!.error).toBe('Network error');
  });

  it('should set generic error message when error is not an Error instance', async () => {
    vi.mocked(authApi.getCurrentUser).mockRejectedValue('string error');

    let capturedData: ReturnType<typeof useUser> | null = null;

    render(
      <UserProvider>
        <TestConsumer onData={(data) => { capturedData = data; }} />
      </UserProvider>
    );

    await waitFor(() => {
      expect(capturedData!.loading).toBe(false);
    });

    expect(capturedData!.error).toBe('Failed to fetch user');
  });

  it('should call authApi.logout and set user to null on logout()', async () => {
    vi.mocked(authApi.getCurrentUser).mockResolvedValue(mockUser);
    vi.mocked(authApi.logout).mockResolvedValue(undefined);

    let capturedData: ReturnType<typeof useUser> | null = null;

    render(
      <UserProvider>
        <TestConsumer onData={(data) => { capturedData = data; }} />
      </UserProvider>
    );

    await waitFor(() => {
      expect(capturedData!.user).toEqual(mockUser);
    });

    await act(async () => {
      await capturedData!.logout();
    });

    expect(authApi.logout).toHaveBeenCalledTimes(1);
    expect(capturedData!.user).toBeNull();
  });

  it('should re-fetch the user on refetch()', async () => {
    vi.mocked(authApi.getCurrentUser)
      .mockResolvedValueOnce(mockUser)
      .mockResolvedValueOnce({ ...mockUser, email: 'updated@example.com' });

    let capturedData: ReturnType<typeof useUser> | null = null;

    render(
      <UserProvider>
        <TestConsumer onData={(data) => { capturedData = data; }} />
      </UserProvider>
    );

    await waitFor(() => {
      expect(capturedData!.user?.email).toBe('test@example.com');
    });

    await act(async () => {
      await capturedData!.refetch();
    });

    expect(authApi.getCurrentUser).toHaveBeenCalledTimes(2);
    expect(capturedData!.user?.email).toBe('updated@example.com');
  });

  it('should handle logout error gracefully', async () => {
    const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    vi.mocked(authApi.getCurrentUser).mockResolvedValue(mockUser);
    vi.mocked(authApi.logout).mockRejectedValue(new Error('Logout failed'));

    let capturedData: ReturnType<typeof useUser> | null = null;

    render(
      <UserProvider>
        <TestConsumer onData={(data) => { capturedData = data; }} />
      </UserProvider>
    );

    await waitFor(() => {
      expect(capturedData!.user).toEqual(mockUser);
    });

    await act(async () => {
      await capturedData!.logout();
    });

    // logError now uses different format: "Logout failed: message (status: N)" for ApiError
    expect(consoleSpy).toHaveBeenCalled();
    // User should still be set (logout failed)
    expect(capturedData!.user).toEqual(mockUser);

    consoleSpy.mockRestore();
  });
});
