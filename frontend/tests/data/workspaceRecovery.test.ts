import { act, renderHook, waitFor } from '@testing-library/react';
import { expect, it, vi } from 'vitest';
import { useWorkspaceRecovery } from '../../src/data/workspaces/useWorkspaceRecovery';

it('rejects a restore without an available selection before contacting the mutation endpoint', async () => {
  const gateway = { getRestorableWorkspaces: vi.fn().mockResolvedValue([]), restoreWorkspaces: vi.fn() };
  const refresh = vi.fn();
  const complete = vi.fn();
  const { result } = renderHook(() => useWorkspaceRecovery(true, gateway, refresh, complete));
  await waitFor(() => expect(result.current.recovery.loading).toBe(false));
  await act(async () => { await result.current.restore(); });
  expect(result.current.error).toBe('Select at least one workspace to restore');
  expect(gateway.restoreWorkspaces).not.toHaveBeenCalled();
  expect(refresh).not.toHaveBeenCalled();
  expect(complete).not.toHaveBeenCalled();
});
