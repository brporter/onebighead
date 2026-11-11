import { beforeEach, expect, it, vi } from 'vitest';
import { createWelcomeFlow, createWorkspaceFlow } from '../../src/data/onboarding/setupFlow';
import { setupAttemptStorage } from '../../src/data/onboarding/setupAttemptStorage';
import { ApiError } from '../../src/api/transport';
import { WorkspaceRole } from '../../src/utils/types';

beforeEach(() => sessionStorage.clear());
const store = () => setupAttemptStorage(1);
const draft = { workspaceName: 'Study', collectionName: 'Books', description: 'First editions', themeId: 2 };
const workspace = { workspaceId: 4, workspaceName: 'Study', hasCompletedWelcome: true, collectionId: 8, collectionName: 'Books' };
const result = { workspaceId: 4, workspaceName: 'Study', collectionId: 8, collectionName: 'Books', workspaceRole: WorkspaceRole.WorkspaceAdmin };

it('retries a failed workspace setup but never repeats a confirmed setup when refreshing its session fails', async () => {
  const setup = vi.fn().mockRejectedValueOnce(new Error('Setup offline')).mockResolvedValue(result);
  const refresh = vi.fn().mockRejectedValueOnce(new Error('Refresh offline')).mockResolvedValue(undefined);
  const flow = createWorkspaceFlow(setup, refresh, store());
  expect(flow.started).toBe(false);
  await expect(flow.complete(draft)).rejects.toThrow('Setup offline');
  expect(flow.started).toBe(true);
  expect(refresh).not.toHaveBeenCalled();
  await expect(flow.complete(draft)).rejects.toThrow('Refresh offline');
  expect(flow.started).toBe(true);
  await expect(flow.complete(draft)).resolves.toEqual(result);
  expect(setup).toHaveBeenCalledTimes(2);
  expect(setup).toHaveBeenLastCalledWith({ requestId: expect.any(String), workspaceName: 'Study', collectionName: 'Books', collectionDescription: 'First editions', themeId: 2 });
  expect(refresh).toHaveBeenCalledTimes(2);
});

it('lets the setup endpoint supply its default collection name and empty description', async () => {
  const setup = vi.fn().mockResolvedValue(result);
  await createWorkspaceFlow(setup, vi.fn(), store()).complete({ ...draft, collectionName: '', description: '' });
  expect(setup).toHaveBeenCalledWith({ requestId: expect.any(String), workspaceName: 'Study', collectionName: undefined, collectionDescription: undefined, themeId: 2 });
});

it('completes welcome and its first collection with one retryable command, then only retries session reads', async () => {
  const welcome = vi.fn().mockRejectedValueOnce(new Error('Response lost')).mockResolvedValue(workspace);
  const refresh = vi.fn().mockRejectedValueOnce(new Error('Refresh offline')).mockResolvedValue(undefined);
  const flow = createWelcomeFlow(welcome, refresh);
  expect(flow.started).toBe(false);
  await expect(flow.complete(draft)).rejects.toThrow('Response lost');
  expect(flow.started).toBe(false);
  expect(refresh).not.toHaveBeenCalled();
  await expect(flow.complete(draft)).rejects.toThrow('Refresh offline');
  expect(flow.started).toBe(true);
  await expect(flow.complete(draft)).resolves.toEqual(workspace);
  expect(welcome).toHaveBeenCalledTimes(2);
  expect(welcome).toHaveBeenLastCalledWith({ workspaceName: 'Study',
    collection: { name: 'Books', description: 'First editions', themeId: 2 } });
  expect(refresh).toHaveBeenCalledTimes(2);
});

it('uses the server result when welcome was completed in another tab or its original collection was deleted', async () => {
  const completed = { ...workspace, collectionId: null, collectionName: null };
  const welcome = vi.fn().mockResolvedValue(completed);
  await expect(createWelcomeFlow(welcome, vi.fn()).complete(draft)).resolves.toEqual(completed);
});

it('recovers a lost welcome response after remounting from the same atomic endpoint', async () => {
  const welcome = vi.fn().mockRejectedValueOnce(new Error('Response lost')).mockResolvedValue(workspace);
  await expect(createWelcomeFlow(welcome, vi.fn()).complete(draft)).rejects.toThrow('Response lost');
  await expect(createWelcomeFlow(welcome, vi.fn()).complete(draft)).resolves.toEqual(workspace);
  expect(welcome.mock.calls[1]).toEqual(welcome.mock.calls[0]);
});

it('resumes a skipped welcome after failed completion or refresh without requesting a collection', async () => {
  const welcome = vi.fn().mockRejectedValueOnce(new Error('Welcome offline')).mockResolvedValue(workspace);
  const refresh = vi.fn().mockRejectedValueOnce(new Error('Refresh offline')).mockResolvedValue(undefined);
  const flow = createWelcomeFlow(welcome, refresh);
  await expect(flow.skip!()).rejects.toThrow('Welcome offline');
  expect(flow.started).toBe(false);
  await expect(flow.skip!()).rejects.toThrow('Refresh offline');
  expect(flow.started).toBe(true);
  await flow.skip!();
  expect(welcome).toHaveBeenCalledTimes(2);
  expect(welcome).toHaveBeenLastCalledWith({});
});

it.each([0, 401, 403, 409, 500])('retains the exact persisted request across remounts after HTTP %s', async status => {
  const setup = vi.fn().mockRejectedValueOnce(new ApiError('Uncertain result', status, 'Failed')).mockResolvedValue(result);
  const first = createWorkspaceFlow(setup, vi.fn(), store());
  await expect(first.complete(draft)).rejects.toThrow('Uncertain result');
  const saved = store().read()!;
  expect(saved.draft).toEqual(draft);
  const recovered = createWorkspaceFlow(setup, vi.fn(), store());
  expect(recovered.started).toBe(true);
  expect(recovered.draft).toEqual(draft);
  await expect(recovered.complete({ ...draft, workspaceName: 'Do not change the request' })).resolves.toEqual(result);
  expect(setup.mock.calls[1]).toEqual(setup.mock.calls[0]);
  expect(store().read()).toBeUndefined();
});

it.each([400, 410])('allows a new explicit attempt after a definitive HTTP %s rejection', async status => {
  const setup = vi.fn().mockRejectedValueOnce(new ApiError('Definitive rejection', status, 'Rejected')).mockResolvedValue(result);
  const ids = vi.fn().mockReturnValueOnce('a1234567-1234-1234-1234-123456789abc').mockReturnValueOnce('b1234567-1234-1234-1234-123456789abc');
  const flow = createWorkspaceFlow(setup, vi.fn(), store(), ids);
  expect(flow.draft).toBeUndefined();
  await expect(flow.complete(draft)).rejects.toThrow('Definitive rejection');
  expect(flow.started).toBe(false);
  expect(store().read()).toBeUndefined();
  await flow.complete({ ...draft, workspaceName: 'Corrected' });
  expect(setup.mock.calls[1][0]).toEqual(expect.objectContaining({ requestId: 'b1234567-1234-1234-1234-123456789abc', workspaceName: 'Corrected' }));
});

it('does not send a command unless the attempt was persisted, and retries cleanup without repeating a confirmed write', async () => {
  const persistence = { read: vi.fn(), save: vi.fn().mockImplementationOnce(() => { throw new Error('Storage full'); }), clear: vi.fn().mockImplementationOnce(() => { throw new Error('Storage blocked'); }) };
  const setup = vi.fn().mockResolvedValue(result);
  const flow = createWorkspaceFlow(setup, vi.fn(), persistence);
  await expect(flow.complete(draft)).rejects.toThrow('Storage full');
  expect(setup).not.toHaveBeenCalled();
  expect(flow.started).toBe(false);
  await expect(flow.complete(draft)).rejects.toThrow('Storage blocked');
  expect(flow.started).toBe(true);
  await expect(flow.complete(draft)).resolves.toEqual(result);
  expect(setup).toHaveBeenCalledOnce();
});
