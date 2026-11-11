import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { publishManagerApi } from '../../src/api/publishManager';

describe('publishManagerApi', () => {
  let mockFetch: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    mockFetch = vi.fn();
    vi.stubGlobal('fetch', mockFetch);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('preflight', () => {
    it('should POST to correct endpoint with action and entities', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({ ready: true, requirements: [] }),
      });

      const result = await publishManagerApi.preflight(1, 'publish', [{ type: 'item', id: 42 }]);

      const call = mockFetch.mock.calls[0];
      expect(call[0]).toBe('/api/workspaces/1/publish/preflight');
      expect(call[1].method).toBe('POST');
      const body = JSON.parse(call[1].body);
      expect(body.action).toBe('publish');
      expect(body.entities).toEqual([{ type: 'item', id: 42 }]);
      expect(result.ready).toBe(true);
    });
  });

  describe('execute', () => {
    it('should POST to correct endpoint with full request', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({ success: true, changed: [], promoted: [] }),
      });

      const request = {
        action: 'publish' as const,
        entities: [{ type: 'item' as const, id: 42 }],
        resolutions: [{ kind: 'collection-not-public' as const, collectionId: 5 }],
      };

      const result = await publishManagerApi.execute(1, request);

      const call = mockFetch.mock.calls[0];
      expect(call[0]).toBe('/api/workspaces/1/publish/execute');
      expect(call[1].method).toBe('POST');
      expect(result.success).toBe(true);
    });
  });
});

it('forwards cancellation through both publication requests', async () => {
  const { api } = await import('../../src/api/client');
  const post = vi.spyOn(api, 'post').mockResolvedValue({});
  const options = { signal: new AbortController().signal };
  await publishManagerApi.preflight(7, 'unpublish', [], options);
  expect(post).toHaveBeenLastCalledWith('/workspaces/7/publish/preflight', { action: 'unpublish', entities: [] }, options);
  await publishManagerApi.execute(7, { action: 'publish', entities: [], resolutions: [] }, options);
  expect(post).toHaveBeenLastCalledWith('/workspaces/7/publish/execute', { action: 'publish', entities: [], resolutions: [] }, options);
  post.mockRestore();
});
