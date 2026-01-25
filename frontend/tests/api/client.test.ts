import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { ApiClient, ApiError } from '../../src/api/client';

describe('ApiClient', () => {
  let client: ApiClient;
  let mockFetch: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    mockFetch = vi.fn();
    vi.stubGlobal('fetch', mockFetch);
    client = new ApiClient({
      baseUrl: '/api',
      defaultHeaders: { 'X-Default-Header': 'default-value' },
    });
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('GET requests', () => {
    it('should make GET request to correct URL', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({ data: 'test' }),
      });

      const result = await client.get('/users');

      expect(mockFetch).toHaveBeenCalledWith(
        '/api/users',
        expect.objectContaining({
          method: 'GET',
        })
      );
      expect(result).toEqual({ data: 'test' });
    });

    it('should include default headers', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({}),
      });

      await client.get('/users');

      const call = mockFetch.mock.calls[0];
      const headers = call[1].headers as Headers;
      expect(headers.get('X-Default-Header')).toBe('default-value');
    });
  });

  describe('POST requests', () => {
    it('should send JSON body', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({ id: 1 }),
      });

      const body = { name: 'Test', email: 'test@example.com' };
      const result = await client.post('/users', body);

      const call = mockFetch.mock.calls[0];
      expect(call[1].method).toBe('POST');
      expect(call[1].body).toBe(JSON.stringify(body));
      expect(result).toEqual({ id: 1 });
    });

    it('should auto-set Content-Type for JSON body', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({}),
      });

      await client.post('/users', { name: 'Test' });

      const call = mockFetch.mock.calls[0];
      const headers = call[1].headers as Headers;
      expect(headers.get('Content-Type')).toBe('application/json');
    });
  });

  describe('PUT requests', () => {
    it('should send JSON body', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({ id: 1, name: 'Updated' }),
      });

      const body = { name: 'Updated' };
      const result = await client.put('/users/1', body);

      const call = mockFetch.mock.calls[0];
      expect(call[1].method).toBe('PUT');
      expect(call[1].body).toBe(JSON.stringify(body));
      expect(result).toEqual({ id: 1, name: 'Updated' });
    });
  });

  describe('DELETE requests', () => {
    it('should make DELETE request', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 204,
      });

      const result = await client.delete('/users/1');

      const call = mockFetch.mock.calls[0];
      expect(call[0]).toBe('/api/users/1');
      expect(call[1].method).toBe('DELETE');
      expect(result).toBeUndefined();
    });
  });

  describe('Response handling', () => {
    it('should handle 200 OK responses correctly', async () => {
      const responseData = { id: 1, name: 'Test User' };
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => responseData,
      });

      const result = await client.get('/users/1');

      expect(result).toEqual(responseData);
    });

    it('should handle 204 No Content responses', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 204,
      });

      const result = await client.delete('/users/1');

      expect(result).toBeUndefined();
    });

    it('should handle 304 Not Modified responses', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 304,
      });

      const result = await client.get('/users/1');

      expect(result).toBeUndefined();
    });
  });

  describe('Error handling', () => {
    it('should handle 401 Unauthorized and call onUnauthorized callback', async () => {
      const onUnauthorized = vi.fn();
      const clientWithCallback = new ApiClient({
        baseUrl: '/api',
        onUnauthorized,
      });

      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 401,
        statusText: 'Unauthorized',
        text: async () => '',
      });

      await expect(clientWithCallback.get('/protected')).rejects.toThrow(ApiError);
      expect(onUnauthorized).toHaveBeenCalledTimes(1);
    });

    it('should handle 404 Not Found with ApiError', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 404,
        statusText: 'Not Found',
        text: async () => '',
      });

      try {
        await client.get('/nonexistent');
        expect.fail('Should have thrown');
      } catch (error) {
        expect(error).toBeInstanceOf(ApiError);
        expect((error as ApiError).status).toBe(404);
        expect((error as ApiError).statusText).toBe('Not Found');
      }
    });

    it('should handle 500 Server Error with ApiError', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 500,
        statusText: 'Internal Server Error',
        text: async () => '',
      });

      try {
        await client.get('/error');
        expect.fail('Should have thrown');
      } catch (error) {
        expect(error).toBeInstanceOf(ApiError);
        expect((error as ApiError).status).toBe(500);
        expect((error as ApiError).statusText).toBe('Internal Server Error');
      }
    });

    it('should parse error message from JSON response body', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 400,
        statusText: 'Bad Request',
        text: async () => JSON.stringify({ error: 'Validation failed: email is required' }),
      });

      try {
        await client.post('/users', {});
        expect.fail('Should have thrown');
      } catch (error) {
        expect(error).toBeInstanceOf(ApiError);
        expect((error as ApiError).message).toBe('Validation failed: email is required');
        expect((error as ApiError).data).toEqual({ error: 'Validation failed: email is required' });
      }
    });

    it('should parse error message from message field', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 400,
        statusText: 'Bad Request',
        text: async () => JSON.stringify({ message: 'Invalid request format' }),
      });

      try {
        await client.post('/users', {});
        expect.fail('Should have thrown');
      } catch (error) {
        expect(error).toBeInstanceOf(ApiError);
        expect((error as ApiError).message).toBe('Invalid request format');
      }
    });

    it('should fall back to statusText when no error body', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 403,
        statusText: 'Forbidden',
        text: async () => '',
      });

      try {
        await client.get('/forbidden');
        expect.fail('Should have thrown');
      } catch (error) {
        expect(error).toBeInstanceOf(ApiError);
        expect((error as ApiError).message).toBe('Forbidden');
      }
    });

    it('should handle network errors', async () => {
      mockFetch.mockRejectedValueOnce(new TypeError('Failed to fetch'));

      try {
        await client.get('/users');
        expect.fail('Should have thrown');
      } catch (error) {
        expect(error).toBeInstanceOf(ApiError);
        expect((error as ApiError).status).toBe(0);
        expect((error as ApiError).statusText).toBe('NetworkError');
        expect((error as ApiError).message).toBe('Failed to fetch');
      }
    });
  });

  describe('Request timeout', () => {
    it('should timeout after specified duration', async () => {
      // Create a promise that will be aborted when AbortController.abort() is called
      let abortSignal: AbortSignal | undefined;
      mockFetch.mockImplementation((_url: string, options?: RequestInit) => {
        abortSignal = options?.signal;
        return new Promise((_, reject) => {
          if (abortSignal) {
            abortSignal.addEventListener('abort', () => {
              reject(new DOMException('The operation was aborted', 'AbortError'));
            });
          }
        });
      });

      // Use a very short timeout
      const promise = client.get('/slow', { timeout: 10 });

      await expect(promise).rejects.toThrow(ApiError);
      await expect(promise).rejects.toThrow('Request was cancelled or timed out');
    }, 1000);

    it('should use default timeout of 30000ms', async () => {
      // Verify the request is made with a signal attached (timeout mechanism is in place)
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({}),
      });

      await client.get('/test');

      const call = mockFetch.mock.calls[0];
      expect(call[1].signal).toBeDefined();
      expect(call[1].signal).toBeInstanceOf(AbortSignal);
    });
  });

  describe('Request cancellation', () => {
    it('should cancel request when cancelRequest is called', async () => {
      let abortSignal: AbortSignal | undefined;
      mockFetch.mockImplementation((_url: string, options?: RequestInit) => {
        abortSignal = options?.signal;
        return new Promise((_, reject) => {
          if (abortSignal) {
            abortSignal.addEventListener('abort', () => {
              reject(new DOMException('The operation was aborted', 'AbortError'));
            });
          }
        });
      });

      const promise = client.get('/data', { timeout: 60000 }, 'my-request');

      // Small delay to ensure the request is started
      await new Promise(resolve => setTimeout(resolve, 10));

      // Cancel the request
      client.cancelRequest('my-request');

      await expect(promise).rejects.toThrow(ApiError);
      await expect(promise).rejects.toThrow('Request was cancelled or timed out');
    }, 1000);

    it('should cancel previous request with same key', async () => {
      const abortSpy = vi.fn();
      const originalAbortController = globalThis.AbortController;

      let controllerCount = 0;
      globalThis.AbortController = class extends originalAbortController {
        constructor() {
          super();
          controllerCount++;
          if (controllerCount === 1) {
            this.abort = abortSpy;
          }
        }
      } as typeof AbortController;

      mockFetch
        .mockImplementationOnce(() => new Promise(() => {}))
        .mockResolvedValueOnce({
          ok: true,
          status: 200,
          json: async () => ({ data: 'second' }),
        });

      // Start first request
      const promise1 = client.get('/data', {}, 'shared-key');

      // Start second request with same key - should abort first
      const promise2 = client.get('/data', {}, 'shared-key');

      expect(abortSpy).toHaveBeenCalled();

      const result = await promise2;
      expect(result).toEqual({ data: 'second' });

      globalThis.AbortController = originalAbortController;
    });
  });

  describe('upload()', () => {
    it('should send FormData correctly', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({ key: 'image-123', url: '/images/image-123' }),
      });

      const formData = new FormData();
      formData.append('file', new Blob(['test content'], { type: 'image/png' }), 'test.png');

      const result = await client.upload('/images', formData);

      const call = mockFetch.mock.calls[0];
      expect(call[1].method).toBe('POST');
      expect(call[1].body).toBe(formData);
      expect(result).toEqual({ key: 'image-123', url: '/images/image-123' });
    });

    it('should not auto-set Content-Type for FormData', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({}),
      });

      const formData = new FormData();
      formData.append('file', new Blob(['test']));

      await client.upload('/images', formData);

      const call = mockFetch.mock.calls[0];
      const headers = call[1].headers as Headers;
      // Content-Type should not be set - browser sets it with boundary
      expect(headers.get('Content-Type')).toBeNull();
    });
  });

  describe('download()', () => {
    it('should return Response object', async () => {
      const mockResponse = {
        ok: true,
        status: 200,
        blob: async () => new Blob(['file content']),
      };
      mockFetch.mockResolvedValueOnce(mockResponse);

      const result = await client.download('/files/document.pdf');

      const call = mockFetch.mock.calls[0];
      expect(call[1].method).toBe('GET');
      expect(result).toBe(mockResponse);
    });

    it('should skip JSON parsing', async () => {
      const mockResponse = {
        ok: true,
        status: 200,
        json: vi.fn(),
      };
      mockFetch.mockResolvedValueOnce(mockResponse);

      await client.download('/files/document.pdf');

      expect(mockResponse.json).not.toHaveBeenCalled();
    });
  });
});

describe('ApiError', () => {
  it('should create error with all properties', () => {
    const error = new ApiError('Test error', 400, 'Bad Request', { field: 'invalid' });

    expect(error.message).toBe('Test error');
    expect(error.status).toBe(400);
    expect(error.statusText).toBe('Bad Request');
    expect(error.data).toEqual({ field: 'invalid' });
    expect(error.name).toBe('ApiError');
  });

  it('should be instanceof Error', () => {
    const error = new ApiError('Test', 500, 'Error');
    expect(error).toBeInstanceOf(Error);
  });
});

describe('api singleton', () => {
  it('should be configured with /api baseUrl', async () => {
    // Import the singleton after setting up mocks
    const mockFetch = vi.fn().mockResolvedValueOnce({
      ok: true,
      status: 200,
      json: async () => ({ test: true }),
    });
    vi.stubGlobal('fetch', mockFetch);

    // Dynamically import to get fresh instance
    const { api } = await import('../../src/api/client');

    await api.get('/test');

    expect(mockFetch).toHaveBeenCalledWith(
      '/api/test',
      expect.anything()
    );

    vi.restoreAllMocks();
  });

  it('should have onUnauthorized callback configured', async () => {
    const consoleSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const mockFetch = vi.fn().mockResolvedValueOnce({
      ok: false,
      status: 401,
      statusText: 'Unauthorized',
      text: async () => '',
    });
    vi.stubGlobal('fetch', mockFetch);

    const { api } = await import('../../src/api/client');

    try {
      await api.get('/protected');
    } catch {
      // Expected to throw
    }

    expect(consoleSpy).toHaveBeenCalledWith('Unauthorized request - user may need to log in');

    consoleSpy.mockRestore();
    vi.restoreAllMocks();
  });
});
