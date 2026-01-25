/**
 * Centralized API client for all HTTP requests.
 * Provides consistent error handling, request/response interceptors, and type safety.
 */

export class ApiError extends Error {
  constructor(
    message: string,
    public status: number,
    public statusText: string,
    public data?: unknown
  ) {
    super(message);
    this.name = 'ApiError';
  }
}

export interface RequestOptions extends RequestInit {
  /** Skip automatic JSON parsing of response */
  skipJsonParse?: boolean;
  /** Custom timeout in milliseconds (default: 30000) */
  timeout?: number;
}

interface ApiClientConfig {
  baseUrl: string;
  defaultHeaders?: HeadersInit;
  onUnauthorized?: () => void;
}

export class ApiClient {
  private config: ApiClientConfig;
  private abortControllers: Map<string, AbortController> = new Map();

  constructor(config: ApiClientConfig) {
    this.config = config;
  }

  /**
   * Cancel a pending request by its key.
   */
  cancelRequest(key: string): void {
    const controller = this.abortControllers.get(key);
    if (controller) {
      controller.abort();
      this.abortControllers.delete(key);
    }
  }

  /**
   * Makes a request to the API.
   * @param endpoint - The API endpoint (will be prefixed with baseUrl)
   * @param options - Fetch options plus custom ApiClient options
   * @param requestKey - Optional key for request cancellation
   */
  async request<T>(
    endpoint: string,
    options: RequestOptions = {},
    requestKey?: string
  ): Promise<T> {
    const { skipJsonParse, timeout = 30000, ...fetchOptions } = options;

    // Create AbortController for timeout and cancellation
    const controller = new AbortController();
    if (requestKey) {
      // Cancel any existing request with same key
      this.cancelRequest(requestKey);
      this.abortControllers.set(requestKey, controller);
    }

    // Set up timeout
    const timeoutId = setTimeout(() => controller.abort(), timeout);

    const url = `${this.config.baseUrl}${endpoint}`;
    const headers = new Headers(this.config.defaultHeaders);

    // Merge custom headers
    if (fetchOptions.headers) {
      const customHeaders = new Headers(fetchOptions.headers);
      customHeaders.forEach((value, key) => {
        headers.set(key, value);
      });
    }

    // Auto-set Content-Type for JSON bodies
    if (fetchOptions.body && typeof fetchOptions.body === 'string') {
      if (!headers.has('Content-Type')) {
        headers.set('Content-Type', 'application/json');
      }
    }

    try {
      const response = await fetch(url, {
        ...fetchOptions,
        headers,
        signal: controller.signal,
      });

      clearTimeout(timeoutId);

      if (requestKey) {
        this.abortControllers.delete(requestKey);
      }

      if (!response.ok) {
        // Handle 401 Unauthorized
        if (response.status === 401 && this.config.onUnauthorized) {
          this.config.onUnauthorized();
        }

        let errorData: unknown;
        let errorMessage = response.statusText;

        try {
          const text = await response.text();
          try {
            errorData = JSON.parse(text);
            errorMessage = (errorData as { error?: string; message?: string })?.error 
              || (errorData as { message?: string })?.message 
              || text 
              || response.statusText;
          } catch {
            errorMessage = text || response.statusText;
          }
        } catch {
          // Ignore parse errors
        }

        throw new ApiError(errorMessage, response.status, response.statusText, errorData);
      }

      // Handle 304 Not Modified (return undefined, caller should handle)
      if (response.status === 304) {
        return undefined as T;
      }

      // Handle 204 No Content
      if (response.status === 204) {
        return undefined as T;
      }

      if (skipJsonParse) {
        return response as unknown as T;
      }

      return await response.json();
    } catch (error) {
      clearTimeout(timeoutId);

      if (requestKey) {
        this.abortControllers.delete(requestKey);
      }

      if (error instanceof ApiError) {
        throw error;
      }

      if (error instanceof DOMException && error.name === 'AbortError') {
        throw new ApiError('Request was cancelled or timed out', 0, 'Aborted');
      }

      throw new ApiError(
        error instanceof Error ? error.message : 'Network error',
        0,
        'NetworkError'
      );
    }
  }

  // Convenience methods

  get<T>(endpoint: string, options?: RequestOptions, requestKey?: string): Promise<T> {
    return this.request<T>(endpoint, { ...options, method: 'GET' }, requestKey);
  }

  post<T>(endpoint: string, body?: unknown, options?: RequestOptions): Promise<T> {
    return this.request<T>(endpoint, {
      ...options,
      method: 'POST',
      body: body ? JSON.stringify(body) : undefined,
    });
  }

  put<T>(endpoint: string, body?: unknown, options?: RequestOptions): Promise<T> {
    return this.request<T>(endpoint, {
      ...options,
      method: 'PUT',
      body: body ? JSON.stringify(body) : undefined,
    });
  }

  delete<T>(endpoint: string, options?: RequestOptions): Promise<T> {
    return this.request<T>(endpoint, { ...options, method: 'DELETE' });
  }

  /**
   * Upload a file using FormData.
   */
  upload<T>(endpoint: string, formData: FormData, options?: RequestOptions): Promise<T> {
    return this.request<T>(endpoint, {
      ...options,
      method: 'POST',
      body: formData,
      // Don't set Content-Type - let browser set it with boundary
    });
  }

  /**
   * Download a file (returns the Response object for blob handling).
   */
  download(endpoint: string, options?: RequestOptions): Promise<Response> {
    return this.request<Response>(endpoint, {
      ...options,
      method: 'GET',
      skipJsonParse: true,
    });
  }
}

// Create singleton instance
export const api = new ApiClient({
  baseUrl: '/api',
  onUnauthorized: () => {
    // Redirect to login or handle as needed
    console.warn('Unauthorized request - user may need to log in');
  },
});

export default api;
