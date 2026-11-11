import { act, renderHook } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { useSuggestions } from '../../src/data/suggestions/useSuggestions';
import { deferred } from '../testUtils/deferred';
import type { PropertySuggestionsResponse } from '../../src/api/suggestions';

function setup() {
  const api = { get: vi.fn().mockResolvedValue({ categories: ['Zulu', 'Alpha'], names: ['Year', 'Author'] }),
    sync: vi.fn().mockResolvedValue({ categories: ['New'], names: ['Name'] }) };
  return { api, ...renderHook(() => useSuggestions(api)) };
}

describe('suggestions module', () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => { vi.useRealTimers(); vi.restoreAllMocks(); });

  it('sorts a copy of the response, caches it, and deduplicates trimmed local suggestions', async () => {
    const { api, result } = setup();
    const data = { categories: ['Zulu', 'Alpha'], names: ['Year', 'Author'] };
    api.get.mockResolvedValue(data);
    await act(async () => { await result.current.loadPropertySuggestions(1); });
    expect(data.categories).toEqual(['Zulu', 'Alpha']);
    expect(data.names).toEqual(['Year', 'Author']);
    expect(result.current.propertyCategorySuggestions).toEqual(['Alpha', 'Zulu']);
    expect(result.current.propertyNameSuggestions).toEqual(['Author', 'Year']);
    await act(async () => { await result.current.loadPropertySuggestions(1); });
    expect(api.get).toHaveBeenCalledTimes(1);
    act(() => {
      result.current.addLocalCategorySuggestion(' Beta ');
      result.current.addLocalCategorySuggestion('Beta');
      result.current.addLocalCategorySuggestion(' ');
      result.current.addLocalNameSuggestion(' Publisher ');
      result.current.addLocalNameSuggestion('Publisher');
      result.current.addLocalNameSuggestion(' ');
    });
    expect(result.current.propertyCategorySuggestions).toEqual(['Alpha', 'Beta', 'Zulu']);
    expect(result.current.propertyNameSuggestions).toEqual(['Author', 'Publisher', 'Year']);
  });

  it('debounces each collection independently and only updates the selected view', async () => {
    const { api, result } = setup();
    await act(async () => { await result.current.loadPropertySuggestions(1); });
    await act(async () => {
      await result.current.syncPropertySuggestions(1);
      await result.current.syncPropertySuggestions(1);
      await result.current.syncPropertySuggestions(2);
    });
    await act(async () => { await vi.advanceTimersByTimeAsync(1999); });
    expect(api.sync).not.toHaveBeenCalled();
    await act(async () => { await vi.advanceTimersByTimeAsync(1); });
    expect(api.sync.mock.calls).toEqual([[1], [2]]);
    expect(result.current.propertyCategorySuggestions).toEqual(['New']);
    await act(async () => { await result.current.loadPropertySuggestions(2); });
    expect(api.get).toHaveBeenCalledTimes(1);
    expect(result.current.propertyNameSuggestions).toEqual(['Name']);
  });

  it('clears old suggestions while a new collection loads and ignores a late response for the old view', async () => {
    const { api, result } = setup();
    const old = deferred<PropertySuggestionsResponse>();
    api.get.mockReturnValueOnce(old.promise);
    let request!: Promise<void>;
    act(() => { request = result.current.loadPropertySuggestions(1); });
    await act(async () => { await result.current.loadPropertySuggestions(2); });
    await act(async () => { old.resolve({ categories: ['Old'], names: [] }); await request; });
    expect(result.current.propertyCategorySuggestions).toEqual(['Alpha', 'Zulu']);
    await act(async () => { await result.current.loadPropertySuggestions(1); });
    expect(result.current.propertyCategorySuggestions).toEqual(['Old']);
  });

  it('ignores a stale response for the same collection', async () => {
    const { api, result } = setup();
    const old = deferred<PropertySuggestionsResponse>();
    api.get.mockReturnValueOnce(old.promise);
    let request!: Promise<void>;
    act(() => { request = result.current.loadPropertySuggestions(1); });
    await act(async () => { await result.current.loadPropertySuggestions(1); });
    await act(async () => { old.resolve({ categories: ['Old'], names: [] }); await request; });
    expect(result.current.propertyCategorySuggestions).toEqual(['Alpha', 'Zulu']);
  });

  it('handles load and sync failures without discarding available suggestions', async () => {
    const { api, result } = setup();
    const log = vi.spyOn(console, 'error').mockImplementation(() => {});
    api.get.mockRejectedValueOnce(new Error('Offline'));
    await act(async () => { await result.current.loadPropertySuggestions(1); });
    expect(result.current.propertyCategorySuggestions).toEqual([]);
    await act(async () => { await result.current.loadPropertySuggestions(1); });
    api.sync.mockRejectedValueOnce(new Error('Offline'));
    await act(async () => { await result.current.syncPropertySuggestions(1); await vi.runAllTimersAsync(); });
    expect(result.current.propertyCategorySuggestions).toEqual(['Alpha', 'Zulu']);
    expect(log).toHaveBeenCalledTimes(2);
  });

  it('cancels scheduled synchronization and ignores in-flight responses on unmount', async () => {
    const { api, result, unmount } = setup();
    const pending = deferred<PropertySuggestionsResponse>();
    api.get.mockReturnValueOnce(pending.promise);
    let request!: Promise<void>;
    act(() => { request = result.current.loadPropertySuggestions(1); });
    await act(async () => { await result.current.syncPropertySuggestions(1); });
    unmount();
    await act(async () => {
      pending.resolve({ categories: ['Late'], names: [] });
      await request;
      await vi.runAllTimersAsync();
    });
    expect(api.sync).not.toHaveBeenCalled();
    expect(result.current.propertyCategorySuggestions).toEqual([]);
  });

  it('preserves and caches local hints added while a read is pending without mutating the response', async () => {
    const { api, result } = setup();
    const pending = deferred<PropertySuggestionsResponse>();
    const response = { categories: ['Server', 'Server'], names: ['Author'] };
    api.get.mockReturnValueOnce(pending.promise);
    let request!: Promise<void>;
    act(() => { request = result.current.loadPropertySuggestions(1); });
    act(() => {
      result.current.addLocalCategorySuggestion(' Local ');
      result.current.addLocalNameSuggestion(' Title ');
      result.current.addLocalNameSuggestion('Title');
    });
    await act(async () => { pending.resolve(response); await request; });
    expect(result.current.propertyCategorySuggestions).toEqual(['Local', 'Server']);
    expect(result.current.propertyNameSuggestions).toEqual(['Author', 'Title']);
    expect(response).toEqual({ categories: ['Server', 'Server'], names: ['Author'] });
    await act(async () => { await result.current.loadPropertySuggestions(2); await result.current.loadPropertySuggestions(1); });
    expect(result.current.propertyCategorySuggestions).toEqual(['Local', 'Server']);
    expect(api.get).toHaveBeenCalledTimes(2);
  });

  it('keeps local hints with their collection across navigation and allows a later synchronization to remove unused hints', async () => {
    const { api, result } = setup();
    await act(async () => { await result.current.loadPropertySuggestions(1); });
    act(() => { result.current.addLocalNameSuggestion('Local'); });
    await act(async () => { await result.current.loadPropertySuggestions(2); });
    expect(result.current.propertyNameSuggestions).not.toContain('Local');
    await act(async () => { await result.current.loadPropertySuggestions(1); });
    expect(result.current.propertyNameSuggestions).toEqual(['Author', 'Local', 'Year']);
    await act(async () => { await result.current.syncPropertySuggestions(1); await vi.advanceTimersByTimeAsync(2000); });
    expect(result.current.propertyNameSuggestions).toEqual(['Name']);
    expect(api.sync).toHaveBeenCalledOnce();
  });

  it('joins an in-flight synchronization instead of replacing it with an older ordinary read', async () => {
    const { api, result } = setup();
    const pending = deferred<PropertySuggestionsResponse>();
    api.sync.mockReturnValueOnce(pending.promise);
    await act(async () => { await result.current.syncPropertySuggestions(1); await vi.advanceTimersByTimeAsync(2000); });
    let request!: Promise<void>;
    act(() => { request = result.current.loadPropertySuggestions(1); });
    expect(api.get).not.toHaveBeenCalled();
    act(() => { result.current.addLocalNameSuggestion('Editing'); });
    await act(async () => { pending.resolve({ categories: ['Current'], names: ['Saved'] }); await request; });
    expect(result.current.propertyNameSuggestions).toEqual(['Editing', 'Saved']);
    expect(result.current.propertyCategorySuggestions).toEqual(['Current']);
  });

  it('carries additions into a replacement read and does not let its predecessor undo them', async () => {
    const { api, result } = setup();
    const pending = deferred<PropertySuggestionsResponse>();
    const fresh = deferred<PropertySuggestionsResponse>();
    api.get.mockReturnValueOnce(pending.promise).mockReturnValueOnce(fresh.promise);
    let old!: Promise<void>;
    let current!: Promise<void>;
    act(() => { old = result.current.loadPropertySuggestions(1); });
    act(() => { result.current.addLocalCategorySuggestion('Draft'); });
    act(() => { current = result.current.loadPropertySuggestions(1); });
    expect(result.current.propertyCategorySuggestions).toEqual(['Draft']);
    await act(async () => { fresh.resolve({ categories: ['Zulu', 'Alpha'], names: [] }); await current; });
    await act(async () => { pending.resolve({ categories: ['Obsolete'], names: [] }); await old; });
    expect(result.current.propertyCategorySuggestions).toEqual(['Alpha', 'Draft', 'Zulu']);
  });

  it('reconciles pending additions independently when both collections finish after navigation', async () => {
    const { api, result } = setup();
    const first = deferred<PropertySuggestionsResponse>();
    const second = deferred<PropertySuggestionsResponse>();
    api.get.mockReturnValueOnce(first.promise).mockReturnValueOnce(second.promise);
    let old!: Promise<void>;
    let current!: Promise<void>;
    act(() => { old = result.current.loadPropertySuggestions(1); });
    act(() => { result.current.addLocalNameSuggestion('First draft'); });
    act(() => { current = result.current.loadPropertySuggestions(2); });
    act(() => { result.current.addLocalNameSuggestion('Second draft'); });
    await act(async () => { first.resolve({ categories: [], names: ['First saved'] }); await old; });
    expect(result.current.propertyNameSuggestions).toEqual(['Second draft']);
    await act(async () => { second.resolve({ categories: [], names: ['Second saved'] }); await current; });
    expect(result.current.propertyNameSuggestions).toEqual(['Second draft', 'Second saved']);
    await act(async () => { await result.current.loadPropertySuggestions(1); });
    expect(result.current.propertyNameSuggestions).toEqual(['First draft', 'First saved']);
  });

  it('allows local editing without a selected collection and prevents callbacks from restarting work after unmount', async () => {
    const { api, result, unmount } = setup();
    act(() => { result.current.addLocalCategorySuggestion('Category'); result.current.addLocalNameSuggestion('Name'); });
    expect(result.current.propertyCategorySuggestions).toEqual(['Category']);
    expect(result.current.propertyNameSuggestions).toEqual(['Name']);
    unmount();
    await act(async () => {
      await result.current.loadPropertySuggestions(1);
      await result.current.syncPropertySuggestions(1);
      result.current.addLocalNameSuggestion('Retired');
      await vi.runAllTimersAsync();
    });
    expect(api.get).not.toHaveBeenCalled();
    expect(api.sync).not.toHaveBeenCalled();
    expect(result.current.propertyNameSuggestions).toEqual(['Name']);
  });

  it.each(['unmount', 'newer read'] as const)('does not report an obsolete failure after %s', async reason => {
    const { api, result, unmount } = setup();
    const log = vi.spyOn(console, 'error').mockImplementation(() => {});
    const pending = deferred<PropertySuggestionsResponse>();
    api.get.mockReturnValueOnce(pending.promise);
    let old!: Promise<void>;
    act(() => { old = result.current.loadPropertySuggestions(1); });
    if (reason === 'unmount') unmount();
    else await act(async () => { await result.current.loadPropertySuggestions(1); });
    await act(async () => { pending.reject(new Error('Obsolete')); await old; });
    expect(log).not.toHaveBeenCalled();
  });

  it('retries normally after a joined synchronization fails', async () => {
    const { api, result } = setup();
    const log = vi.spyOn(console, 'error').mockImplementation(() => {});
    const pending = deferred<PropertySuggestionsResponse>();
    api.sync.mockReturnValueOnce(pending.promise);
    await act(async () => { await result.current.syncPropertySuggestions(1); await vi.advanceTimersByTimeAsync(2000); });
    let request!: Promise<void>;
    act(() => { request = result.current.loadPropertySuggestions(1); });
    await act(async () => { pending.reject(new Error('Offline')); await request; });
    await act(async () => { await result.current.loadPropertySuggestions(1); });
    expect(log).toHaveBeenCalledOnce();
    expect(api.get).toHaveBeenCalledOnce();
    expect(result.current.propertyCategorySuggestions).toEqual(['Alpha', 'Zulu']);
  });
});
