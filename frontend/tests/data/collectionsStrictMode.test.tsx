import { StrictMode, useEffect } from 'react';
import { act, render, screen } from '@testing-library/react';
import { expect, it, vi } from 'vitest';
import { useCollections } from '../../src/data/collections/useCollections';
import { createMockCollection } from '../testUtils/factories';
import { deferred } from '../testUtils/deferred';
import type { Collection } from '../../src/utils/types';

it('finishes the initial collection read when StrictMode replays provider and child effects', async () => {
  const response = deferred<Collection[]>();
  const retired = deferred<Collection[]>();
  const gateway = { getAll: vi.fn().mockReturnValueOnce(retired.promise).mockReturnValueOnce(response.promise), create: vi.fn(), setup: vi.fn(), update: vi.fn(), delete: vi.fn() };
  function Reader({ data }: { data: ReturnType<typeof useCollections> }) {
    const { loadCollections } = data;
    useEffect(() => { void loadCollections(); }, [loadCollections]);
    return <div>{data.collectionsLoading ? 'Loading collections' : data.collections.map(collection => collection.name).join(', ')}</div>;
  }
  function Provider() {
    return <Reader data={useCollections(gateway)} />;
  }
  render(<StrictMode><Provider /></StrictMode>);
  expect(gateway.getAll).toHaveBeenCalledTimes(2);
  await act(async () => { response.resolve([createMockCollection({ name: 'Persisted collection' })]); });
  await act(async () => { retired.resolve([createMockCollection({ name: 'Retired collection' })]); });
  expect(screen.queryByText('Loading collections')).not.toBeInTheDocument();
  expect(screen.getByText('Persisted collection')).toBeInTheDocument();
  expect(screen.queryByText('Retired collection')).not.toBeInTheDocument();
});
