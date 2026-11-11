import { describe, expect, it, vi } from 'vitest';
import { waitFor } from '@testing-library/react';
import { createPublicationSession, type PublicationPhase } from '../../src/data/publishing/publicationSession';
import { publicationNotice, requirementKey, resolveRequirements } from '../../src/data/publishing/publicationRequirements';
import type { ExecuteResponse, PreflightResponse, PublishRequirement } from '../../src/utils/types';
import { collectionRequirement, publicationOptions, requirements, saved } from '../testUtils/publication';
import { deferred } from '../testUtils/deferred';

const unknown = { kind: 'future-requirement' } as unknown as PublishRequirement;
function setup() {
  const options = publicationOptions();
  const session = createPublicationSession(options);
  const phase = (value: PublicationPhase) => waitFor(() => expect(session.getSnapshot().phase).toBe(value));
  return { ...options, session, phase };
}

describe('publication consent policy', () => {
  it('requires valid URL and explicit consent for every impacted entity', () => {
    const draft = { slug: '', acknowledged: new Set<string>() };
    expect(resolveRequirements(requirements, draft)).toBeNull();
    draft.slug = ' library ';
    expect(resolveRequirements(requirements, draft)).toBeNull();
    draft.acknowledged = new Set(requirements.map(requirement => requirementKey(requirement)!));
    expect(resolveRequirements(requirements, draft)).toEqual([
      { kind: 'workspace-slug-required', slug: 'library' },
      { kind: 'collection-not-public', collectionId: 2 },
      { kind: 'category-not-public', categoryId: 3 },
      { kind: 'unpublish-will-hide-children', entityType: 'category', entityId: 3, affectedPublicItems: 1, affectedPublicCategories: 1 },
    ]);
    expect(resolveRequirements([unknown], draft)).toBeNull();
    expect(resolveRequirements([], draft)).toEqual([]);
  });
  it('summarizes changed and promoted entities without calling categories items', () => {
    expect(publicationNotice('publish', { ...saved, changed: [] })).toEqual({ message: 'Visibility updated.', details: undefined });
    expect(publicationNotice('publish', saved).message).toBe('Dune published.');
    expect(publicationNotice('unpublish', saved).message).toBe('Dune made private.');
    expect(publicationNotice('unpublish', { ...saved, changed: [...saved.changed, ...saved.changed], promoted: [{ type: 'collection', id: 2, name: 'Books' }] }))
      .toEqual({ message: '2 entries made private.', details: 'Also made public: Books.' });
  });
});

describe('publication session', () => {
  it('requires preflight consent, locks duplicate writes and completes only after refresh', async () => {
    const { session, gateway, refresh, complete, dismiss, phase } = setup();
    const write = deferred<ExecuteResponse>();
    const read = deferred<void>();
    gateway.execute.mockReturnValue(write.promise);
    refresh.mockReturnValue(read.promise);
    const listener = vi.fn();
    const unsubscribe = session.subscribe(listener);
    session.setSlug('ignored'); session.toggle('collection:2');
    await session.submit(); await session.retry();
    expect(gateway.execute).not.toHaveBeenCalled();
    session.start();
    await phase('review');
    await session.submit();
    expect(gateway.execute).not.toHaveBeenCalled();
    session.toggle('collection:2'); session.toggle('collection:2');
    expect(session.getSnapshot().draft.acknowledged.size).toBe(0);
    session.setSlug('library'); session.toggle('collection:2');
    const submit = session.submit();
    await phase('saving');
    session.cancel(); session.setSlug('changed'); session.toggle('collection:2');
    await session.submit(); await session.retry();
    expect(session.getSnapshot().draft.slug).toBe('library');
    expect(dismiss).not.toHaveBeenCalled();
    expect(gateway.execute).toHaveBeenCalledExactlyOnceWith(7, {
      action: 'publish', entities: [{ type: 'item', id: 4 }], resolutions: [{ kind: 'collection-not-public', collectionId: 2 }],
    }, { signal: expect.any(AbortSignal) });
    write.resolve(saved);
    await phase('refreshing');
    session.cancel();
    expect(complete).not.toHaveBeenCalled();
    read.resolve(); await submit;
    expect(complete).toHaveBeenCalledExactlyOnceWith(saved);
    session.cancel(); await session.retry();
    expect(dismiss).not.toHaveBeenCalled();
    expect(refresh).toHaveBeenCalledTimes(1);
    expect(listener).toHaveBeenCalled();
    unsubscribe(); session.stop();
  });

  it('cancels a check before network work and supports StrictMode restart', async () => {
    const { session, gateway, phase } = setup();
    session.start(); session.stop();
    await Promise.resolve();
    expect(gateway.preflight).not.toHaveBeenCalled();
    session.start(); await phase('review');
    expect(gateway.preflight).toHaveBeenCalledTimes(1);
  });

  it.each(['resolve', 'reject'] as const)('ignores a late preflight %s after cancellation', async outcome => {
    const { session, gateway, dismiss } = setup();
    const check = deferred<PreflightResponse>();
    gateway.preflight.mockReturnValue(check.promise);
    session.start(); await waitFor(() => expect(gateway.preflight).toHaveBeenCalledTimes(1));
    const signal = gateway.preflight.mock.calls[0][3]!.signal!;
    session.cancel(); session.cancel();
    expect(dismiss).toHaveBeenCalledTimes(1);
    expect(signal.aborted).toBe(true);
    if (outcome === 'resolve') check.resolve({ ready: true, requirements: [] }); else check.reject(new Error('Late failure'));
    await check.promise.catch(() => {});
    await Promise.resolve();
    expect(session.getSnapshot().phase).toBe('checking');
    expect(gateway.execute).not.toHaveBeenCalled();
  });

  it('does not execute a stopped review or modify its draft', async () => {
    const { session, gateway, phase } = setup();
    session.start(); await phase('review');
    session.toggle('collection:2'); session.stop();
    session.toggle('collection:2'); session.setSlug('ignored');
    await session.submit();
    expect(gateway.execute).not.toHaveBeenCalled();
    expect(session.getSnapshot().draft.slug).toBe('');
  });

  it.each([new Error('Offline'), null])('rechecks after preflight failures: %s', async error => {
    const { session, gateway, phase } = setup();
    gateway.preflight.mockRejectedValueOnce(error);
    session.start(); await phase('check-error');
    expect(session.getSnapshot().error).toBe(error?.message ?? 'Could not check visibility requirements.');
    await session.retry(); await phase('review');
    expect(gateway.execute).not.toHaveBeenCalled();
  });

  it('fails closed on inconsistent or unknown preflight responses', async () => {
    const { session, gateway, phase } = setup();
    gateway.preflight.mockResolvedValueOnce({ ready: false, requirements: [] }).mockResolvedValueOnce({ ready: true, requirements: [unknown] });
    session.start(); await phase('check-error');
    expect(session.getSnapshot().error).toContain('no requirements');
    await session.retry(); await phase('review');
    await session.submit();
    expect(gateway.execute).not.toHaveBeenCalled();
  });

  it('requires fresh consent when execution returns updated requirements and preserves the URL draft', async () => {
    const { session, gateway, phase } = setup();
    gateway.execute.mockResolvedValueOnce({ ...saved, success: false, requirements: [collectionRequirement] });
    session.start(); await phase('review');
    session.setSlug('library'); session.toggle('collection:2');
    await session.submit();
    expect(session.getSnapshot()).toMatchObject({ phase: 'review', error: 'Could not update visibility.', draft: { slug: 'library' } });
    expect(session.getSnapshot().draft.acknowledged.size).toBe(0);
    await session.submit();
    expect(gateway.execute).toHaveBeenCalledTimes(1);
    session.toggle('collection:2'); await session.submit();
    expect(gateway.execute).toHaveBeenCalledTimes(2);
  });

  it.each(['rejected', 'empty', 'throw'] as const)('shows automatic execution %s failures and rechecks before retry', async failure => {
    const { session, gateway, phase, complete } = setup();
    gateway.preflight.mockResolvedValue({ ready: true, requirements: [] });
    if (failure === 'throw') gateway.execute.mockRejectedValueOnce(null);
    else gateway.execute.mockResolvedValueOnce({ ...saved, success: false, error: 'Conflict', requirements: failure === 'empty' ? [] : undefined });
    session.start(); await phase('execute-error');
    expect(session.getSnapshot().error).toBe(failure === 'throw' ? 'Could not update visibility.' : 'Conflict');
    expect(complete).not.toHaveBeenCalled();
    gateway.preflight.mockResolvedValueOnce({ ready: false, requirements: [collectionRequirement] });
    await session.retry(); await phase('review');
    expect(gateway.execute).toHaveBeenCalledTimes(1);
  });

  it.each(['resolve', 'reject'] as const)('ignores an abandoned execution %s', async outcome => {
    const { session, gateway, phase, complete, refresh } = setup();
    const write = deferred<ExecuteResponse>();
    gateway.preflight.mockResolvedValue({ ready: true, requirements: [] });
    gateway.execute.mockReturnValue(write.promise);
    session.start(); await phase('saving'); session.stop();
    if (outcome === 'resolve') write.resolve(saved); else write.reject(new Error('Late error'));
    await write.promise.catch(() => {}); await Promise.resolve();
    expect(refresh).not.toHaveBeenCalled(); expect(complete).not.toHaveBeenCalled();
    expect(session.getSnapshot().phase).toBe('saving');
  });

  it.each([new Error('Refresh offline'), null])('retries only refresh after a confirmed write: %s', async error => {
    const { session, gateway, refresh, complete, phase } = setup();
    gateway.preflight.mockResolvedValue({ ready: true, requirements: [] });
    refresh.mockRejectedValueOnce(error);
    session.start(); await phase('refresh-error');
    expect(session.getSnapshot().saved).toBe(saved);
    expect(session.getSnapshot().error).toBe(error?.message ?? 'Could not refresh the updated data.');
    await session.retry();
    expect(gateway.execute).toHaveBeenCalledTimes(1);
    expect(refresh).toHaveBeenCalledTimes(2);
    expect(complete).toHaveBeenCalledExactlyOnceWith(saved);
  });

  it.each(['resolve', 'reject'] as const)('ignores an abandoned refresh %s', async outcome => {
    const { session, gateway, phase, complete, refresh } = setup();
    const read = deferred<void>();
    gateway.preflight.mockResolvedValue({ ready: true, requirements: [] });
    refresh.mockReturnValue(read.promise);
    session.start(); await phase('refreshing'); session.stop();
    if (outcome === 'resolve') read.resolve(); else read.reject(new Error('Late error'));
    await read.promise.catch(() => {}); await Promise.resolve();
    expect(complete).not.toHaveBeenCalled();
    expect(session.getSnapshot().phase).toBe('refreshing');
  });
});
