import { beforeEach, expect, it, vi } from 'vitest';
import { setupAttemptStorage } from '../../src/data/onboarding/setupAttemptStorage';

const attempt = { requestId: 'a1234567-1234-1234-1234-123456789abc',
  draft: { workspaceName: 'Study', collectionName: 'Books', description: 'Editions', themeId: 2 } };
const saved = { version: 1, ...attempt };
beforeEach(() => sessionStorage.clear());

it('round-trips an attempt across instances and isolates different accounts', () => {
  const first = setupAttemptStorage(1);
  expect(first.read()).toBeUndefined();
  first.clear(attempt.requestId);
  first.save(attempt);
  first.save(attempt);
  const restored = setupAttemptStorage(1);
  expect(restored.read()).toEqual(attempt);
  const other = setupAttemptStorage(2);
  expect(other.read()).toBeUndefined();
  other.save({ ...attempt, draft: { ...attempt.draft, workspaceName: 'Other user' } });
  restored.clear('another-request');
  expect(first.read()).toEqual(attempt);
  restored.clear(attempt.requestId);
  expect(first.read()).toBeUndefined();
  expect(other.read()?.draft.workspaceName).toBe('Other user');
});

it('does not overwrite an unresolved attempt with a different creation', () => {
  const store = setupAttemptStorage(1);
  store.save(attempt);
  expect(() => store.save({ ...attempt, requestId: 'b1234567-1234-1234-1234-123456789abc' })).toThrow('Another workspace setup');
  expect(store.read()).toEqual(attempt);
});

it.each([
  'bad JSON', 'null', '1', JSON.stringify({ ...saved, version: 2 }),
  JSON.stringify({ ...saved, requestId: 1 }), JSON.stringify({ ...saved, requestId: 'invalid' }),
  JSON.stringify({ ...saved, draft: null }), JSON.stringify({ ...saved, draft: 'invalid' }),
  ...['workspaceName', 'collectionName', 'description', 'themeId'].map(field => JSON.stringify({ ...saved, draft: { ...attempt.draft, [field]: null } })),
  JSON.stringify({ ...saved, draft: { ...attempt.draft, themeId: 0 } }),
])('retains malformed storage instead of silently losing the creation identity (%s)', value => {
  sessionStorage.setItem('workspace-setup:1', value);
  const store = setupAttemptStorage(1);
  expect(() => store.read()).toThrow('Saved workspace setup could not be read');
  expect(() => store.clear(attempt.requestId)).toThrow('Saved workspace setup could not be read');
  expect(sessionStorage.getItem('workspace-setup:1')).toBe(value);
});

it('propagates unavailable storage and never claims to persist a failed write', () => {
  const blocked = setupAttemptStorage(1, () => { throw new Error('Storage blocked'); });
  expect(() => blocked.read()).toThrow('Storage blocked');
  const full = setupAttemptStorage(1, () => ({ getItem: () => null, setItem: () => { throw new Error('Storage full'); }, removeItem: vi.fn() }));
  expect(() => full.save(attempt)).toThrow('Storage full');
});
