import { act, renderHook } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { prepareSupportRequest, type SupportDraft } from '../../src/data/support/supportDraft';
import { useSupportSubmission } from '../../src/data/support/useSupportSubmission';
import { sessionSupportDismissal } from '../../src/data/support/supportDismissal';
import { supportRequest } from '../testUtils/support';
import { deferred } from '../testUtils/deferred';

const draft: SupportDraft = { subject: ' Help ', description: ' Details ', email: ' reader@example.com ' };

describe('support request preparation', () => {
  it('normalizes fields without changing the draft and never sends an authenticated email override', () => {
    expect(prepareSupportRequest(draft, false)).toEqual({ subject: 'Help', description: 'Details', email: 'reader@example.com' });
    expect(prepareSupportRequest({ ...draft, email: 'invalid' }, true)).toEqual({ subject: 'Help', description: 'Details' });
    expect(draft.subject).toBe(' Help ');
    expect(prepareSupportRequest({ subject: 's'.repeat(200), description: 'd'.repeat(4000), email: 'x'.repeat(314) + '@a.com' }, false).email).toHaveLength(320);
  });
  it.each([
    [{ subject: '   ' }, 'Enter a subject'],
    [{ subject: 's'.repeat(201) }, '200 characters'],
    [{ description: '\n ' }, 'Describe how'],
    [{ description: 'd'.repeat(4001) }, '4,000 characters'],
    [{ email: '' }, 'valid email'],
    [{ email: 'reader@localhost' }, 'valid email'],
    [{ email: 'bad email@example.com' }, 'valid email'],
    [{ email: 'x'.repeat(315) + '@a.com' }, 'valid email'],
  ])('rejects invalid payload %o', (changes, message) => {
    expect(() => prepareSupportRequest({ ...draft, ...changes }, false)).toThrow(message);
  });
});

it('retains failed drafts, serializes writes, and never resubmits a completed request', async () => {
  const pending = deferred<ReturnType<typeof supportRequest>>();
  const gateway = { create: vi.fn().mockReturnValueOnce(pending.promise).mockResolvedValue(supportRequest()) };
  const { result } = renderHook(() => useSupportSubmission(true, gateway));
  expect(result.current.dirty).toBe(false);
  act(() => result.current.setDraft(draft));
  expect(result.current.dirty).toBe(true);
  act(() => { void result.current.submit(); void result.current.submit(); });
  expect(result.current.pending).toBe(true);
  expect(gateway.create).toHaveBeenCalledExactlyOnceWith({ subject: 'Help', description: 'Details' });
  await act(async () => pending.reject(null));
  expect(result.current.error).toBe('Failed to submit support request');
  expect(result.current.draft).toEqual(draft);
  await act(async () => { await result.current.submit(); });
  expect(result.current.submitted).toBe(true);
  expect(result.current.dirty).toBe(false);
  await act(async () => { await result.current.submit(); });
  expect(gateway.create).toHaveBeenCalledTimes(2);
});

it('validates empty drafts before calling the gateway', async () => {
  const gateway = { create: vi.fn() };
  const { result } = renderHook(() => useSupportSubmission(false, gateway));
  await act(async () => { await result.current.submit(); });
  expect(gateway.create).not.toHaveBeenCalled();
  expect(result.current.error).toBe('Enter a subject for your request.');
});

it('keeps dismissal preferences separate and tolerates unavailable session storage', () => {
  sessionStorage.clear();
  expect(sessionSupportDismissal.isDismissed(1)).toBe(false);
  sessionSupportDismissal.dismiss(1);
  expect(sessionSupportDismissal.isDismissed(1)).toBe(true);
  expect(sessionSupportDismissal.isDismissed(2)).toBe(false);
  vi.stubGlobal('sessionStorage', {
    getItem: () => { throw new Error('Storage blocked'); },
    setItem: () => { throw new Error('Storage blocked'); },
  });
  expect(sessionSupportDismissal.isDismissed(1)).toBe(false);
  expect(() => sessionSupportDismissal.dismiss(1)).not.toThrow();
  vi.unstubAllGlobals();
  sessionStorage.clear();
});
