import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  AuthErrorType,
  buildSignInUrl,
  handleUnauthorized,
  parseAuthErrorCode,
} from '../src/utils/authErrors';

describe('parseAuthErrorCode', () => {
  it('maps SessionRevoked to AuthErrorType.SessionRevoked', () => {
    expect(parseAuthErrorCode('SessionRevoked')).toBe(AuthErrorType.SessionRevoked);
  });

  it('maps unknown codes to None', () => {
    expect(parseAuthErrorCode('SomethingElse')).toBe(AuthErrorType.None);
  });

  it('maps undefined to None', () => {
    expect(parseAuthErrorCode(undefined)).toBe(AuthErrorType.None);
  });

  it('maps non-string values to None', () => {
    expect(parseAuthErrorCode(42)).toBe(AuthErrorType.None);
    expect(parseAuthErrorCode(null)).toBe(AuthErrorType.None);
    expect(parseAuthErrorCode({})).toBe(AuthErrorType.None);
  });
});

describe('buildSignInUrl', () => {
  it('includes the error type name and encoded return URL', () => {
    const url = buildSignInUrl(AuthErrorType.SessionRevoked, '/collections/5?tab=items');

    expect(url).toBe('/signin?errorType=SessionRevoked&returnUrl=%2Fcollections%2F5%3Ftab%3Ditems');
  });
});

describe('handleUnauthorized', () => {
  let fakeLocation: { pathname: string; search: string; href: string };

  beforeEach(() => {
    fakeLocation = { pathname: '/collections/5', search: '?tab=items', href: '' };
    vi.stubGlobal('location', fakeLocation);
    vi.spyOn(console, 'warn').mockImplementation(() => {});
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it('redirects to sign-in with error type and return URL for a revoked session', () => {
    handleUnauthorized('SessionRevoked');

    expect(fakeLocation.href).toBe(
      '/signin?errorType=SessionRevoked&returnUrl=%2Fcollections%2F5%3Ftab%3Ditems'
    );
  });

  it('does not redirect for a generic 401', () => {
    handleUnauthorized(undefined);

    expect(fakeLocation.href).toBe('');
    expect(console.warn).toHaveBeenCalledOnce();
  });

  it('does not redirect for an unknown error code', () => {
    handleUnauthorized('SomeUnknownCode');

    expect(fakeLocation.href).toBe('');
  });
});
