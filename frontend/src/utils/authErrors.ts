/**
 * 401 error causes surfaced by the backend authentication handler.
 * Mirrors the backend AuthErrorType enum; values are passed to the sign-in
 * page as the "errorType" query string parameter, where they are mapped back
 * to a display string.
 */
export enum AuthErrorType {
  None = 0,
  SessionRevoked = 1,
}

/** Maps backend 401 response codes to their AuthErrorType. */
const codeToErrorType: Record<string, AuthErrorType> = {
  SessionRevoked: AuthErrorType.SessionRevoked,
};

/**
 * Parses the "code" field of a 401 response body into an AuthErrorType.
 * Unknown or missing codes map to AuthErrorType.None.
 */
export function parseAuthErrorCode(code: unknown): AuthErrorType {
  if (typeof code !== 'string') {
    return AuthErrorType.None;
  }
  return codeToErrorType[code] ?? AuthErrorType.None;
}

/**
 * Builds the sign-in page URL carrying the error type and a return URL so the
 * user lands back where they were after re-authenticating.
 */
export function buildSignInUrl(errorType: AuthErrorType, returnUrl: string): string {
  return `/signin?errorType=${AuthErrorType[errorType]}&returnUrl=${encodeURIComponent(returnUrl)}`;
}

/**
 * Global 401 handler: when the backend signals a typed cause (e.g. the session
 * was revoked because the user's access changed), redirect to the sign-in page
 * so the cause is displayed and the user can re-authenticate. Generic 401s
 * (e.g. anonymous visitors on public pages) are left to the caller to handle.
 */
export function handleUnauthorized(errorCode?: string): void {
  const errorType = parseAuthErrorCode(errorCode);

  if (errorType === AuthErrorType.None) {
    console.warn('Unauthorized request - user may need to log in');
    return;
  }

  const returnUrl = globalThis.location.pathname + globalThis.location.search;
  globalThis.location.href = buildSignInUrl(errorType, returnUrl);
}
