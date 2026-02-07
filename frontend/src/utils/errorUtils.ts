import { ApiError } from '../api';

/**
 * Extract a user-friendly error message from an error, preserving status code for API errors.
 */
export function getErrorMessage(error: unknown, defaultMessage: string): string {
  if (error instanceof ApiError) {
    const statusInfo = error.status ? ` (${error.status})` : '';
    return `${error.message}${statusInfo}`;
  }
  if (error instanceof Error) {
    return error.message;
  }
  return defaultMessage;
}

/**
 * Log an error with context, including status code for API errors.
 */
export function logError(context: string, error: unknown): void {
  if (error instanceof ApiError) {
    console.error(`${context}: ${error.message} (status: ${error.status})`);
  } else {
    console.error(`${context}:`, error);
  }
}
