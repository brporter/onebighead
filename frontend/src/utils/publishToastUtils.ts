import type { PublishResponse, BulkPublishResponse, UnpublishResponse, BulkUnpublishResponse } from './types';

/**
 * Build a toast message string from a publish response.
 */
export function buildPublishToastMessage(response: PublishResponse): string {
  return `${response.published.name} published.`;
}

/**
 * Build a toast details string showing promoted parents.
 */
export function buildPublishToastDetails(response: PublishResponse): string | undefined {
  if (response.promoted.length === 0) return undefined;
  const names = response.promoted.map(p => `'${p.name}'`).join(', ');
  if (response.promoted.length === 1) {
    return `${response.promoted[0].type} ${names} is now visible in your gallery.`;
  }
  return `Promoted: ${names} are now visible in your gallery.`;
}

/**
 * Build a toast message from a bulk publish response.
 */
export function buildBulkPublishToastMessage(response: BulkPublishResponse): string {
  const count = response.publishedCount;
  return `${count} item${count === 1 ? '' : 's'} published.`;
}

/**
 * Build a toast details string from a bulk publish response.
 */
export function buildBulkPublishToastDetails(response: BulkPublishResponse): string | undefined {
  if (response.promoted.length === 0) return undefined;
  const names = response.promoted.map(p => `'${p.name}'`).join(', ');
  return `Promoted: ${names} are now visible in your gallery.`;
}

/**
 * Build a toast message from an unpublish response.
 */
export function buildUnpublishToastMessage(response: UnpublishResponse): string {
  return `${response.unpublished.name} unpublished.`;
}

/**
 * Build a toast message from a bulk unpublish response.
 */
export function buildBulkUnpublishToastMessage(response: BulkUnpublishResponse): string {
  const count = response.unpublishedCount;
  return `${count} item${count === 1 ? '' : 's'} unpublished.`;
}
