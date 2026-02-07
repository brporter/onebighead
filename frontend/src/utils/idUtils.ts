/**
 * Generate a unique ID for drag-and-drop and other UI purposes.
 * Uses crypto.randomUUID() for proper uniqueness.
 */
export function generateUniqueId(prefix: string = 'id'): string {
  return `${prefix}-${crypto.randomUUID()}`;
}
