/**
 * Convert a string to a URL-friendly slug.
 */
export function toSlug(name: string): string {
  return name
    .toLowerCase()
    .replace(/[^a-z0-9-]/g, '-')
    .replace(/-+/g, '-')
    .replace(/^-|-$/g, '')
    .slice(0, 50);
}

/**
 * Validate a slug: lowercase alphanumeric + hyphens, 3-50 chars,
 * no leading/trailing hyphens, no consecutive hyphens.
 */
export function isValidSlug(slug: string): boolean {
  return /^[a-z0-9]([a-z0-9]|-(?!-))*[a-z0-9]$/.test(slug) && slug.length >= 3 && slug.length <= 50;
}
