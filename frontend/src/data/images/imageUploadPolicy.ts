export const IMAGE_FILE_TYPES = ['image/jpeg', 'image/png', 'image/gif', 'image/webp', 'image/avif'];
export const IMAGE_SIZE_LIMIT_MB = 10;
export const IMAGE_SIZE_LIMIT_BYTES = IMAGE_SIZE_LIMIT_MB * 1024 * 1024;
export const IMAGE_UPLOAD_HINT = `JPEG, PNG, GIF, WebP or AVIF. Up to ${IMAGE_SIZE_LIMIT_MB} MB per image.`;

/** Browser checks provide early feedback; the API verifies the actual image contents. */
export function validateImageFile(file: Pick<File, 'type' | 'size'>): string | null {
  if (!IMAGE_FILE_TYPES.includes(file.type)) return 'Choose a JPEG, PNG, GIF, WebP or AVIF image.';
  if (file.size === 0) return 'This file is empty.';
  if (file.size > IMAGE_SIZE_LIMIT_BYTES) return `File size exceeds the ${IMAGE_SIZE_LIMIT_MB} MB limit.`;
  return null;
}

export function imageDescription(fileName: string): string {
  return fileName.replace(/\.[^/.]+$/, '') || 'Image';
}
