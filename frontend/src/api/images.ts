/**
 * Images API
 */
import { api } from './client';

export interface UploadImageResult {
  key: string;
  url: string;
}

export const imagesApi = {
  upload(file: File): Promise<UploadImageResult> {
    const formData = new FormData();
    formData.append('file', file);
    return api.upload<UploadImageResult>('/images', formData);
  },

  delete(key: string): Promise<void> {
    return api.delete(`/images/${encodeURIComponent(key)}`);
  },

  getUrl(key: string): string {
    return `/api/images/${encodeURIComponent(key)}`;
  },
};
