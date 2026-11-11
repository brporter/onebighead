/**
 * Images API
 */
import { api, type RequestOptions } from './client';

export interface UploadImageResult {
  key: string;
  url: string;
}

export const imagesApi = {
  upload(file: File, options?: RequestOptions): Promise<UploadImageResult> {
    const formData = new FormData();
    formData.append('file', file);
    return api.upload<UploadImageResult>('/images', formData, options);
  },

  delete(key: string): Promise<void> {
    return api.delete(`/images/${encodeURIComponent(key)}`);
  },

  getUrl(key: string): string {
    return `/api/images/${encodeURIComponent(key)}`;
  },
};
