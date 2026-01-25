/**
 * Export API
 */
import { api } from './client';

export const exportApi = {
  async downloadExport(): Promise<{ blob: Blob; filename: string }> {
    const response = await api.download('/export', { credentials: 'include' });
    const blob = await response.blob();
    
    let filename = 'export.zip';
    const contentDisposition = response.headers.get('Content-Disposition');
    if (contentDisposition) {
      const match = contentDisposition.match(/filename=(.+)/);
      if (match) {
        filename = match[1].replace(/"/g, '');
      }
    }

    return { blob, filename };
  },
};
