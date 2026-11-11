/**
 * Export API
 */
import { api } from './client';
import { downloadFilename } from '../utils/downloadFilename';

export const exportApi = {
  async downloadExport(): Promise<{ blob: Blob; filename: string }> {
    const response = await api.download('/export', { credentials: 'include' });
    const blob = await response.blob();
    const filename = downloadFilename(response.headers.get('Content-Disposition'), 'export.zip');

    return { blob, filename };
  },
};
