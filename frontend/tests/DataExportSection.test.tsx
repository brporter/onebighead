import { act, fireEvent, render, screen } from '@testing-library/react';
import { expect, it, vi } from 'vitest';
import { DataExportSection } from '../src/components/workspace/DataExportSection';
import { exportApi } from '../src/api';
import { saveDownload } from '../src/utils/saveDownload';
import { deferred } from './testUtils/deferred';

vi.mock('../src/api', () => ({ exportApi: { downloadExport: vi.fn() } }));
vi.mock('../src/utils/saveDownload', () => ({ saveDownload: vi.fn() }));

it('identifies the active workspace scope and supports a single pending export with retry', async () => {
  const pending = deferred<{ blob: Blob; filename: string }>();
  vi.mocked(exportApi.downloadExport).mockRejectedValueOnce(new Error('Unavailable')).mockReturnValueOnce(pending.promise);
  render(<DataExportSection />);
  expect(screen.getByText(/Download the active workspace/)).toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', { name: 'Download Export' }));
  expect(await screen.findByRole('alert')).toHaveTextContent('Unavailable');
  fireEvent.click(screen.getByRole('button', { name: 'Download Export' }));
  const busy = screen.getByRole('button', { name: 'Exporting...' });
  expect(busy).toBeDisabled();
  fireEvent.click(busy);
  expect(exportApi.downloadExport).toHaveBeenCalledTimes(2);
  const file = { blob: new Blob(['archive']), filename: 'workspace.zip' };
  await act(async () => pending.resolve(file));
  expect(saveDownload).toHaveBeenCalledExactlyOnceWith(file);
  expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Download Export' })).toBeEnabled();
});
