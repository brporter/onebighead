import { useState } from 'react';
import { beforeEach, expect, it, vi } from 'vitest';
import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import ImageEditor from '../src/components/common/ImageEditor';
import { useImagesData } from '../src/contexts/useData';
import type { ItemImage } from '../src/utils/types';
import type { EditorStatusListener } from '../src/data/shared/useEditorStatus';
import { deferred } from './testUtils/deferred';

vi.mock('../src/contexts/useData', () => ({ useImagesData: vi.fn() }));
const upload = vi.fn();
const initial = [{ url: '/one.png', alt: 'Front view' }, { url: '/two.png', alt: 'Back view' }];
const photo = (name = 'new.photo.png') => new File(['image'], name, { type: 'image/png' });
const picker = () => screen.getByLabelText('Choose images') as HTMLInputElement;
function Editor({ initialImages = initial, status = vi.fn() }: { initialImages?: ItemImage[]; status?: EditorStatusListener }) {
  const [images, setImages] = useState(initialImages);
  return <ImageEditor images={images} onChange={setImages} onStatusChange={status} />;
}
beforeEach(() => {
  upload.mockReset().mockResolvedValue({ url: '/uploaded.png' });
  vi.mocked(useImagesData).mockReturnValue({ uploadImage: upload });
});

it('labels previews, descriptions and individual removal controls, and explains file constraints', () => {
  render(<Editor />);
  expect(screen.getByRole('region', { name: 'Images' })).toHaveAttribute('aria-busy', 'false');
  expect(screen.getByRole('img', { name: 'Front view' })).toHaveAttribute('src', '/one.png');
  expect(screen.getByRole('textbox', { name: 'Image 2 description' })).toHaveValue('Back view');
  expect(screen.getByRole('button', { name: 'Remove image 1' })).toBeEnabled();
  expect(picker()).toHaveAttribute('accept', 'image/jpeg,image/png,image/gif,image/webp,image/avif');
  expect(picker()).toHaveAttribute('multiple');
  expect(picker()).toHaveAccessibleDescription(/Up to 10 MB/);
});

it('supports an empty editor and opens the native file picker from its button', async () => {
  render(<Editor initialImages={[]} />);
  expect(screen.queryByRole('img')).not.toBeInTheDocument();
  const click = vi.spyOn(picker(), 'click');
  await userEvent.click(screen.getByRole('button', { name: '+ Add Image' }));
  expect(click).toHaveBeenCalledOnce();
});

it('keeps independent form labels unique when two editors are mounted', () => {
  render(<><Editor /><Editor /></>);
  const editors = screen.getAllByRole('region', { name: 'Images' });
  const fields = editors.map(editor => within(editor).getByRole('textbox', { name: 'Image 1 description' }));
  expect(fields[0].id).not.toBe(fields[1].id);
});

it('updates descriptions and removes only the chosen image', async () => {
  render(<Editor />);
  await userEvent.clear(screen.getByRole('textbox', { name: 'Image 2 description' }));
  await userEvent.type(screen.getByRole('textbox', { name: 'Image 2 description' }), 'Details');
  expect(screen.getByRole('img', { name: 'Details' })).toHaveAttribute('src', '/two.png');
  await userEvent.click(screen.getByRole('button', { name: 'Remove image 1' }));
  expect(screen.queryByRole('img', { name: 'Front view' })).not.toBeInTheDocument();
  expect(screen.getByRole('textbox', { name: 'Image 1 description' })).toHaveValue('Details');
});

it('appends a completed batch to the latest edited images rather than replacing them', async () => {
  const pending = deferred<{ url: string }>();
  upload.mockReturnValueOnce(pending.promise);
  const status = vi.fn();
  render(<Editor status={status} />);
  await userEvent.upload(picker(), photo());
  expect(screen.getByRole('status')).toHaveTextContent('Uploading images (0/1)');
  expect(picker()).toBeDisabled();
  expect(screen.getByRole('button', { name: 'Uploading...' })).toBeDisabled();
  expect(status).toHaveBeenLastCalledWith({ dirty: false, pending: true });
  await userEvent.clear(screen.getByRole('textbox', { name: 'Image 2 description' }));
  await userEvent.type(screen.getByRole('textbox', { name: 'Image 2 description' }), 'Updated during upload');
  await userEvent.click(screen.getByRole('button', { name: 'Remove image 1' }));
  await act(async () => pending.resolve({ url: '/new.png' }));
  expect(screen.getByRole('img', { name: 'Updated during upload' })).toHaveAttribute('src', '/two.png');
  expect(screen.getByRole('img', { name: 'new.photo' })).toHaveAttribute('src', '/new.png');
  expect(screen.getAllByRole('img')).toHaveLength(2);
  expect(status).toHaveBeenLastCalledWith({ dirty: false, pending: false });
});

it('keeps successful uploads and file-specific errors, then permits retrying the failed file', async () => {
  const failed = photo('second.png');
  upload.mockResolvedValueOnce({ url: '/first.png' }).mockRejectedValueOnce(new Error('Offline')).mockResolvedValue({ url: '/retry.png' });
  render(<Editor initialImages={[]} />);
  await userEvent.upload(picker(), [photo('first.png'), failed]);
  expect(await screen.findByRole('alert')).toHaveTextContent('second.png: Offline');
  expect(screen.getByRole('img', { name: 'first' })).toHaveAttribute('src', '/first.png');
  expect(picker()).toHaveValue('');
  await userEvent.upload(picker(), failed);
  expect(await screen.findByRole('img', { name: 'second' })).toHaveAttribute('src', '/retry.png');
  expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  expect(upload).toHaveBeenCalledTimes(3);
});

it('reports invalid files without preventing valid files from being added', async () => {
  render(<Editor initialImages={[]} />);
  fireEvent.change(picker(), { target: { files: [new File(['text'], 'notes.txt', { type: 'text/plain' }), photo()] } });
  expect(await screen.findByRole('img', { name: 'new.photo' })).toBeInTheDocument();
  expect(screen.getByRole('alert')).toHaveTextContent('notes.txt: Choose a JPEG');
  expect(upload).toHaveBeenCalledOnce();
});

it.each([null, []])('does not start an upload when selection is cancelled: %s', files => {
  render(<Editor />);
  fireEvent.change(picker(), { target: { files } });
  expect(upload).not.toHaveBeenCalled();
  expect(screen.queryByRole('status')).not.toBeInTheDocument();
});

it('aborts requests and releases pending status when the editor unmounts', async () => {
  const pending = deferred<{ url: string }>();
  upload.mockReturnValueOnce(pending.promise);
  const status = vi.fn();
  const change = vi.fn();
  const { unmount } = render(<ImageEditor images={[]} onChange={change} onStatusChange={status} />);
  await userEvent.upload(picker(), [photo(), photo('later.png')]);
  const signal = upload.mock.calls[0][1].signal;
  unmount();
  expect(signal.aborted).toBe(true);
  await act(async () => pending.resolve({ url: '/obsolete.png' }));
  expect(change).not.toHaveBeenCalled();
  expect(upload).toHaveBeenCalledOnce();
  expect(status).toHaveBeenLastCalledWith({ dirty: false, pending: false });
});

it('inherits a containing form lock for every image action', async () => {
  render(<fieldset disabled><Editor /></fieldset>);
  expect(picker()).toBeDisabled();
  expect(screen.getByRole('textbox', { name: 'Image 1 description' })).toBeDisabled();
  await userEvent.click(screen.getByRole('button', { name: 'Remove image 1' }));
  expect(screen.getAllByRole('img')).toHaveLength(2);
  await waitFor(() => expect(upload).not.toHaveBeenCalled());
});
