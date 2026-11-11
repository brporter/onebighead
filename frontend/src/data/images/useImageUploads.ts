import { useEffect, useRef, useState } from 'react';
import type { RequestOptions } from '../../api/client';
import type { ItemImage } from '../../utils/types';
import { getErrorMessage } from '../../utils/errorUtils';
import { imageDescription, validateImageFile } from './imageUploadPolicy';

export type ImageUploadPort = (file: File, options?: RequestOptions) => Promise<{ url: string }>;
export interface ImageUploadIssue { fileName: string; message: string }

/** One ordered batch; successful files survive failures elsewhere in the batch. */
export function useImageUploads(upload: ImageUploadPort, onAdded: (images: ItemImage[]) => void) {
  const [state, setState] = useState({ pending: false, completed: 0, total: 0, issues: [] as ImageUploadIssue[] });
  const active = useRef<AbortController | null>(null);
  useEffect(() => () => { active.current?.abort(); active.current = null; }, []);

  async function select(files: File[]) {
    if (active.current || files.length === 0) return;
    const controller = new AbortController();
    active.current = controller;
    const issues: ImageUploadIssue[] = [];
    const added: ItemImage[] = [];
    let completed = 0;
    setState({ pending: true, completed, total: files.length, issues: [] });
    try {
      for (const file of files) {
        const invalid = validateImageFile(file);
        if (invalid) issues.push({ fileName: file.name, message: invalid });
        else {
          try {
            const result = await upload(file, { signal: controller.signal });
            controller.signal.throwIfAborted();
            added.push({ url: result.url, alt: imageDescription(file.name) });
          } catch (cause) {
            if (controller.signal.aborted) return;
            issues.push({ fileName: file.name, message: getErrorMessage(cause, 'Failed to upload image') });
          }
        }
        completed++;
        setState({ pending: true, completed, total: files.length, issues: [...issues] });
      }
      if (added.length > 0) onAdded(added);
      setState({ pending: false, completed, total: files.length, issues });
    } finally {
      if (active.current === controller) active.current = null;
    }
  }

  return { ...state, select };
}
