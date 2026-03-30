import { useEffect, useRef, useCallback, type RefObject, type MouseEvent } from 'react';

/**
 * Manages a native HTML <dialog> element's lifecycle: open/close sync,
 * native close event forwarding (Escape key), and backdrop click handling.
 *
 * @param isOpen - Whether the dialog should be open
 * @param onClose - Called when the dialog is dismissed via Escape key or backdrop click
 * @returns [dialogRef, handleBackdropClick]
 */
export function useDialog(
  isOpen: boolean,
  onClose: () => void,
): [RefObject<HTMLDialogElement | null>, (e: MouseEvent<HTMLDialogElement>) => void] {
  const dialogRef = useRef<HTMLDialogElement | null>(null);

  useEffect(() => {
    const dialog = dialogRef.current;
    if (!dialog) return;
    if (isOpen) {
      if (!dialog.open) dialog.showModal();
    } else {
      if (dialog.open) dialog.close();
    }
  }, [isOpen]);

  useEffect(() => {
    const dialog = dialogRef.current;
    if (!dialog) return;
    const handler = () => onClose();
    dialog.addEventListener('close', handler);
    return () => dialog.removeEventListener('close', handler);
  }, [onClose]);

  const handleBackdropClick = useCallback(
    (e: MouseEvent<HTMLDialogElement>) => {
      if (e.target === dialogRef.current) onClose();
    },
    [onClose],
  );

  return [dialogRef, handleBackdropClick];
}
