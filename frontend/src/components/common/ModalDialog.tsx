import type { ReactNode } from 'react';
import { useDialog } from '../../utils/useDialog';

interface ModalDialogProps {
  children: ReactNode;
  onClose: () => void;
  isOpen?: boolean;
  className?: string;
  label: string;
}

/** Controlled modal: the caller decides whether a dismissal may close it. */
export function ModalDialog({ children, onClose, isOpen = true, className = '', label }: ModalDialogProps) {
  const [dialogRef, onBackdropClick] = useDialog(isOpen, onClose);
  return (
    <dialog
      ref={dialogRef}
      className={`modal-dialog ${className}`}
      aria-label={label}
      onClick={onBackdropClick}
      onCancel={(event) => {
        event.preventDefault();
        event.stopPropagation();
        onClose();
      }}
    >
      {children}
    </dialog>
  );
}
