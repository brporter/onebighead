import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { renderHook, act } from '@testing-library/react';
import { useDialog } from '../src/utils/useDialog';

describe('useDialog', () => {
  beforeEach(() => {
    HTMLDialogElement.prototype.showModal = vi.fn(function (this: HTMLDialogElement) {
      this.setAttribute('open', '');
    });
    HTMLDialogElement.prototype.close = vi.fn(function (this: HTMLDialogElement) {
      this.removeAttribute('open');
    });
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('should return a dialog ref and backdrop click handler', () => {
    const onClose = vi.fn();
    const { result } = renderHook(() => useDialog(false, onClose));

    const [dialogRef, handleBackdropClick] = result.current;
    expect(dialogRef).toBeDefined();
    expect(typeof handleBackdropClick).toBe('function');
  });

  it('should call showModal when isOpen becomes true', () => {
    const onClose = vi.fn();
    const dialog = document.createElement('dialog');
    document.body.appendChild(dialog);

    const { result, rerender } = renderHook(
      ({ isOpen }) => {
        const hookResult = useDialog(isOpen, onClose);
        // Manually set the ref to our dialog element
        (hookResult[0] as { current: HTMLDialogElement | null }).current = dialog;
        return hookResult;
      },
      { initialProps: { isOpen: false } },
    );

    // Re-render with isOpen=true to trigger the effect
    rerender({ isOpen: true });

    expect(HTMLDialogElement.prototype.showModal).toHaveBeenCalled();

    document.body.removeChild(dialog);
    void result; // avoid unused variable warning
  });

  it('should call close when isOpen becomes false', () => {
    const onClose = vi.fn();
    const dialog = document.createElement('dialog');
    dialog.setAttribute('open', '');
    document.body.appendChild(dialog);

    const { result, rerender } = renderHook(
      ({ isOpen }) => {
        const hookResult = useDialog(isOpen, onClose);
        (hookResult[0] as { current: HTMLDialogElement | null }).current = dialog;
        return hookResult;
      },
      { initialProps: { isOpen: true } },
    );

    rerender({ isOpen: false });

    expect(HTMLDialogElement.prototype.close).toHaveBeenCalled();

    document.body.removeChild(dialog);
    void result;
  });

  it('should not call close if dialog is already closed', () => {
    const onClose = vi.fn();
    const dialog = document.createElement('dialog');
    document.body.appendChild(dialog);

    const { result, rerender } = renderHook(
      ({ isOpen }) => {
        const hookResult = useDialog(isOpen, onClose);
        (hookResult[0] as { current: HTMLDialogElement | null }).current = dialog;
        return hookResult;
      },
      { initialProps: { isOpen: false } },
    );

    // dialog.open is false by default, so close should not be called
    rerender({ isOpen: false });

    expect(HTMLDialogElement.prototype.close).not.toHaveBeenCalled();

    document.body.removeChild(dialog);
    void result;
  });

  it('should not call showModal if dialog is already open', () => {
    const onClose = vi.fn();
    const dialog = document.createElement('dialog');
    dialog.setAttribute('open', '');
    Object.defineProperty(dialog, 'open', { get: () => true, configurable: true });
    document.body.appendChild(dialog);

    const { result, rerender } = renderHook(
      ({ isOpen }) => {
        const hookResult = useDialog(isOpen, onClose);
        (hookResult[0] as { current: HTMLDialogElement | null }).current = dialog;
        return hookResult;
      },
      { initialProps: { isOpen: false } },
    );

    rerender({ isOpen: true });

    expect(HTMLDialogElement.prototype.showModal).not.toHaveBeenCalled();

    document.body.removeChild(dialog);
    void result;
  });

  it('should call onClose when native close event fires', () => {
    const onClose = vi.fn();
    const dialog = document.createElement('dialog');
    document.body.appendChild(dialog);

    const { result } = renderHook(() => {
      const hookResult = useDialog(true, onClose);
      (hookResult[0] as { current: HTMLDialogElement | null }).current = dialog;
      return hookResult;
    });

    // Trigger the native close event
    act(() => {
      dialog.dispatchEvent(new Event('close'));
    });

    expect(onClose).toHaveBeenCalledOnce();

    document.body.removeChild(dialog);
    void result;
  });

  it('should call onClose when backdrop is clicked', () => {
    const onClose = vi.fn();
    const dialog = document.createElement('dialog');
    document.body.appendChild(dialog);

    const { result } = renderHook(() => useDialog(false, onClose));

    const [dialogRef, handleBackdropClick] = result.current;
    (dialogRef as { current: HTMLDialogElement | null }).current = dialog;

    // Simulate backdrop click where target === dialog
    act(() => {
      handleBackdropClick({ target: dialog, currentTarget: dialog } as unknown as React.MouseEvent<HTMLDialogElement>);
    });

    expect(onClose).toHaveBeenCalledOnce();

    document.body.removeChild(dialog);
  });

  it('should not call onClose when content area is clicked', () => {
    const onClose = vi.fn();
    const dialog = document.createElement('dialog');
    const content = document.createElement('div');
    dialog.appendChild(content);
    document.body.appendChild(dialog);

    const { result } = renderHook(() => useDialog(false, onClose));

    const [dialogRef, handleBackdropClick] = result.current;
    (dialogRef as { current: HTMLDialogElement | null }).current = dialog;

    // Simulate click on content (not backdrop)
    act(() => {
      handleBackdropClick({ target: content, currentTarget: dialog } as unknown as React.MouseEvent<HTMLDialogElement>);
    });

    expect(onClose).not.toHaveBeenCalled();

    document.body.removeChild(dialog);
  });

  it('should clean up native close listener on unmount', () => {
    const onClose = vi.fn();
    const dialog = document.createElement('dialog');
    document.body.appendChild(dialog);

    const { result, unmount } = renderHook(() => {
      const hookResult = useDialog(false, onClose);
      (hookResult[0] as { current: HTMLDialogElement | null }).current = dialog;
      return hookResult;
    });

    unmount();

    // Fire close event after unmount
    dialog.dispatchEvent(new Event('close'));

    expect(onClose).not.toHaveBeenCalled();

    document.body.removeChild(dialog);
    void result;
  });
});
