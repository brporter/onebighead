import { describe, it, expect, vi } from 'vitest';
import { fireEvent, render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { ModalDialog } from '../src/components/common/ModalDialog';

describe('ModalDialog', () => {
  it('opens a named native dialog and synchronizes controlled visibility', () => {
    const onClose = vi.fn();
    const { rerender } = render(<ModalDialog label="Example" className="custom" onClose={onClose}>Content</ModalDialog>);
    const dialog = screen.getByRole('dialog', { name: 'Example' });
    expect(dialog).toHaveAttribute('open');
    expect(dialog).toHaveClass('custom');
    rerender(<ModalDialog label="Example" isOpen={false} onClose={onClose}>Content</ModalDialog>);
    expect(dialog).not.toHaveAttribute('open');
  });

  it('delegates cancel and backdrop dismissal to the caller', async () => {
    const onClose = vi.fn();
    render(<ModalDialog label="Example" onClose={onClose}><button>Inside</button></ModalDialog>);
    const dialog = screen.getByRole('dialog');
    await userEvent.click(screen.getByRole('button'));
    expect(onClose).not.toHaveBeenCalled();
    await userEvent.click(dialog);
    expect(onClose).toHaveBeenCalledTimes(1);
    const cancel = new Event('cancel', { bubbles: true, cancelable: true });
    fireEvent(dialog, cancel);
    expect(cancel.defaultPrevented).toBe(true);
    expect(dialog).toHaveAttribute('open');
    expect(onClose).toHaveBeenCalledTimes(2);
  });

  it('does not dismiss the parent when a nested dialog is cancelled', () => {
    const parentClose = vi.fn();
    const childClose = vi.fn();
    render(<ModalDialog label="Parent" onClose={parentClose}>
      <ModalDialog label="Child" onClose={childClose}>Confirm</ModalDialog>
    </ModalDialog>);
    fireEvent(screen.getByRole('dialog', { name: 'Child' }), new Event('cancel', { bubbles: true, cancelable: true }));
    expect(childClose).toHaveBeenCalledOnce();
    expect(parentClose).not.toHaveBeenCalled();
  });
});
