import { render, screen, fireEvent } from '@testing-library/react';
import { describe, it, expect, vi } from 'vitest';
import SortConfirmModal from '../src/components/category/SortConfirmModal';

describe('SortConfirmModal', () => {
  it('renders both sort options', () => {
    render(<SortConfirmModal onConfirm={vi.fn()} onCancel={vi.fn()} />);
    expect(screen.getByText(/this level only/i)).toBeInTheDocument();
    expect(screen.getByText(/all levels/i)).toBeInTheDocument();
  });

  it('calls onConfirm with "level" when This Level Only is clicked', () => {
    const onConfirm = vi.fn();
    render(<SortConfirmModal onConfirm={onConfirm} onCancel={vi.fn()} />);
    fireEvent.click(screen.getByRole('button', { name: /this level only/i }));
    expect(onConfirm).toHaveBeenCalledWith('level');
  });

  it('calls onConfirm with "all" when All Levels is clicked', () => {
    const onConfirm = vi.fn();
    render(<SortConfirmModal onConfirm={onConfirm} onCancel={vi.fn()} />);
    fireEvent.click(screen.getByRole('button', { name: /all levels/i }));
    expect(onConfirm).toHaveBeenCalledWith('all');
  });

  it('calls onCancel when Cancel is clicked', () => {
    const onCancel = vi.fn();
    render(<SortConfirmModal onConfirm={vi.fn()} onCancel={onCancel} />);
    fireEvent.click(screen.getByRole('button', { name: /cancel/i }));
    expect(onCancel).toHaveBeenCalled();
  });

  it('displays warning about overwriting custom ordering', () => {
    render(<SortConfirmModal onConfirm={vi.fn()} onCancel={vi.fn()} />);
    expect(screen.getByText(/overwrite/i)).toBeInTheDocument();
  });
});
