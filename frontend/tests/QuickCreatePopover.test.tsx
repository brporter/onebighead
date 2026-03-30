// frontend/tests/QuickCreatePopover.test.tsx
import React from 'react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import QuickCreatePopover from '../src/components/category/QuickCreatePopover';

describe('QuickCreatePopover', () => {
  const defaultProps = {
    isVisible: true,
    onSave: vi.fn(),
    onMoreDetails: vi.fn(),
    onCancel: vi.fn(),
  };

  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('should render when visible', () => {
    render(<QuickCreatePopover {...defaultProps} />);
    expect(screen.getByPlaceholderText('Category name')).toBeInTheDocument();
  });

  it('should not render when not visible', () => {
    render(<QuickCreatePopover {...defaultProps} isVisible={false} />);
    expect(screen.queryByPlaceholderText('Category name')).not.toBeInTheDocument();
  });

  it('should focus name input on open', async () => {
    render(<QuickCreatePopover {...defaultProps} />);
    await waitFor(() => {
      expect(screen.getByPlaceholderText('Category name')).toHaveFocus();
    });
  });

  it('should call onSave with trimmed name when Save clicked', async () => {
    const user = userEvent.setup();
    render(<QuickCreatePopover {...defaultProps} />);

    await user.type(screen.getByPlaceholderText('Category name'), '  New Category  ');
    await user.click(screen.getByRole('button', { name: 'Save' }));

    expect(defaultProps.onSave).toHaveBeenCalledWith('New Category');
  });

  it('should show validation error when Save clicked with empty name', async () => {
    const user = userEvent.setup();
    render(<QuickCreatePopover {...defaultProps} />);

    await user.click(screen.getByRole('button', { name: 'Save' }));

    expect(screen.getByRole('alert')).toHaveTextContent('Name is required');
    expect(defaultProps.onSave).not.toHaveBeenCalled();
  });

  it('should show validation error for reserved name', async () => {
    const user = userEvent.setup();
    render(<QuickCreatePopover {...defaultProps} />);

    await user.type(screen.getByPlaceholderText('Category name'), 'Unassigned Items');
    await user.click(screen.getByRole('button', { name: 'Save' }));

    expect(screen.getByRole('alert')).toHaveTextContent('reserved name');
    expect(defaultProps.onSave).not.toHaveBeenCalled();
  });

  it('should clear validation error when user types', async () => {
    const user = userEvent.setup();
    render(<QuickCreatePopover {...defaultProps} />);

    await user.click(screen.getByRole('button', { name: 'Save' }));
    expect(screen.getByRole('alert')).toBeInTheDocument();

    await user.type(screen.getByPlaceholderText('Category name'), 'a');
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  });

  it('should call onMoreDetails with current name when More Details clicked', async () => {
    const user = userEvent.setup();
    render(<QuickCreatePopover {...defaultProps} />);

    await user.type(screen.getByPlaceholderText('Category name'), 'My Category');
    await user.click(screen.getByRole('button', { name: 'More Details...' }));

    expect(defaultProps.onMoreDetails).toHaveBeenCalledWith('My Category');
  });

  it('should call onMoreDetails with empty string when name is empty', async () => {
    const user = userEvent.setup();
    render(<QuickCreatePopover {...defaultProps} />);

    await user.click(screen.getByRole('button', { name: 'More Details...' }));

    expect(defaultProps.onMoreDetails).toHaveBeenCalledWith('');
  });

  it('should call onCancel when Cancel clicked', async () => {
    const user = userEvent.setup();
    render(<QuickCreatePopover {...defaultProps} />);

    await user.click(screen.getByRole('button', { name: 'Cancel' }));

    expect(defaultProps.onCancel).toHaveBeenCalled();
  });

  it('should call onSave when Enter pressed in input', async () => {
    const user = userEvent.setup();
    render(<QuickCreatePopover {...defaultProps} />);

    await user.type(screen.getByPlaceholderText('Category name'), 'Quick Cat{Enter}');

    expect(defaultProps.onSave).toHaveBeenCalledWith('Quick Cat');
  });

  it('should call onCancel when Escape pressed in input', async () => {
    const user = userEvent.setup();
    render(<QuickCreatePopover {...defaultProps} />);

    await user.type(screen.getByPlaceholderText('Category name'), 'Something');
    await user.keyboard('{Escape}');

    expect(defaultProps.onCancel).toHaveBeenCalled();
  });

  it('should reset name when becoming visible again', async () => {
    const { rerender } = render(<QuickCreatePopover {...defaultProps} isVisible={false} />);

    rerender(<QuickCreatePopover {...defaultProps} isVisible={true} />);

    expect(screen.getByPlaceholderText('Category name')).toHaveValue('');
  });
});
