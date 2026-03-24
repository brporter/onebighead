import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, it, expect, vi } from 'vitest';
import { UnpublishConfirmModal } from '../src/components/common/UnpublishConfirmModal';

describe('UnpublishConfirmModal', () => {
  const defaultProps = {
    entityType: 'category' as const,
    entityName: 'Watches',
    affectedPublicItems: 5,
    onConfirm: vi.fn(),
    onCancel: vi.fn(),
  };

  it('should render the warning message with item count', () => {
    render(<UnpublishConfirmModal {...defaultProps} />);

    expect(screen.getByText(/This category has 5 items currently visible in your public gallery/)).toBeInTheDocument();
  });

  it('should render the reappear message', () => {
    render(<UnpublishConfirmModal {...defaultProps} />);

    expect(screen.getByText(/They will be hidden, but if you make this category public again, they'll reappear. Continue\?/)).toBeInTheDocument();
  });

  it('should render collection entity type in message', () => {
    render(<UnpublishConfirmModal {...defaultProps} entityType="collection" />);

    expect(screen.getByText(/This collection has 5 items currently visible in your public gallery/)).toBeInTheDocument();
  });

  it('should mention affected categories for collections', () => {
    render(<UnpublishConfirmModal {...defaultProps} entityType="collection" affectedPublicCategories={3} />);

    expect(screen.getByText(/3 categories/)).toBeInTheDocument();
  });

  it('should render Confirm button', () => {
    render(<UnpublishConfirmModal {...defaultProps} />);

    expect(screen.getByRole('button', { name: 'Make Private' })).toBeInTheDocument();
  });

  it('should render Cancel button', () => {
    render(<UnpublishConfirmModal {...defaultProps} />);

    expect(screen.getByRole('button', { name: 'Cancel' })).toBeInTheDocument();
  });

  it('should call onConfirm when Confirm is clicked', async () => {
    const user = userEvent.setup();
    const onConfirm = vi.fn();

    render(<UnpublishConfirmModal {...defaultProps} onConfirm={onConfirm} />);

    await user.click(screen.getByRole('button', { name: 'Make Private' }));

    expect(onConfirm).toHaveBeenCalledTimes(1);
  });

  it('should call onCancel when Cancel is clicked', async () => {
    const user = userEvent.setup();
    const onCancel = vi.fn();

    render(<UnpublishConfirmModal {...defaultProps} onCancel={onCancel} />);

    await user.click(screen.getByRole('button', { name: 'Cancel' }));

    expect(onCancel).toHaveBeenCalledTimes(1);
  });

  it('should have the modal-overlay CSS class', () => {
    const { container } = render(<UnpublishConfirmModal {...defaultProps} />);

    expect(container.querySelector('.modal-overlay')).toBeInTheDocument();
  });

  it('should not mention categories when affectedPublicCategories is not provided', () => {
    const { container } = render(<UnpublishConfirmModal {...defaultProps} entityType="collection" />);

    expect(container.textContent).not.toContain('categories');
  });
});
