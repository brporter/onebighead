import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, it, expect, vi } from 'vitest';
import { PublishConfirmModal } from '../src/components/common/PublishConfirmModal';

describe('PublishConfirmModal', () => {
  const defaultProps = {
    entityType: 'category' as const,
    entityName: 'Watches',
    itemCount: 5,
    onConfirm: vi.fn(),
    onCancel: vi.fn(),
  };

  it('should render the title with entity type and name', () => {
    render(<PublishConfirmModal {...defaultProps} />);

    expect(screen.getByText("Publish category 'Watches'?")).toBeInTheDocument();
  });

  it('should render the title for collection entity type', () => {
    render(<PublishConfirmModal {...defaultProps} entityType="collection" entityName="My Collection" />);

    expect(screen.getByText("Publish collection 'My Collection'?")).toBeInTheDocument();
  });

  it('should show item count in the publish-all option', () => {
    render(<PublishConfirmModal {...defaultProps} />);

    expect(screen.getByRole('button', { name: 'Publish category and all 5 items' })).toBeInTheDocument();
  });

  it('should show category count when provided for collection', () => {
    render(<PublishConfirmModal {...defaultProps} entityType="collection" categoryCount={3} />);

    expect(screen.getByText(/3 categories/)).toBeInTheDocument();
  });

  it('should show publish entity only option', () => {
    render(<PublishConfirmModal {...defaultProps} />);

    expect(screen.getByRole('button', { name: 'Publish category only' })).toBeInTheDocument();
  });

  it('should call onConfirm with true when publish-all is clicked', async () => {
    const user = userEvent.setup();
    const onConfirm = vi.fn();

    render(<PublishConfirmModal {...defaultProps} onConfirm={onConfirm} />);

    await user.click(screen.getByRole('button', { name: 'Publish category and all 5 items' }));

    expect(onConfirm).toHaveBeenCalledWith(true);
  });

  it('should call onConfirm with false when publish-only is clicked', async () => {
    const user = userEvent.setup();
    const onConfirm = vi.fn();

    render(<PublishConfirmModal {...defaultProps} onConfirm={onConfirm} />);

    await user.click(screen.getByRole('button', { name: 'Publish category only' }));

    expect(onConfirm).toHaveBeenCalledWith(false);
  });

  it('should render Cancel button', () => {
    render(<PublishConfirmModal {...defaultProps} />);

    expect(screen.getByRole('button', { name: 'Cancel' })).toBeInTheDocument();
  });

  it('should call onCancel when Cancel is clicked', async () => {
    const user = userEvent.setup();
    const onCancel = vi.fn();

    render(<PublishConfirmModal {...defaultProps} onCancel={onCancel} />);

    await user.click(screen.getByRole('button', { name: 'Cancel' }));

    expect(onCancel).toHaveBeenCalledTimes(1);
  });

  it('should have the modal-overlay CSS class', () => {
    const { container } = render(<PublishConfirmModal {...defaultProps} />);

    expect(container.querySelector('.modal-overlay')).toBeInTheDocument();
  });

  it('should show collection-specific text with categories and items', () => {
    render(
      <PublishConfirmModal
        entityType="collection"
        entityName="My Stuff"
        itemCount={10}
        categoryCount={4}
        onConfirm={vi.fn()}
        onCancel={vi.fn()}
      />
    );

    expect(screen.getByRole('button', { name: 'Publish collection and all 10 items' })).toBeInTheDocument();
  });
});
