import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, it, expect, vi } from 'vitest';
import { BulkActionBar } from '../src/components/common/BulkActionBar';

describe('BulkActionBar', () => {
  const defaultProps = {
    selectedCount: 3,
    onPublish: vi.fn(),
    onUnpublish: vi.fn(),
    onCancel: vi.fn(),
  };

  it('should render the selected count badge', () => {
    render(<BulkActionBar {...defaultProps} />);

    expect(screen.getByText('3')).toBeInTheDocument();
  });

  it('should render "items selected" text', () => {
    render(<BulkActionBar {...defaultProps} />);

    expect(screen.getByText('items selected')).toBeInTheDocument();
  });

  it('should render Publish Selected button', () => {
    render(<BulkActionBar {...defaultProps} />);

    expect(screen.getByRole('button', { name: 'Publish Selected' })).toBeInTheDocument();
  });

  it('should render Make Private button', () => {
    render(<BulkActionBar {...defaultProps} />);

    expect(screen.getByRole('button', { name: 'Make Private' })).toBeInTheDocument();
  });

  it('should render Cancel button', () => {
    render(<BulkActionBar {...defaultProps} />);

    expect(screen.getByRole('button', { name: 'Cancel' })).toBeInTheDocument();
  });

  it('should call onPublish when Publish Selected is clicked', async () => {
    const user = userEvent.setup();
    const onPublish = vi.fn();

    render(<BulkActionBar {...defaultProps} onPublish={onPublish} />);

    await user.click(screen.getByRole('button', { name: 'Publish Selected' }));

    expect(onPublish).toHaveBeenCalledTimes(1);
  });

  it('should call onUnpublish when Make Private is clicked', async () => {
    const user = userEvent.setup();
    const onUnpublish = vi.fn();

    render(<BulkActionBar {...defaultProps} onUnpublish={onUnpublish} />);

    await user.click(screen.getByRole('button', { name: 'Make Private' }));

    expect(onUnpublish).toHaveBeenCalledTimes(1);
  });

  it('should call onCancel when Cancel is clicked', async () => {
    const user = userEvent.setup();
    const onCancel = vi.fn();

    render(<BulkActionBar {...defaultProps} onCancel={onCancel} />);

    await user.click(screen.getByRole('button', { name: 'Cancel' }));

    expect(onCancel).toHaveBeenCalledTimes(1);
  });

  it('should return null when selectedCount is 0', () => {
    const { container } = render(<BulkActionBar {...defaultProps} selectedCount={0} />);

    expect(container.innerHTML).toBe('');
  });

  it('should render with count of 1', () => {
    render(<BulkActionBar {...defaultProps} selectedCount={1} />);

    expect(screen.getByText('1')).toBeInTheDocument();
    expect(screen.getByText('items selected')).toBeInTheDocument();
  });

  it('should have the bulk-action-bar CSS class', () => {
    const { container } = render(<BulkActionBar {...defaultProps} />);

    expect(container.querySelector('.bulk-action-bar')).toBeInTheDocument();
  });

  it('should have green styling class on Publish Selected button', () => {
    render(<BulkActionBar {...defaultProps} />);

    expect(screen.getByRole('button', { name: 'Publish Selected' })).toHaveClass('bulk-action-bar__button--publish');
  });
});
