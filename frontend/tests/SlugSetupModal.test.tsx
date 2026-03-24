import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, it, expect, vi } from 'vitest';
import { SlugSetupModal } from '../src/components/common/SlugSetupModal';

describe('SlugSetupModal', () => {
  const defaultProps = {
    onConfirm: vi.fn(),
    onCancel: vi.fn(),
  };

  it('should render the setup title when no existing slug', () => {
    render(<SlugSetupModal {...defaultProps} />);

    expect(screen.getByText('Set Up Your Public Gallery')).toBeInTheDocument();
  });

  it('should render slug input field', () => {
    render(<SlugSetupModal {...defaultProps} />);

    expect(screen.getByRole('textbox')).toBeInTheDocument();
  });

  it('should show live URL preview', () => {
    render(<SlugSetupModal {...defaultProps} />);

    expect(screen.getByText(/\/public\//)).toBeInTheDocument();
  });

  it('should pre-populate slug when existingSlug is provided', () => {
    render(<SlugSetupModal {...defaultProps} existingSlug="my-watches" />);

    expect(screen.getByRole('textbox')).toHaveValue('my-watches');
  });

  it('should show simpler message when existing slug is provided', () => {
    render(<SlugSetupModal {...defaultProps} existingSlug="my-watches" />);

    expect(screen.getByText('Your gallery URL is already set.')).toBeInTheDocument();
  });

  it('should show "Create Gallery & Publish" button when no existing slug', () => {
    render(<SlugSetupModal {...defaultProps} />);

    expect(screen.getByRole('button', { name: 'Create Gallery & Publish' })).toBeInTheDocument();
  });

  it('should show "Continue & Publish" button when existing slug is provided', () => {
    render(<SlugSetupModal {...defaultProps} existingSlug="my-watches" />);

    expect(screen.getByRole('button', { name: 'Continue & Publish' })).toBeInTheDocument();
  });

  it('should disable submit button when slug is empty', () => {
    render(<SlugSetupModal {...defaultProps} />);

    expect(screen.getByRole('button', { name: 'Create Gallery & Publish' })).toBeDisabled();
  });

  it('should disable submit button when slug is invalid', async () => {
    const user = userEvent.setup();
    render(<SlugSetupModal {...defaultProps} />);

    await user.type(screen.getByRole('textbox'), 'ab');

    expect(screen.getByRole('button', { name: 'Create Gallery & Publish' })).toBeDisabled();
  });

  it('should enable submit button when slug is valid', async () => {
    const user = userEvent.setup();
    render(<SlugSetupModal {...defaultProps} />);

    await user.type(screen.getByRole('textbox'), 'my-watches');

    expect(screen.getByRole('button', { name: 'Create Gallery & Publish' })).toBeEnabled();
  });

  it('should call onConfirm with slug value when submitted', async () => {
    const user = userEvent.setup();
    const onConfirm = vi.fn();

    render(<SlugSetupModal {...defaultProps} onConfirm={onConfirm} />);

    await user.type(screen.getByRole('textbox'), 'my-watches');
    await user.click(screen.getByRole('button', { name: 'Create Gallery & Publish' }));

    expect(onConfirm).toHaveBeenCalledWith('my-watches');
  });

  it('should call onCancel when Cancel is clicked', async () => {
    const user = userEvent.setup();
    const onCancel = vi.fn();

    render(<SlugSetupModal {...defaultProps} onCancel={onCancel} />);

    await user.click(screen.getByRole('button', { name: 'Cancel' }));

    expect(onCancel).toHaveBeenCalledTimes(1);
  });

  it('should update URL preview as slug changes', async () => {
    const user = userEvent.setup();
    render(<SlugSetupModal {...defaultProps} />);

    await user.type(screen.getByRole('textbox'), 'cool-stuff');

    expect(screen.getByText('/public/cool-stuff')).toBeInTheDocument();
  });

  it('should have the modal-overlay CSS class', () => {
    const { container } = render(<SlugSetupModal {...defaultProps} />);

    expect(container.querySelector('.modal-overlay')).toBeInTheDocument();
  });

  it('should show validation error for invalid slug format', async () => {
    const user = userEvent.setup();
    render(<SlugSetupModal {...defaultProps} />);

    await user.type(screen.getByRole('textbox'), 'INVALID_SLUG!');

    expect(screen.getByRole('button', { name: 'Create Gallery & Publish' })).toBeDisabled();
  });

  it('should enable submit when existingSlug is already valid', () => {
    render(<SlugSetupModal {...defaultProps} existingSlug="my-watches" />);

    expect(screen.getByRole('button', { name: 'Continue & Publish' })).toBeEnabled();
  });
});
