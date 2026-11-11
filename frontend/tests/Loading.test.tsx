import { expect, it } from 'vitest';
import { render, screen } from '@testing-library/react';
import { Loading } from '../src/components/common/Loading';
import LoadingFallback from '../src/components/common/LoadingFallback';

it('announces route loading using the shared loading indicator', () => {
  render(<LoadingFallback />);
  const status = screen.getByRole('status');
  expect(status).toHaveTextContent('Loading...');
  expect(status).toHaveAttribute('aria-live', 'polite');
  expect(status.querySelector('.spinner')).toHaveAttribute('aria-hidden', 'true');
});

it.each(['sm', 'lg'] as const)('supports a %s inline indicator with and without text', size => {
  const { rerender } = render(<Loading inline size={size} message="Saving changes" />);
  expect(screen.getByRole('status')).toHaveClass('loading--inline');
  expect(screen.getByRole('status')).toHaveTextContent('Saving changes');
  expect(screen.getByRole('status').querySelector('.spinner')).toHaveClass(`spinner--${size}`);
  rerender(<Loading inline size={size} message="" />);
  expect(screen.queryByText('Saving changes')).not.toBeInTheDocument();
  expect(screen.getByRole('status').querySelector('.loading__text')).toBeNull();
});
