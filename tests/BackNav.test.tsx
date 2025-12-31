import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, it, expect, vi } from 'vitest';
import BackNav from '../src/BackNav';

describe('BackNav', () => {
  it('should render with the provided label', () => {
    render(<BackNav label="Back to items" onClick={() => {}} />);

    expect(screen.getByRole('button')).toHaveTextContent('← Back to items');
  });

  it('should call onClick when button is clicked', async () => {
    const user = userEvent.setup();
    const handleClick = vi.fn();

    render(<BackNav label="Categories" onClick={handleClick} />);

    await user.click(screen.getByRole('button'));

    expect(handleClick).toHaveBeenCalledTimes(1);
  });

  it('should render as a nav element', () => {
    render(<BackNav label="Test" onClick={() => {}} />);

    expect(screen.getByRole('navigation')).toBeInTheDocument();
  });

  it('should have correct CSS classes', () => {
    render(<BackNav label="Test" onClick={() => {}} />);

    expect(screen.getByRole('navigation')).toHaveClass('mobileNav');
    expect(screen.getByRole('button')).toHaveClass('mobileNav__back');
  });

  describe('snapshots', () => {
    it('should match snapshot', () => {
      const { container } = render(<BackNav label="Back to items" onClick={() => {}} />);

      expect(container).toMatchSnapshot();
    });
  });
});

