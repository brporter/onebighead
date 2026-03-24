import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, it, expect, vi } from 'vitest';
import { VisibilityFilter } from '../src/components/common/VisibilityFilter';
import type { VisibilityFilterValue } from '../src/components/common/VisibilityFilter';

describe('VisibilityFilter', () => {
  it('should render three filter buttons: All, Public, Private', () => {
    render(<VisibilityFilter value="all" onChange={() => {}} totalCount={10} filteredCount={10} />);

    expect(screen.getByRole('button', { name: /all/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /public/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /private/i })).toBeInTheDocument();
  });

  it('should apply active class to "All" button when value is "all"', () => {
    render(<VisibilityFilter value="all" onChange={() => {}} totalCount={10} filteredCount={10} />);

    expect(screen.getByRole('button', { name: /all/i })).toHaveClass('active');
    expect(screen.getByRole('button', { name: /public/i })).not.toHaveClass('active');
    expect(screen.getByRole('button', { name: /private/i })).not.toHaveClass('active');
  });

  it('should apply active class to "Public" button when value is "public"', () => {
    render(<VisibilityFilter value="public" onChange={() => {}} totalCount={10} filteredCount={5} />);

    expect(screen.getByRole('button', { name: /all/i })).not.toHaveClass('active');
    expect(screen.getByRole('button', { name: /public/i })).toHaveClass('active');
    expect(screen.getByRole('button', { name: /private/i })).not.toHaveClass('active');
  });

  it('should apply active class to "Private" button when value is "private"', () => {
    render(<VisibilityFilter value="private" onChange={() => {}} totalCount={10} filteredCount={3} />);

    expect(screen.getByRole('button', { name: /all/i })).not.toHaveClass('active');
    expect(screen.getByRole('button', { name: /public/i })).not.toHaveClass('active');
    expect(screen.getByRole('button', { name: /private/i })).toHaveClass('active');
  });

  it('should call onChange with "all" when All button is clicked', async () => {
    const user = userEvent.setup();
    const handleChange = vi.fn();

    render(<VisibilityFilter value="public" onChange={handleChange} totalCount={10} filteredCount={5} />);

    await user.click(screen.getByRole('button', { name: /all/i }));

    expect(handleChange).toHaveBeenCalledTimes(1);
    expect(handleChange).toHaveBeenCalledWith('all');
  });

  it('should call onChange with "public" when Public button is clicked', async () => {
    const user = userEvent.setup();
    const handleChange = vi.fn();

    render(<VisibilityFilter value="all" onChange={handleChange} totalCount={10} filteredCount={10} />);

    await user.click(screen.getByRole('button', { name: /public/i }));

    expect(handleChange).toHaveBeenCalledTimes(1);
    expect(handleChange).toHaveBeenCalledWith('public');
  });

  it('should call onChange with "private" when Private button is clicked', async () => {
    const user = userEvent.setup();
    const handleChange = vi.fn();

    render(<VisibilityFilter value="all" onChange={handleChange} totalCount={10} filteredCount={10} />);

    await user.click(screen.getByRole('button', { name: /private/i }));

    expect(handleChange).toHaveBeenCalledTimes(1);
    expect(handleChange).toHaveBeenCalledWith('private');
  });

  it('should show filtered count text', () => {
    render(<VisibilityFilter value="public" onChange={() => {}} totalCount={10} filteredCount={4} />);

    expect(screen.getByText('Showing 4 items')).toBeInTheDocument();
  });

  it('should update filtered count text when filteredCount changes', () => {
    const { rerender } = render(
      <VisibilityFilter value="all" onChange={() => {}} totalCount={10} filteredCount={10} />
    );

    expect(screen.getByText('Showing 10 items')).toBeInTheDocument();

    rerender(<VisibilityFilter value="public" onChange={() => {}} totalCount={10} filteredCount={3} />);

    expect(screen.getByText('Showing 3 items')).toBeInTheDocument();
  });

  it('should render the filter group container', () => {
    render(<VisibilityFilter value="all" onChange={() => {}} totalCount={5} filteredCount={5} />);

    expect(screen.getByRole('group', { name: /visibility filter/i })).toBeInTheDocument();
  });

  it('should have filter-btn class on all buttons', () => {
    const { container } = render(
      <VisibilityFilter value="all" onChange={() => {}} totalCount={10} filteredCount={10} />
    );

    const buttons = container.querySelectorAll('.filter-btn');
    expect(buttons).toHaveLength(3);
  });

  it('should have filter-bar class on the container', () => {
    const { container } = render(
      <VisibilityFilter value="all" onChange={() => {}} totalCount={10} filteredCount={10} />
    );

    expect(container.querySelector('.filter-bar')).toBeInTheDocument();
  });

  it('should render an SVG eye icon inside the Public button', () => {
    const { container } = render(
      <VisibilityFilter value="all" onChange={() => {}} totalCount={10} filteredCount={10} />
    );

    const publicBtn = screen.getByRole('button', { name: /public/i });
    expect(publicBtn.querySelector('svg')).toBeInTheDocument();
  });

  it('should export VisibilityFilterValue type correctly', () => {
    const values: VisibilityFilterValue[] = ['all', 'public', 'private'];
    expect(values).toHaveLength(3);
  });

  describe('snapshots', () => {
    it('should match snapshot with value "all"', () => {
      const { container } = render(
        <VisibilityFilter value="all" onChange={() => {}} totalCount={10} filteredCount={10} />
      );
      expect(container).toMatchSnapshot();
    });

    it('should match snapshot with value "public"', () => {
      const { container } = render(
        <VisibilityFilter value="public" onChange={() => {}} totalCount={10} filteredCount={5} />
      );
      expect(container).toMatchSnapshot();
    });

    it('should match snapshot with value "private"', () => {
      const { container } = render(
        <VisibilityFilter value="private" onChange={() => {}} totalCount={10} filteredCount={3} />
      );
      expect(container).toMatchSnapshot();
    });
  });
});
