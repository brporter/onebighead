import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, it, expect, vi } from 'vitest';
import { PublicBadge } from '../src/components/common/PublicBadge';

describe('PublicBadge', () => {
  it('should render with "Public" text when effectiveIsPublic is true', () => {
    render(<PublicBadge effectiveIsPublic={true} onUnpublish={() => {}} />);

    expect(screen.getByText('Public')).toBeInTheDocument();
  });

  it('should not render when effectiveIsPublic is false', () => {
    const { container } = render(<PublicBadge effectiveIsPublic={false} onUnpublish={() => {}} />);

    expect(container.firstChild).toBeNull();
  });

  it('should call onUnpublish callback when clicked', async () => {
    const user = userEvent.setup();
    const handleUnpublish = vi.fn();

    render(<PublicBadge effectiveIsPublic={true} onUnpublish={handleUnpublish} />);

    await user.click(screen.getByRole('button'));

    expect(handleUnpublish).toHaveBeenCalledTimes(1);
  });

  it('should stop event propagation on click', async () => {
    const handleUnpublish = vi.fn();
    const handleParentClick = vi.fn();

    render(
      <div onClick={handleParentClick}>
        <PublicBadge effectiveIsPublic={true} onUnpublish={handleUnpublish} />
      </div>
    );

    await userEvent.setup().click(screen.getByRole('button'));

    expect(handleUnpublish).toHaveBeenCalledTimes(1);
    expect(handleParentClick).not.toHaveBeenCalled();
  });

  it('should have the public-badge CSS class', () => {
    render(<PublicBadge effectiveIsPublic={true} onUnpublish={() => {}} />);

    expect(screen.getByRole('button')).toHaveClass('public-badge');
  });

  it('should append additional className when provided', () => {
    render(<PublicBadge effectiveIsPublic={true} onUnpublish={() => {}} className="extra" />);

    const button = screen.getByRole('button');
    expect(button).toHaveClass('public-badge');
    expect(button).toHaveClass('extra');
  });

  it('should contain "Unpublish" text in the hover span', () => {
    render(<PublicBadge effectiveIsPublic={true} onUnpublish={() => {}} />);

    expect(screen.getByText('Unpublish')).toBeInTheDocument();
  });

  it('should have default and hover spans', () => {
    const { container } = render(<PublicBadge effectiveIsPublic={true} onUnpublish={() => {}} />);

    expect(container.querySelector('.public-badge__default')).toBeInTheDocument();
    expect(container.querySelector('.public-badge__hover')).toBeInTheDocument();
  });

  it('should contain SVG icons', () => {
    const { container } = render(<PublicBadge effectiveIsPublic={true} onUnpublish={() => {}} />);

    const svgs = container.querySelectorAll('svg');
    expect(svgs).toHaveLength(2);
  });

  describe('snapshots', () => {
    it('should match snapshot when public', () => {
      const { container } = render(<PublicBadge effectiveIsPublic={true} onUnpublish={() => {}} />);

      expect(container).toMatchSnapshot();
    });

    it('should match snapshot when not public', () => {
      const { container } = render(<PublicBadge effectiveIsPublic={false} onUnpublish={() => {}} />);

      expect(container).toMatchSnapshot();
    });

    it('should match snapshot with custom className', () => {
      const { container } = render(<PublicBadge effectiveIsPublic={true} onUnpublish={() => {}} className="custom" />);

      expect(container).toMatchSnapshot();
    });
  });
});
