import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, it, expect, vi } from 'vitest';
import { PublishButton } from '../src/components/common/PublishButton';

describe('PublishButton', () => {
  it('should render with "Publish" text', () => {
    render(<PublishButton onPublish={() => {}} />);

    expect(screen.getByRole('button')).toHaveTextContent('Publish');
  });

  it('should call onPublish callback when clicked', async () => {
    const user = userEvent.setup();
    const handlePublish = vi.fn();

    render(<PublishButton onPublish={handlePublish} />);

    await user.click(screen.getByRole('button'));

    expect(handlePublish).toHaveBeenCalledTimes(1);
  });

  it('should stop event propagation on click', async () => {
    const handlePublish = vi.fn();
    const handleParentClick = vi.fn();

    const { container } = render(
      <div onClick={handleParentClick}>
        <PublishButton onPublish={handlePublish} />
      </div>
    );

    const button = screen.getByRole('button');
    await userEvent.setup().click(button);

    expect(handlePublish).toHaveBeenCalledTimes(1);
    expect(handleParentClick).not.toHaveBeenCalled();
  });

  it('should have the publish-btn CSS class', () => {
    render(<PublishButton onPublish={() => {}} />);

    expect(screen.getByRole('button')).toHaveClass('publish-btn');
  });

  it('should append additional className when provided', () => {
    render(<PublishButton onPublish={() => {}} className="extra" />);

    const button = screen.getByRole('button');
    expect(button).toHaveClass('publish-btn');
    expect(button).toHaveClass('extra');
  });

  it('should contain an SVG icon', () => {
    const { container } = render(<PublishButton onPublish={() => {}} />);

    const svg = container.querySelector('svg');
    expect(svg).toBeInTheDocument();
  });

  describe('snapshots', () => {
    it('should match snapshot', () => {
      const { container } = render(<PublishButton onPublish={() => {}} />);

      expect(container).toMatchSnapshot();
    });

    it('should match snapshot with custom className', () => {
      const { container } = render(<PublishButton onPublish={() => {}} className="custom" />);

      expect(container).toMatchSnapshot();
    });
  });
});
