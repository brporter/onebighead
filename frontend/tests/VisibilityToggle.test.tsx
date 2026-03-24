import { render, screen, fireEvent } from '@testing-library/react';
import { describe, it, expect, vi } from 'vitest';
import VisibilityToggle from '../src/components/common/VisibilityToggle';
import { Visibility } from '../src/utils/types';

describe('VisibilityToggle', () => {
  describe('Collection mode (isCollection=true)', () => {
    it('should render Public and Private buttons only', () => {
      render(
        <VisibilityToggle
          visibility={Visibility.Public}
          effectiveIsPublic={true}
          parentIsPublic={true}
          onChange={() => {}}
          isCollection={true}
        />
      );

      expect(screen.getByTitle('Mark as public')).toBeInTheDocument();
      expect(screen.getByTitle('Mark as private')).toBeInTheDocument();
    });

    it('should show Public selected when visibility is Public', () => {
      render(
        <VisibilityToggle
          visibility={Visibility.Public}
          effectiveIsPublic={true}
          parentIsPublic={true}
          onChange={() => {}}
          isCollection={true}
        />
      );

      const publicBtn = screen.getByTitle('Mark as public');
      expect(publicBtn).toHaveClass('selected');
    });

    it('should show Private selected when visibility is Private', () => {
      render(
        <VisibilityToggle
          visibility={Visibility.Private}
          effectiveIsPublic={false}
          parentIsPublic={true}
          onChange={() => {}}
          isCollection={true}
        />
      );

      const privateBtn = screen.getByTitle('Mark as private');
      expect(privateBtn).toHaveClass('selected');
    });

    it('should call onChange with Visibility.Public when Public is clicked', () => {
      const onChange = vi.fn();
      render(
        <VisibilityToggle
          visibility={Visibility.Private}
          effectiveIsPublic={false}
          parentIsPublic={true}
          onChange={onChange}
          isCollection={true}
        />
      );

      fireEvent.click(screen.getByTitle('Mark as public'));
      expect(onChange).toHaveBeenCalledWith(Visibility.Public);
    });

    it('should call onChange with Visibility.Private when Private is clicked', () => {
      const onChange = vi.fn();
      render(
        <VisibilityToggle
          visibility={Visibility.Public}
          effectiveIsPublic={true}
          parentIsPublic={true}
          onChange={onChange}
          isCollection={true}
        />
      );

      fireEvent.click(screen.getByTitle('Mark as private'));
      expect(onChange).toHaveBeenCalledWith(Visibility.Private);
    });
  });

  describe('Category/Item mode (isCollection=false)', () => {
    it('should render Public and Private buttons', () => {
      render(
        <VisibilityToggle
          visibility={Visibility.Private}
          effectiveIsPublic={false}
          parentIsPublic={true}
          onChange={() => {}}
        />
      );

      expect(screen.getByTitle('Mark as public')).toBeInTheDocument();
      expect(screen.getByTitle('Mark as private')).toBeInTheDocument();
    });

    it('should show Public selected when visibility is Public', () => {
      render(
        <VisibilityToggle
          visibility={Visibility.Public}
          effectiveIsPublic={true}
          parentIsPublic={true}
          onChange={() => {}}
        />
      );

      const publicBtn = screen.getByTitle('Mark as public');
      expect(publicBtn).toHaveClass('selected');
    });

    it('should show Private selected when visibility is Private', () => {
      render(
        <VisibilityToggle
          visibility={Visibility.Private}
          effectiveIsPublic={false}
          parentIsPublic={true}
          onChange={() => {}}
        />
      );

      const privateBtn = screen.getByTitle('Mark as private');
      expect(privateBtn).toHaveClass('selected');
    });

    it('should call onChange with Visibility.Public when Public is clicked', () => {
      const onChange = vi.fn();
      render(
        <VisibilityToggle
          visibility={Visibility.Private}
          effectiveIsPublic={false}
          parentIsPublic={true}
          onChange={onChange}
        />
      );

      fireEvent.click(screen.getByTitle('Mark as public'));
      expect(onChange).toHaveBeenCalledWith(Visibility.Public);
    });

    it('should call onChange with Visibility.Private when Private is clicked', () => {
      const onChange = vi.fn();
      render(
        <VisibilityToggle
          visibility={Visibility.Public}
          effectiveIsPublic={true}
          parentIsPublic={true}
          onChange={onChange}
        />
      );

      fireEvent.click(screen.getByTitle('Mark as private'));
      expect(onChange).toHaveBeenCalledWith(Visibility.Private);
    });
  });

  describe('Parent visibility restrictions', () => {
    it('should disable Public button when parent is private', () => {
      render(
        <VisibilityToggle
          visibility={Visibility.Private}
          effectiveIsPublic={false}
          parentIsPublic={false}
          onChange={() => {}}
        />
      );

      const publicBtn = screen.getByTitle('Mark as public');
      expect(publicBtn).toBeDisabled();
    });

    it('should show note when parent is private', () => {
      render(
        <VisibilityToggle
          visibility={Visibility.Private}
          effectiveIsPublic={false}
          parentIsPublic={false}
          onChange={() => {}}
        />
      );

      expect(screen.getByText(/cannot override to public/i)).toBeInTheDocument();
    });

    it('should not show note when parent is public', () => {
      render(
        <VisibilityToggle
          visibility={Visibility.Private}
          effectiveIsPublic={false}
          parentIsPublic={true}
          onChange={() => {}}
        />
      );

      expect(screen.queryByText(/cannot override to public/i)).not.toBeInTheDocument();
    });

    it('should not show note for collection mode even when parent is private', () => {
      render(
        <VisibilityToggle
          visibility={Visibility.Private}
          effectiveIsPublic={false}
          parentIsPublic={false}
          onChange={() => {}}
          isCollection={true}
        />
      );

      expect(screen.queryByText(/cannot override to public/i)).not.toBeInTheDocument();
    });
  });

  describe('Effective visibility display', () => {
    it('should show "Public" with success style when effective is public', () => {
      render(
        <VisibilityToggle
          visibility={Visibility.Public}
          effectiveIsPublic={true}
          parentIsPublic={true}
          onChange={() => {}}
        />
      );

      const effectiveSpan = screen.getByText('Public', { selector: '.visibility-effective span' });
      expect(effectiveSpan).toHaveClass('public');
    });

    it('should show "Private" when effective is private', () => {
      render(
        <VisibilityToggle
          visibility={Visibility.Private}
          effectiveIsPublic={false}
          parentIsPublic={true}
          onChange={() => {}}
        />
      );

      const effectiveSpan = screen.getByText('Private', { selector: '.visibility-effective span' });
      expect(effectiveSpan).toHaveClass('private');
    });
  });

  describe('Custom label', () => {
    it('should display custom label', () => {
      render(
        <VisibilityToggle
          visibility={Visibility.Private}
          effectiveIsPublic={false}
          parentIsPublic={true}
          onChange={() => {}}
          label="Collection Visibility"
        />
      );

      expect(screen.getByText('Collection Visibility')).toBeInTheDocument();
    });

    it('should display default "Visibility" label when not provided', () => {
      render(
        <VisibilityToggle
          visibility={Visibility.Private}
          effectiveIsPublic={false}
          parentIsPublic={true}
          onChange={() => {}}
        />
      );

      expect(screen.getByText('Visibility')).toBeInTheDocument();
    });
  });

  describe('snapshots', () => {
    it('should match snapshot for collection mode (public)', () => {
      const { container } = render(
        <VisibilityToggle
          visibility={Visibility.Public}
          effectiveIsPublic={true}
          parentIsPublic={true}
          onChange={() => {}}
          isCollection={true}
        />
      );
      expect(container).toMatchSnapshot();
    });

    it('should match snapshot for item mode (private)', () => {
      const { container } = render(
        <VisibilityToggle
          visibility={Visibility.Private}
          effectiveIsPublic={false}
          parentIsPublic={true}
          onChange={() => {}}
        />
      );
      expect(container).toMatchSnapshot();
    });

    it('should match snapshot when parent is private', () => {
      const { container } = render(
        <VisibilityToggle
          visibility={Visibility.Private}
          effectiveIsPublic={false}
          parentIsPublic={false}
          onChange={() => {}}
        />
      );
      expect(container).toMatchSnapshot();
    });
  });
});
