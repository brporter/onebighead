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
      expect(screen.queryByText(/Inherit/)).not.toBeInTheDocument();
    });

    it('should show Public selected when effectiveIsPublic is true', () => {
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

    it('should show Private selected when effectiveIsPublic is false', () => {
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
    it('should render Inherit, Public, and Private buttons', () => {
      render(
        <VisibilityToggle
          visibility={Visibility.Default}
          effectiveIsPublic={true}
          parentIsPublic={true}
          onChange={() => {}}
        />
      );

      expect(screen.getByText(/Inherit/)).toBeInTheDocument();
      expect(screen.getByTitle('Mark as public')).toBeInTheDocument();
      expect(screen.getByTitle('Mark as private')).toBeInTheDocument();
    });

    it('should show Inherit selected when visibility is Default', () => {
      render(
        <VisibilityToggle
          visibility={Visibility.Default}
          effectiveIsPublic={true}
          parentIsPublic={true}
          onChange={() => {}}
        />
      );

      const inheritBtn = screen.getByText(/Inherit \(Public\)/);
      expect(inheritBtn).toHaveClass('selected');
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

    it('should call onChange with Visibility.Default when Inherit is clicked', () => {
      const onChange = vi.fn();
      render(
        <VisibilityToggle
          visibility={Visibility.Public}
          effectiveIsPublic={true}
          parentIsPublic={true}
          onChange={onChange}
        />
      );

      fireEvent.click(screen.getByText(/Inherit \(Public\)/));
      expect(onChange).toHaveBeenCalledWith(Visibility.Default);
    });

    it('should call onChange with Visibility.Public when Public is clicked', () => {
      const onChange = vi.fn();
      render(
        <VisibilityToggle
          visibility={Visibility.Default}
          effectiveIsPublic={true}
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
          visibility={Visibility.Default}
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
          visibility={Visibility.Default}
          effectiveIsPublic={false}
          parentIsPublic={false}
          onChange={() => {}}
        />
      );

      const publicBtn = screen.getByTitle('Mark as public');
      expect(publicBtn).toBeDisabled();
    });

    it('should enable Inherit button even when parent is private', () => {
      render(
        <VisibilityToggle
          visibility={Visibility.Private}
          effectiveIsPublic={false}
          parentIsPublic={false}
          onChange={() => {}}
        />
      );

      const inheritBtn = screen.getByText(/Inherit \(Private\)/);
      expect(inheritBtn).toBeEnabled();
    });

    it('should allow switching from Private to Inherit when parent is private', () => {
      const onChange = vi.fn();
      render(
        <VisibilityToggle
          visibility={Visibility.Private}
          effectiveIsPublic={false}
          parentIsPublic={false}
          onChange={onChange}
        />
      );

      fireEvent.click(screen.getByText(/Inherit \(Private\)/));
      expect(onChange).toHaveBeenCalledWith(Visibility.Default);
    });

    it('should show note when parent is private', () => {
      render(
        <VisibilityToggle
          visibility={Visibility.Default}
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
          visibility={Visibility.Default}
          effectiveIsPublic={true}
          parentIsPublic={true}
          onChange={() => {}}
        />
      );

      expect(screen.queryByText(/cannot override to public/i)).not.toBeInTheDocument();
    });

    it('should show inherited status in Inherit button', () => {
      render(
        <VisibilityToggle
          visibility={Visibility.Default}
          effectiveIsPublic={true}
          parentIsPublic={true}
          onChange={() => {}}
        />
      );

      expect(screen.getByText(/Inherit \(Public\)/)).toBeInTheDocument();
    });

    it('should show Private in Inherit button when parent is private', () => {
      render(
        <VisibilityToggle
          visibility={Visibility.Default}
          effectiveIsPublic={false}
          parentIsPublic={false}
          onChange={() => {}}
        />
      );

      expect(screen.getByText(/Inherit \(Private\)/)).toBeInTheDocument();
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
          visibility={Visibility.Default}
          effectiveIsPublic={true}
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
          visibility={Visibility.Default}
          effectiveIsPublic={true}
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

    it('should match snapshot for item mode with inherit', () => {
      const { container } = render(
        <VisibilityToggle
          visibility={Visibility.Default}
          effectiveIsPublic={true}
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
