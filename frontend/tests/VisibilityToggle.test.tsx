import { render, screen, fireEvent } from '@testing-library/react';
import { describe, it, expect, vi } from 'vitest';
import VisibilityToggle from '../src/components/common/VisibilityToggle';

describe('VisibilityToggle', () => {
  describe('Collection mode (isCollection=true)', () => {
    it('should render Public and Private buttons only', () => {
      render(
        <VisibilityToggle
          isPublicOverride={true}
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
          isPublicOverride={true}
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
          isPublicOverride={false}
          effectiveIsPublic={false}
          parentIsPublic={true}
          onChange={() => {}}
          isCollection={true}
        />
      );
      
      const privateBtn = screen.getByTitle('Mark as private');
      expect(privateBtn).toHaveClass('selected');
    });

    it('should call onChange with true when Public is clicked', () => {
      const onChange = vi.fn();
      render(
        <VisibilityToggle
          isPublicOverride={false}
          effectiveIsPublic={false}
          parentIsPublic={true}
          onChange={onChange}
          isCollection={true}
        />
      );
      
      fireEvent.click(screen.getByTitle('Mark as public'));
      expect(onChange).toHaveBeenCalledWith(true);
    });

    it('should call onChange with false when Private is clicked', () => {
      const onChange = vi.fn();
      render(
        <VisibilityToggle
          isPublicOverride={true}
          effectiveIsPublic={true}
          parentIsPublic={true}
          onChange={onChange}
          isCollection={true}
        />
      );
      
      fireEvent.click(screen.getByTitle('Mark as private'));
      expect(onChange).toHaveBeenCalledWith(false);
    });
  });

  describe('Category/Item mode (isCollection=false)', () => {
    it('should render Inherit, Public, and Private buttons', () => {
      render(
        <VisibilityToggle
          isPublicOverride={null}
          effectiveIsPublic={true}
          parentIsPublic={true}
          onChange={() => {}}
        />
      );
      
      expect(screen.getByText(/Inherit/)).toBeInTheDocument();
      expect(screen.getByTitle('Mark as public')).toBeInTheDocument();
      expect(screen.getByTitle('Mark as private')).toBeInTheDocument();
    });

    it('should show Inherit selected when isPublicOverride is null', () => {
      render(
        <VisibilityToggle
          isPublicOverride={null}
          effectiveIsPublic={true}
          parentIsPublic={true}
          onChange={() => {}}
        />
      );
      
      const inheritBtn = screen.getByText(/Inherit \(Public\)/);
      expect(inheritBtn).toHaveClass('selected');
    });

    it('should show Public selected when isPublicOverride is true', () => {
      render(
        <VisibilityToggle
          isPublicOverride={true}
          effectiveIsPublic={true}
          parentIsPublic={true}
          onChange={() => {}}
        />
      );
      
      const publicBtn = screen.getByTitle('Mark as public');
      expect(publicBtn).toHaveClass('selected');
    });

    it('should show Private selected when isPublicOverride is false', () => {
      render(
        <VisibilityToggle
          isPublicOverride={false}
          effectiveIsPublic={false}
          parentIsPublic={true}
          onChange={() => {}}
        />
      );
      
      const privateBtn = screen.getByTitle('Mark as private');
      expect(privateBtn).toHaveClass('selected');
    });

    it('should call onChange with null when Inherit is clicked', () => {
      const onChange = vi.fn();
      render(
        <VisibilityToggle
          isPublicOverride={true}
          effectiveIsPublic={true}
          parentIsPublic={true}
          onChange={onChange}
        />
      );
      
      fireEvent.click(screen.getByText(/Inherit \(Public\)/));
      expect(onChange).toHaveBeenCalledWith(null);
    });

    it('should call onChange with true when Public is clicked', () => {
      const onChange = vi.fn();
      render(
        <VisibilityToggle
          isPublicOverride={null}
          effectiveIsPublic={true}
          parentIsPublic={true}
          onChange={onChange}
        />
      );
      
      fireEvent.click(screen.getByTitle('Mark as public'));
      expect(onChange).toHaveBeenCalledWith(true);
    });

    it('should call onChange with false when Private is clicked', () => {
      const onChange = vi.fn();
      render(
        <VisibilityToggle
          isPublicOverride={null}
          effectiveIsPublic={true}
          parentIsPublic={true}
          onChange={onChange}
        />
      );
      
      fireEvent.click(screen.getByTitle('Mark as private'));
      expect(onChange).toHaveBeenCalledWith(false);
    });
  });

  describe('Parent visibility restrictions', () => {
    it('should disable Public button when parent is private', () => {
      render(
        <VisibilityToggle
          isPublicOverride={null}
          effectiveIsPublic={false}
          parentIsPublic={false}
          onChange={() => {}}
        />
      );
      
      const publicBtn = screen.getByTitle('Mark as public');
      expect(publicBtn).toBeDisabled();
    });

    it('should disable Inherit button when parent is private and override is not inherit', () => {
      render(
        <VisibilityToggle
          isPublicOverride={false}
          effectiveIsPublic={false}
          parentIsPublic={false}
          onChange={() => {}}
        />
      );
      
      const inheritBtn = screen.getByText(/Inherit \(Private\)/);
      expect(inheritBtn).toBeDisabled();
    });

    it('should show note when parent is private', () => {
      render(
        <VisibilityToggle
          isPublicOverride={null}
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
          isPublicOverride={null}
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
          isPublicOverride={null}
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
          isPublicOverride={null}
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
          isPublicOverride={true}
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
          isPublicOverride={false}
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
          isPublicOverride={null}
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
          isPublicOverride={null}
          effectiveIsPublic={true}
          parentIsPublic={true}
          onChange={() => {}}
        />
      );
      
      expect(screen.getByText('Visibility')).toBeInTheDocument();
    });
  });
});
