import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import CategoryTemplateSelector from '../src/components/category/CategoryTemplateSelector';
import { useData } from '../src/contexts/DataContext';
import type { ItemTemplate } from '../src/utils/types';

vi.mock('../src/contexts/DataContext', () => ({
  useData: vi.fn(),
}));

describe('CategoryTemplateSelector', () => {
  const mockCollectionTemplates: ItemTemplate[] = [
    {
      itemTemplateId: 1,
      name: 'Collection Template 1',
      description: 'Description 1',
      isSystem: false,
      properties: [],
      createdAt: '2026-01-01',
      updatedAt: '2026-01-01',
    },
    {
      itemTemplateId: 2,
      name: 'Collection Template 2',
      description: '',
      isSystem: false,
      properties: [],
      createdAt: '2026-01-01',
      updatedAt: '2026-01-01',
    },
  ];

  const mockLibraryTemplates: ItemTemplate[] = [
    {
      itemTemplateId: 3,
      name: 'Library Template',
      description: 'A library template',
      isSystem: true,
      properties: [],
      createdAt: '2026-01-01',
      updatedAt: '2026-01-01',
    },
  ];

  const mockLoadCollectionTemplates = vi.fn();
  const mockLoadItemTemplates = vi.fn();

  const defaultProps = {
    collectionId: 1,
    selectedTemplateIds: [] as number[],
    onChange: vi.fn(),
    disabled: false,
  };

  beforeEach(() => {
    vi.clearAllMocks();
    mockLoadCollectionTemplates.mockResolvedValue(mockCollectionTemplates);
    mockLoadItemTemplates.mockResolvedValue(undefined);
    (useData as ReturnType<typeof vi.fn>).mockReturnValue({
      loadCollectionTemplates: mockLoadCollectionTemplates,
      loadItemTemplates: mockLoadItemTemplates,
      itemTemplates: mockLibraryTemplates,
    });
  });

  describe('loading state', () => {
    it('should show loading message while templates are loading', () => {
      // Make the promise never resolve to keep loading state
      mockLoadCollectionTemplates.mockReturnValue(new Promise(() => {}));
      mockLoadItemTemplates.mockReturnValue(new Promise(() => {}));

      render(<CategoryTemplateSelector {...defaultProps} />);

      expect(screen.getByText('Loading templates...')).toBeInTheDocument();
    });

    it('should hide loading message after templates load', async () => {
      render(<CategoryTemplateSelector {...defaultProps} />);

      await waitFor(() => {
        expect(screen.queryByText('Loading templates...')).not.toBeInTheDocument();
      });
    });
  });

  describe('empty state', () => {
    it('should show "No templates available" when no templates exist', async () => {
      mockLoadCollectionTemplates.mockResolvedValue([]);
      (useData as ReturnType<typeof vi.fn>).mockReturnValue({
        loadCollectionTemplates: mockLoadCollectionTemplates,
        loadItemTemplates: mockLoadItemTemplates,
        itemTemplates: [],
      });

      render(<CategoryTemplateSelector {...defaultProps} />);

      await waitFor(() => {
        expect(screen.getByText('No templates available.')).toBeInTheDocument();
      });
    });
  });

  describe('template display', () => {
    it('should display collection templates', async () => {
      render(<CategoryTemplateSelector {...defaultProps} />);

      await waitFor(() => {
        expect(screen.getByText('Collection Template 1')).toBeInTheDocument();
        expect(screen.getByText('Collection Template 2')).toBeInTheDocument();
      });
    });

    it('should display library templates', async () => {
      render(<CategoryTemplateSelector {...defaultProps} />);

      await waitFor(() => {
        expect(screen.getByText('Library Template')).toBeInTheDocument();
      });
    });

    it('should display template descriptions when present', async () => {
      render(<CategoryTemplateSelector {...defaultProps} />);

      await waitFor(() => {
        expect(screen.getByText('Description 1')).toBeInTheDocument();
        expect(screen.getByText('A library template')).toBeInTheDocument();
      });
    });

    it('should display System badge for system templates', async () => {
      render(<CategoryTemplateSelector {...defaultProps} />);

      await waitFor(() => {
        expect(screen.getByText('System')).toBeInTheDocument();
      });
    });

    it('should deduplicate templates from collection and library', async () => {
      // Add a duplicate template to library with same ID as collection template
      const duplicateLibraryTemplates: ItemTemplate[] = [
        ...mockLibraryTemplates,
        {
          itemTemplateId: 1, // Same as Collection Template 1
          name: 'Duplicate Name',
          description: '',
          isSystem: false,
          properties: [],
          createdAt: '2026-01-01',
          updatedAt: '2026-01-01',
        },
      ];

      (useData as ReturnType<typeof vi.fn>).mockReturnValue({
        loadCollectionTemplates: mockLoadCollectionTemplates,
        loadItemTemplates: mockLoadItemTemplates,
        itemTemplates: duplicateLibraryTemplates,
      });

      render(<CategoryTemplateSelector {...defaultProps} />);

      await waitFor(() => {
        // Collection Template 1 should appear (from collection)
        expect(screen.getByText('Collection Template 1')).toBeInTheDocument();
        // Duplicate Name should NOT appear (deduplicated)
        expect(screen.queryByText('Duplicate Name')).not.toBeInTheDocument();
      });
    });

    it('should sort templates alphabetically', async () => {
      const unsortedTemplates: ItemTemplate[] = [
        { itemTemplateId: 1, name: 'Zebra Template', description: '', isSystem: false, properties: [], createdAt: '', updatedAt: '' },
        { itemTemplateId: 2, name: 'Apple Template', description: '', isSystem: false, properties: [], createdAt: '', updatedAt: '' },
      ];
      mockLoadCollectionTemplates.mockResolvedValue(unsortedTemplates);
      (useData as ReturnType<typeof vi.fn>).mockReturnValue({
        loadCollectionTemplates: mockLoadCollectionTemplates,
        loadItemTemplates: mockLoadItemTemplates,
        itemTemplates: [],
      });

      render(<CategoryTemplateSelector {...defaultProps} />);

      await waitFor(() => {
        const labels = screen.getAllByRole('checkbox');
        const labelTexts = labels.map(label => label.closest('label')?.textContent);
        expect(labelTexts[0]).toContain('Apple Template');
        expect(labelTexts[1]).toContain('Zebra Template');
      });
    });

    it('should show hint text about recommended templates', async () => {
      render(<CategoryTemplateSelector {...defaultProps} />);

      await waitFor(() => {
        expect(screen.getByText(/Items in this category will see these templates recommended/)).toBeInTheDocument();
      });
    });
  });

  describe('selection behavior', () => {
    it('should show checkboxes as checked for selected templates', async () => {
      render(<CategoryTemplateSelector {...defaultProps} selectedTemplateIds={[1, 3]} />);

      await waitFor(() => {
        const checkboxes = screen.getAllByRole('checkbox');
        const checkbox1 = checkboxes.find(cb => cb.closest('label')?.textContent?.includes('Collection Template 1'));
        const checkbox2 = checkboxes.find(cb => cb.closest('label')?.textContent?.includes('Collection Template 2'));
        const checkbox3 = checkboxes.find(cb => cb.closest('label')?.textContent?.includes('Library Template'));
        
        expect(checkbox1).toBeChecked();
        expect(checkbox2).not.toBeChecked();
        expect(checkbox3).toBeChecked();
      });
    });

    it('should call onChange with added template ID when unchecked template is clicked', async () => {
      const user = userEvent.setup();
      const onChange = vi.fn();

      render(<CategoryTemplateSelector {...defaultProps} selectedTemplateIds={[]} onChange={onChange} />);

      await waitFor(() => {
        expect(screen.getByText('Collection Template 1')).toBeInTheDocument();
      });

      const checkbox = screen.getAllByRole('checkbox')[0];
      await user.click(checkbox);

      expect(onChange).toHaveBeenCalledWith([1]);
    });

    it('should call onChange with removed template ID when checked template is clicked', async () => {
      const user = userEvent.setup();
      const onChange = vi.fn();

      render(<CategoryTemplateSelector {...defaultProps} selectedTemplateIds={[1, 2]} onChange={onChange} />);

      await waitFor(() => {
        expect(screen.getByText('Collection Template 1')).toBeInTheDocument();
      });

      // Find and click the first checkbox (Collection Template 1, due to sorting it may be first)
      const checkboxes = screen.getAllByRole('checkbox');
      const checkbox1 = checkboxes.find(cb => cb.closest('label')?.textContent?.includes('Collection Template 1'));
      await user.click(checkbox1!);

      expect(onChange).toHaveBeenCalledWith([2]);
    });
  });

  describe('disabled state', () => {
    it('should disable all checkboxes when disabled prop is true', async () => {
      render(<CategoryTemplateSelector {...defaultProps} disabled={true} />);

      await waitFor(() => {
        const checkboxes = screen.getAllByRole('checkbox');
        checkboxes.forEach(checkbox => {
          expect(checkbox).toBeDisabled();
        });
      });
    });

    it('should not call onChange when disabled and checkbox is clicked', async () => {
      const user = userEvent.setup();
      const onChange = vi.fn();

      render(<CategoryTemplateSelector {...defaultProps} disabled={true} onChange={onChange} />);

      await waitFor(() => {
        expect(screen.getByText('Collection Template 1')).toBeInTheDocument();
      });

      const checkbox = screen.getAllByRole('checkbox')[0];
      await user.click(checkbox);

      expect(onChange).not.toHaveBeenCalled();
    });

    it('should add disabled class to template items when disabled', async () => {
      render(<CategoryTemplateSelector {...defaultProps} disabled={true} />);

      await waitFor(() => {
        const labels = screen.getAllByRole('checkbox').map(cb => cb.closest('label'));
        labels.forEach(label => {
          expect(label).toHaveClass('categoryTemplateSelector__item--disabled');
        });
      });
    });
  });

  describe('data loading', () => {
    it('should call loadCollectionTemplates with collectionId', async () => {
      render(<CategoryTemplateSelector {...defaultProps} collectionId={42} />);

      await waitFor(() => {
        expect(mockLoadCollectionTemplates).toHaveBeenCalledWith(42);
      });
    });

    it('should call loadItemTemplates', async () => {
      render(<CategoryTemplateSelector {...defaultProps} />);

      await waitFor(() => {
        expect(mockLoadItemTemplates).toHaveBeenCalled();
      });
    });

    it('should reload templates when collectionId changes', async () => {
      const { rerender } = render(<CategoryTemplateSelector {...defaultProps} collectionId={1} />);

      await waitFor(() => {
        expect(mockLoadCollectionTemplates).toHaveBeenCalledWith(1);
      });

      mockLoadCollectionTemplates.mockClear();

      rerender(<CategoryTemplateSelector {...defaultProps} collectionId={2} />);

      await waitFor(() => {
        expect(mockLoadCollectionTemplates).toHaveBeenCalledWith(2);
      });
    });
  });

  describe('snapshots', () => {
    it('should match snapshot with templates', async () => {
      const { container } = render(<CategoryTemplateSelector {...defaultProps} />);

      await waitFor(() => {
        expect(screen.getByText('Collection Template 1')).toBeInTheDocument();
      });

      expect(container).toMatchSnapshot();
    });
  });
});
