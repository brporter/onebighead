import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import CollectionTemplateEditor from '../src/components/collection/CollectionTemplateEditor';
import DataContext from '../src/contexts/DataContext';
import type { Collection, ItemTemplate } from '../src/utils/types';

const mockCollection: Collection = {
  collectionId: 1,
  tenantId: 1,
  name: 'Test Collection',
  description: 'Test Description',
  heroImageUrl: null,
  slug: 'test-collection',
  isPublic: true,
};

const mockTemplates: ItemTemplate[] = [
  {
    itemTemplateId: 1,
    tenantId: 1,
    name: 'Template A',
    description: 'First template',
    isSystem: false,
    properties: [{ name: 'Prop1', defaultValue: '' }],
  },
  {
    itemTemplateId: 2,
    tenantId: 1,
    name: 'Template B',
    description: 'Second template',
    isSystem: true,
    properties: [],
  },
  {
    itemTemplateId: 3,
    tenantId: 1,
    name: 'Template C',
    description: '',
    isSystem: false,
    properties: [{ name: 'P1', defaultValue: '' }, { name: 'P2', defaultValue: '' }],
  },
];

function createMockContext(overrides: Partial<ReturnType<typeof useDataMock>> = {}) {
  const base = {
    collections: [],
    categories: [],
    items: [],
    itemTemplates: mockTemplates,
    propertySuggestions: [],
    loading: false,
    error: null,
    categoriesLoading: false,
    categoriesError: null,
    itemsLoading: false,
    itemsError: null,
    collectionsLoading: false,
    collectionsError: null,
    itemTemplatesLoading: false,
    itemTemplatesError: null,
    loadCollections: vi.fn(),
    addCollection: vi.fn(),
    updateCollection: vi.fn(),
    deleteCollection: vi.fn(),
    loadCategories: vi.fn(),
    addCategory: vi.fn(),
    updateCategory: vi.fn(),
    deleteCategory: vi.fn(),
    loadItems: vi.fn(),
    addItem: vi.fn(),
    updateItem: vi.fn(),
    deleteItem: vi.fn(),
    uploadImage: vi.fn(),
    loadItemTemplates: vi.fn().mockResolvedValue(mockTemplates),
    addItemTemplate: vi.fn(),
    updateItemTemplate: vi.fn(),
    deleteItemTemplate: vi.fn(),
    loadCollectionTemplates: vi.fn().mockResolvedValue([mockTemplates[0]]),
    associateTemplateWithCollection: vi.fn().mockResolvedValue(undefined),
    disassociateTemplateFromCollection: vi.fn().mockResolvedValue(undefined),
    loadPropertySuggestions: vi.fn(),
    syncPropertySuggestions: vi.fn(),
    setSelectedCategoryId: vi.fn(),
    selectedCategoryId: null,
  };
  return { ...base, ...overrides };
}

function useDataMock() {
  return createMockContext();
}

describe('CollectionTemplateEditor', () => {
  let mockContext: ReturnType<typeof createMockContext>;

  beforeEach(() => {
    mockContext = createMockContext();
  });

  const renderComponent = (onClose = vi.fn(), onDirtyChange = vi.fn()) => {
    return render(
      <DataContext.Provider value={mockContext}>
        <CollectionTemplateEditor
          collection={mockCollection}
          onClose={onClose}
          onDirtyChange={onDirtyChange}
        />
      </DataContext.Provider>
    );
  };

  it('shows loading state initially', () => {
    renderComponent();
    expect(screen.getByText('Loading templates...')).toBeInTheDocument();
  });

  it('displays collection name in title', async () => {
    renderComponent();
    await waitFor(() => {
      expect(screen.getByText('Templates for "Test Collection"')).toBeInTheDocument();
    });
  });

  it('loads templates on mount', async () => {
    renderComponent();
    await waitFor(() => {
      expect(mockContext.loadCollectionTemplates).toHaveBeenCalledWith(1);
      expect(mockContext.loadItemTemplates).toHaveBeenCalled();
    });
  });

  it('displays all available templates with checkboxes', async () => {
    renderComponent();
    await waitFor(() => {
      expect(screen.getByText('Template A')).toBeInTheDocument();
      expect(screen.getByText('Template B')).toBeInTheDocument();
      expect(screen.getByText('Template C')).toBeInTheDocument();
    });
  });

  it('shows system badge for system templates', async () => {
    renderComponent();
    await waitFor(() => {
      expect(screen.getByText('System')).toBeInTheDocument();
    });
  });

  it('shows property count for each template', async () => {
    renderComponent();
    await waitFor(() => {
      expect(screen.getByText('1 property')).toBeInTheDocument();
      expect(screen.getByText('0 properties')).toBeInTheDocument();
      expect(screen.getByText('2 properties')).toBeInTheDocument();
    });
  });

  it('pre-checks templates already associated with collection', async () => {
    renderComponent();
    await waitFor(() => {
      const checkboxes = screen.getAllByRole('checkbox');
      // Template A (id: 1) is returned by loadCollectionTemplates
      expect(checkboxes[0]).toBeChecked();
      expect(checkboxes[1]).not.toBeChecked();
      expect(checkboxes[2]).not.toBeChecked();
    });
  });

  it('toggles template selection on checkbox click', async () => {
    renderComponent();
    await waitFor(() => {
      expect(screen.getByText('Template B')).toBeInTheDocument();
    });

    const checkboxes = screen.getAllByRole('checkbox');
    fireEvent.click(checkboxes[1]); // Click Template B

    await waitFor(() => {
      expect(checkboxes[1]).toBeChecked();
    });
  });

  it('reports dirty state when selection changes', async () => {
    const onDirtyChange = vi.fn();
    renderComponent(vi.fn(), onDirtyChange);

    await waitFor(() => {
      expect(screen.getByText('Template B')).toBeInTheDocument();
    });

    // Initially not dirty
    expect(onDirtyChange).toHaveBeenLastCalledWith(false);

    // Toggle a checkbox
    const checkboxes = screen.getAllByRole('checkbox');
    fireEvent.click(checkboxes[1]);

    await waitFor(() => {
      expect(onDirtyChange).toHaveBeenCalledWith(true);
    });
  });

  it('disables save button when no changes made', async () => {
    renderComponent();
    await waitFor(() => {
      const saveButton = screen.getByRole('button', { name: /save changes/i });
      expect(saveButton).toBeDisabled();
    });
  });

  it('enables save button when changes made', async () => {
    renderComponent();
    await waitFor(() => {
      expect(screen.getByText('Template B')).toBeInTheDocument();
    });

    const checkboxes = screen.getAllByRole('checkbox');
    fireEvent.click(checkboxes[1]);

    await waitFor(() => {
      const saveButton = screen.getByRole('button', { name: /save changes/i });
      expect(saveButton).not.toBeDisabled();
    });
  });

  it('calls associate API for newly selected templates on save', async () => {
    renderComponent();
    await waitFor(() => {
      expect(screen.getByText('Template B')).toBeInTheDocument();
    });

    // Select Template B
    const checkboxes = screen.getAllByRole('checkbox');
    fireEvent.click(checkboxes[1]);

    // Click save
    const saveButton = screen.getByRole('button', { name: /save changes/i });
    fireEvent.click(saveButton);

    await waitFor(() => {
      expect(mockContext.associateTemplateWithCollection).toHaveBeenCalledWith(1, 2);
    });
  });

  it('calls disassociate API for deselected templates on save', async () => {
    renderComponent();
    await waitFor(() => {
      expect(screen.getByText('Template A')).toBeInTheDocument();
    });

    // Deselect Template A (which was initially selected)
    const checkboxes = screen.getAllByRole('checkbox');
    fireEvent.click(checkboxes[0]);

    // Click save
    const saveButton = screen.getByRole('button', { name: /save changes/i });
    fireEvent.click(saveButton);

    await waitFor(() => {
      expect(mockContext.disassociateTemplateFromCollection).toHaveBeenCalledWith(1, 1);
    });
  });

  it('shows error when save fails', async () => {
    mockContext.associateTemplateWithCollection = vi.fn().mockRejectedValue(new Error('Network error'));
    renderComponent();

    await waitFor(() => {
      expect(screen.getByText('Template B')).toBeInTheDocument();
    });

    const checkboxes = screen.getAllByRole('checkbox');
    fireEvent.click(checkboxes[1]);

    const saveButton = screen.getByRole('button', { name: /save changes/i });
    fireEvent.click(saveButton);

    await waitFor(() => {
      expect(screen.getByText('Network error')).toBeInTheDocument();
    });
  });

  it('shows empty message when no templates available', async () => {
    mockContext.loadItemTemplates = vi.fn().mockResolvedValue([]);
    mockContext.loadCollectionTemplates = vi.fn().mockResolvedValue([]);
    mockContext.itemTemplates = [];

    renderComponent();
    await waitFor(() => {
      expect(screen.getByText(/no templates available/i)).toBeInTheDocument();
    });
  });

  it('calls onClose when Back button clicked with no changes', async () => {
    const onClose = vi.fn();
    renderComponent(onClose);

    await waitFor(() => {
      expect(screen.getByText('Template A')).toBeInTheDocument();
    });

    const backButton = screen.getByRole('button', { name: /back/i });
    fireEvent.click(backButton);

    expect(onClose).toHaveBeenCalled();
  });

  it('shows Cancel button when there are unsaved changes', async () => {
    renderComponent();
    await waitFor(() => {
      expect(screen.getByText('Template B')).toBeInTheDocument();
    });

    // Initially shows Back
    expect(screen.getByRole('button', { name: /back/i })).toBeInTheDocument();

    // Make a change
    const checkboxes = screen.getAllByRole('checkbox');
    fireEvent.click(checkboxes[1]);

    // Now shows Cancel
    await waitFor(() => {
      expect(screen.getByRole('button', { name: /cancel/i })).toBeInTheDocument();
    });
  });

  it('shows saving state during save operation', async () => {
    // Create a promise we can control
    let resolveAssociate: () => void;
    mockContext.associateTemplateWithCollection = vi.fn().mockImplementation(
      () => new Promise((resolve) => { resolveAssociate = resolve; })
    );

    renderComponent();
    await waitFor(() => {
      expect(screen.getByText('Template B')).toBeInTheDocument();
    });

    const checkboxes = screen.getAllByRole('checkbox');
    fireEvent.click(checkboxes[1]);

    const saveButton = screen.getByRole('button', { name: /save changes/i });
    fireEvent.click(saveButton);

    await waitFor(() => {
      expect(screen.getByRole('button', { name: /saving/i })).toBeInTheDocument();
    });

    // Complete the save
    resolveAssociate!();
  });

  it('disables checkboxes during save', async () => {
    let resolveAssociate: () => void;
    mockContext.associateTemplateWithCollection = vi.fn().mockImplementation(
      () => new Promise((resolve) => { resolveAssociate = resolve; })
    );

    renderComponent();
    await waitFor(() => {
      expect(screen.getByText('Template B')).toBeInTheDocument();
    });

    const checkboxes = screen.getAllByRole('checkbox');
    fireEvent.click(checkboxes[1]);

    const saveButton = screen.getByRole('button', { name: /save changes/i });
    fireEvent.click(saveButton);

    await waitFor(() => {
      const allCheckboxes = screen.getAllByRole('checkbox');
      allCheckboxes.forEach(checkbox => {
        expect(checkbox).toBeDisabled();
      });
    });

    resolveAssociate!();
  });

  it('resets dirty state after successful save', async () => {
    const onDirtyChange = vi.fn();
    renderComponent(vi.fn(), onDirtyChange);

    await waitFor(() => {
      expect(screen.getByText('Template B')).toBeInTheDocument();
    });

    const checkboxes = screen.getAllByRole('checkbox');
    fireEvent.click(checkboxes[1]);

    const saveButton = screen.getByRole('button', { name: /save changes/i });
    fireEvent.click(saveButton);

    await waitFor(() => {
      expect(onDirtyChange).toHaveBeenLastCalledWith(false);
    });
  });
});
