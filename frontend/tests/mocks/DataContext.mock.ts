import { ReactNode } from 'react';
import { vi } from 'vitest';
import type { Category, Item, Collection, Tenant } from '../../src/types';
import type { DataContextValue } from '../../src/DataContext';

export const mockCategories: Category[] = [
  { tenantId: 1, categoryId: 1, name: 'Root Category', description: 'Root description', parentCategoryId: null, isSystem: false },
  { tenantId: 1, categoryId: 2, name: 'Child Category', description: 'Child description', parentCategoryId: 1, isSystem: false },
  { tenantId: 1, categoryId: 3, name: 'Another Root', description: 'Another root description', parentCategoryId: null, isSystem: false },
];

export const mockItems: Item[] = [
  {
    id: 1,
    tenantId: 1,
    categoryId: 2,
    name: 'Test Item 1',
    summary: 'Test summary 1',
    description: 'Test description 1',
    properties: [{ category: 'General', name: 'Prop1', value: 'Value1' }],
    images: [{ url: 'https://example.com/image1.jpg', alt: 'Image 1' }],
  },
  {
    id: 2,
    tenantId: 1,
    categoryId: 2,
    name: 'Test Item 2',
    summary: 'Test summary 2',
    description: 'Test description 2',
    properties: [],
    images: [],
  },
];

export const mockCollections: Collection[] = [
  { collectionId: 1, name: 'Test Collection', tenantId: 1 },
];

export const mockTenants: Tenant[] = [
  { tenantId: 1, name: 'Test Tenant', owner: 'test@example.com' },
];

export const createMockDataContext = (overrides?: Partial<DataContextValue>): DataContextValue => ({
  categories: mockCategories,
  categoriesLoading: false,
  categoriesError: null,
  items: mockItems,
  itemsLoading: false,
  itemsError: null,
  collections: mockCollections,
  tenants: mockTenants,
  addItem: vi.fn(async () => 3),
  updateItem: vi.fn(async () => {}),
  deleteItem: vi.fn(async () => {}),
  refreshItems: vi.fn(async () => {}),
  addCategory: vi.fn(async () => 4),
  updateCategory: vi.fn(async () => {}),
  deleteCategory: vi.fn(async () => {}),
  refreshCategories: vi.fn(async () => {}),
  addCollection: vi.fn(),
  updateCollection: vi.fn(),
  deleteCollection: vi.fn(),
  addTenant: vi.fn(),
  updateTenant: vi.fn(),
  deleteTenant: vi.fn(),
  ...overrides,
});

export const mockDataContextValue = createMockDataContext();

// Mock the DataContext module
vi.mock('../../src/DataContext', async () => {
  const actual = await vi.importActual<typeof import('../../src/DataContext')>('../../src/DataContext');
  return {
    ...actual,
    useData: vi.fn(() => mockDataContextValue),
    DataProvider: ({ children }: { children: ReactNode }) => children,
  };
});

