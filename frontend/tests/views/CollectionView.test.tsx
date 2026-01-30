import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter, Routes, Route } from 'react-router-dom';
import CollectionView from '../../src/views/CollectionView';
import { useData } from '../../src/contexts/DataContext';
import type { Collection } from '../../src/utils/types';

vi.mock('../../src/contexts/DataContext', () => ({
  useData: vi.fn(),
}));

const mockNavigate = vi.fn();
vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual('react-router-dom');
  return {
    ...actual,
    useNavigate: () => mockNavigate,
  };
});

function renderWithRouter() {
  return render(
    <MemoryRouter initialEntries={['/collections']}>
      <Routes>
        <Route path="/collections" element={<CollectionView />} />
      </Routes>
    </MemoryRouter>
  );
}

describe('CollectionView', () => {
  const mockCollections: Collection[] = [
    { collectionId: 1, tenantId: 1, name: 'Collection One', description: 'First collection', heroImageUrl: null, slug: 'one' },
    { collectionId: 2, tenantId: 1, name: 'Collection Two', description: 'Second collection', heroImageUrl: null, slug: 'two' },
  ];

  const mockDataContext = {
    collections: mockCollections,
    collectionsLoading: false,
    loadCollections: vi.fn(),
  };

  beforeEach(() => {
    vi.clearAllMocks();
    (useData as ReturnType<typeof vi.fn>).mockReturnValue(mockDataContext);
  });

  it('should load collections on mount', () => {
    renderWithRouter();

    expect(mockDataContext.loadCollections).toHaveBeenCalled();
  });

  it('should show loading state while collections are loading', () => {
    (useData as ReturnType<typeof vi.fn>).mockReturnValue({
      ...mockDataContext,
      collectionsLoading: true,
      collections: [],
    });

    renderWithRouter();

    expect(screen.getByText('Loading collections...')).toBeInTheDocument();
  });

  it('should show message when no collections found', () => {
    (useData as ReturnType<typeof vi.fn>).mockReturnValue({
      ...mockDataContext,
      collections: [],
    });

    renderWithRouter();

    expect(screen.getByText('Redirecting to setup...')).toBeInTheDocument();
  });

  it('should render collection list', () => {
    renderWithRouter();

    expect(screen.getByText('Collection One')).toBeInTheDocument();
    expect(screen.getByText('Collection Two')).toBeInTheDocument();
  });

  it('should navigate to collection when clicked', async () => {
    const user = userEvent.setup();
    renderWithRouter();

    await user.click(screen.getByText('Collection One'));

    expect(mockNavigate).toHaveBeenCalledWith('/collections/1');
  });

  it('should auto-navigate when only one collection exists', async () => {
    (useData as ReturnType<typeof vi.fn>).mockReturnValue({
      ...mockDataContext,
      collections: [mockCollections[0]],
    });

    renderWithRouter();

    await waitFor(() => {
      expect(mockNavigate).toHaveBeenCalledWith('/collections/1', { replace: true });
    });
  });

  describe('snapshots', () => {
    it('should match snapshot with collections', () => {
      const { container } = renderWithRouter();
      expect(container).toMatchSnapshot();
    });
  });
});
