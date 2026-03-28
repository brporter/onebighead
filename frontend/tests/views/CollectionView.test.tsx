import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter, Routes, Route } from 'react-router-dom';
import CollectionView from '../../src/views/CollectionView';
import { useData } from '../../src/contexts/useData';
import type { Collection } from '../../src/utils/types';
import { Visibility } from '../../src/utils/types';

vi.mock('../../src/contexts/useData', () => ({
  useData: vi.fn(),
}));

const mockRequestPublish = vi.fn();
const mockRequestUnpublish = vi.fn();

vi.mock('../../src/contexts/usePublish', () => ({
  usePublish: () => ({
    requestPublish: mockRequestPublish,
    requestUnpublish: mockRequestUnpublish,
    pendingIntent: null,
    clearIntent: vi.fn(),
  }),
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
    { collectionId: 1, workspaceId: 1, name: 'Collection One', description: 'First collection', heroImageUrl: null, slug: 'one', visibility: Visibility.Private, effectiveIsPublic: false },
    { collectionId: 2, workspaceId: 1, name: 'Collection Two', description: 'Second collection', heroImageUrl: null, slug: 'two', visibility: Visibility.Private, effectiveIsPublic: false },
  ];

  const mockDataContext = {
    collections: mockCollections,
    collectionsLoading: false,
    collectionsError: null,
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

  describe('publish/unpublish in collection list', () => {
    it('should show PublishButton for private collections', () => {
      renderWithRouter();
      const publishButtons = screen.getAllByText('Publish');
      expect(publishButtons.length).toBe(2);
    });

    it('should show PublicBadge for public collections', () => {
      const publicCollections: Collection[] = [
        { ...mockCollections[0], effectiveIsPublic: true },
        { ...mockCollections[1], effectiveIsPublic: false },
      ];
      (useData as ReturnType<typeof vi.fn>).mockReturnValue({
        ...mockDataContext,
        collections: publicCollections,
      });

      renderWithRouter();
      expect(screen.getByText('Public')).toBeInTheDocument();
      expect(screen.getAllByText('Publish').length).toBe(1);
    });

    it('should call requestPublish when clicking Publish button', async () => {
      const user = userEvent.setup();
      renderWithRouter();

      const publishButtons = screen.getAllByText('Publish');
      await user.click(publishButtons[0]);

      expect(mockRequestPublish).toHaveBeenCalledWith([{ type: 'collection', id: 1 }]);
    });

    it('should call requestUnpublish when clicking PublicBadge', async () => {
      const publicCollections: Collection[] = [
        { ...mockCollections[0], effectiveIsPublic: true },
      ];
      (useData as ReturnType<typeof vi.fn>).mockReturnValue({
        ...mockDataContext,
        collections: publicCollections,
      });

      const user = userEvent.setup();
      renderWithRouter();

      await user.click(screen.getByText('Public'));

      expect(mockRequestUnpublish).toHaveBeenCalledWith([{ type: 'collection', id: 1 }]);
    });
  });

  describe('snapshots', () => {
    it('should match snapshot with collections', () => {
      const { container } = renderWithRouter();
      expect(container).toMatchSnapshot();
    });
  });
});
