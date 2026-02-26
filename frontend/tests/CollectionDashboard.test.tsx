import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import userEvent from '@testing-library/user-event';
import CollectionDashboard from '../src/components/collection/CollectionDashboard';
import { collectionsApi } from '../src/api/collections';
import type { CollectionStatisticsResponse } from '../src/api/collections';

vi.mock('../src/api/collections', () => ({
  collectionsApi: {
    getStatistics: vi.fn(),
  },
}));

vi.mock('../src/api', () => ({
  matchesApi: {
    getCount: vi.fn().mockResolvedValue({ newMatchCount: 0, unreadMessageCount: 0 }),
    getAll: vi.fn().mockResolvedValue({ matches: [], totalCount: 0 }),
  },
}));

describe('CollectionDashboard', () => {
  const mockOnSelectItem = vi.fn();

  const mockStats: CollectionStatisticsResponse = {
    itemCount: 42,
    imageCount: 15,
    totalImageSizeBytes: 8388608,
    topViewedItems: [
      { itemId: 1, itemName: 'Popular Item', viewCount: 25 },
      { itemId: 2, itemName: 'Second Popular', viewCount: 10 },
    ],
    recentlyAddedItems: [
      { itemId: 3, itemName: 'New Item', createdAt: new Date().toISOString() },
      { itemId: 4, itemName: 'Older Item', createdAt: new Date(Date.now() - 86400000 * 5).toISOString() },
    ],
  };

  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('should show loading state while fetching', () => {
    (collectionsApi.getStatistics as ReturnType<typeof vi.fn>).mockReturnValue(new Promise(() => {}));

    render(<MemoryRouter><CollectionDashboard collectionId={1} onSelectItem={mockOnSelectItem} /></MemoryRouter>);

    expect(screen.getByText('Loading dashboard...')).toBeInTheDocument();
  });

  it('should show stats cards when data is loaded', async () => {
    (collectionsApi.getStatistics as ReturnType<typeof vi.fn>).mockResolvedValue(mockStats);

    render(<MemoryRouter><CollectionDashboard collectionId={1} onSelectItem={mockOnSelectItem} /></MemoryRouter>);

    await waitFor(() => {
      expect(screen.getByText('42')).toBeInTheDocument();
    });

    expect(screen.getByText('Items')).toBeInTheDocument();
    expect(screen.getByText('15')).toBeInTheDocument();
    expect(screen.getByText('Images')).toBeInTheDocument();
    expect(screen.getByText('8.0 MB')).toBeInTheDocument();
    expect(screen.getByText('Total Image Size')).toBeInTheDocument();
  });

  it('should show recently added items', async () => {
    (collectionsApi.getStatistics as ReturnType<typeof vi.fn>).mockResolvedValue(mockStats);

    render(<MemoryRouter><CollectionDashboard collectionId={1} onSelectItem={mockOnSelectItem} /></MemoryRouter>);

    await waitFor(() => {
      expect(screen.getByText('Recently Added')).toBeInTheDocument();
    });

    expect(screen.getByText('New Item')).toBeInTheDocument();
    expect(screen.getByText('Older Item')).toBeInTheDocument();
  });

  it('should show most viewed items', async () => {
    (collectionsApi.getStatistics as ReturnType<typeof vi.fn>).mockResolvedValue(mockStats);

    render(<MemoryRouter><CollectionDashboard collectionId={1} onSelectItem={mockOnSelectItem} /></MemoryRouter>);

    await waitFor(() => {
      expect(screen.getByText('Most Viewed')).toBeInTheDocument();
    });

    expect(screen.getByText('Popular Item')).toBeInTheDocument();
    expect(screen.getByText('25 views')).toBeInTheDocument();
    expect(screen.getByText('Second Popular')).toBeInTheDocument();
    expect(screen.getByText('10 views')).toBeInTheDocument();
  });

  it('should call onSelectItem when clicking a recently added item', async () => {
    const user = userEvent.setup();
    (collectionsApi.getStatistics as ReturnType<typeof vi.fn>).mockResolvedValue(mockStats);

    render(<MemoryRouter><CollectionDashboard collectionId={1} onSelectItem={mockOnSelectItem} /></MemoryRouter>);

    await waitFor(() => {
      expect(screen.getByText('New Item')).toBeInTheDocument();
    });

    await user.click(screen.getByText('New Item'));

    expect(mockOnSelectItem).toHaveBeenCalledWith(3);
  });

  it('should call onSelectItem when clicking a most viewed item', async () => {
    const user = userEvent.setup();
    (collectionsApi.getStatistics as ReturnType<typeof vi.fn>).mockResolvedValue(mockStats);

    render(<MemoryRouter><CollectionDashboard collectionId={1} onSelectItem={mockOnSelectItem} /></MemoryRouter>);

    await waitFor(() => {
      expect(screen.getByText('Popular Item')).toBeInTheDocument();
    });

    await user.click(screen.getByText('Popular Item'));

    expect(mockOnSelectItem).toHaveBeenCalledWith(1);
  });

  it('should call onSelectItem when pressing Enter on an item', async () => {
    const user = userEvent.setup();
    (collectionsApi.getStatistics as ReturnType<typeof vi.fn>).mockResolvedValue(mockStats);

    render(<MemoryRouter><CollectionDashboard collectionId={1} onSelectItem={mockOnSelectItem} /></MemoryRouter>);

    await waitFor(() => {
      expect(screen.getByText('Popular Item')).toBeInTheDocument();
    });

    const item = screen.getByText('Popular Item').closest('.collection-dashboard__item')!;
    item.focus();
    await user.keyboard('{Enter}');

    expect(mockOnSelectItem).toHaveBeenCalledWith(1);
  });

  it('should show empty state when collection has no items', async () => {
    const emptyStats: CollectionStatisticsResponse = {
      itemCount: 0,
      imageCount: 0,
      totalImageSizeBytes: 0,
      topViewedItems: [],
      recentlyAddedItems: [],
    };
    (collectionsApi.getStatistics as ReturnType<typeof vi.fn>).mockResolvedValue(emptyStats);

    render(<MemoryRouter><CollectionDashboard collectionId={1} onSelectItem={mockOnSelectItem} /></MemoryRouter>);

    await waitFor(() => {
      expect(screen.getByText('No items yet. Select a category and start adding items.')).toBeInTheDocument();
    });
  });

  it('should show error state when API fails', async () => {
    (collectionsApi.getStatistics as ReturnType<typeof vi.fn>).mockRejectedValue(new Error('Network error'));

    render(<MemoryRouter><CollectionDashboard collectionId={1} onSelectItem={mockOnSelectItem} /></MemoryRouter>);

    await waitFor(() => {
      expect(screen.getByText('Failed to load collection statistics.')).toBeInTheDocument();
    });
  });

  it('should fetch statistics for the given collectionId', async () => {
    (collectionsApi.getStatistics as ReturnType<typeof vi.fn>).mockResolvedValue(mockStats);

    render(<MemoryRouter><CollectionDashboard collectionId={42} onSelectItem={mockOnSelectItem} /></MemoryRouter>);

    expect(collectionsApi.getStatistics).toHaveBeenCalledWith(42);
  });

  it('should not show panels when lists are empty but itemCount > 0', async () => {
    const statsNoLists: CollectionStatisticsResponse = {
      itemCount: 5,
      imageCount: 0,
      totalImageSizeBytes: 0,
      topViewedItems: [],
      recentlyAddedItems: [],
    };
    (collectionsApi.getStatistics as ReturnType<typeof vi.fn>).mockResolvedValue(statsNoLists);

    render(<MemoryRouter><CollectionDashboard collectionId={1} onSelectItem={mockOnSelectItem} /></MemoryRouter>);

    await waitFor(() => {
      expect(screen.getByText('5')).toBeInTheDocument();
    });

    expect(screen.queryByText('Recently Added')).not.toBeInTheDocument();
    expect(screen.queryByText('Most Viewed')).not.toBeInTheDocument();
  });

  it('should format bytes correctly for zero bytes', async () => {
    const statsZeroBytes: CollectionStatisticsResponse = {
      itemCount: 1,
      imageCount: 0,
      totalImageSizeBytes: 0,
      topViewedItems: [],
      recentlyAddedItems: [],
    };
    (collectionsApi.getStatistics as ReturnType<typeof vi.fn>).mockResolvedValue(statsZeroBytes);

    render(<MemoryRouter><CollectionDashboard collectionId={1} onSelectItem={mockOnSelectItem} /></MemoryRouter>);

    await waitFor(() => {
      expect(screen.getByText('0 B')).toBeInTheDocument();
    });
  });

  describe('snapshots', () => {
    it('should match snapshot with stats loaded', async () => {
      (collectionsApi.getStatistics as ReturnType<typeof vi.fn>).mockResolvedValue(mockStats);

      const { container } = render(<MemoryRouter><CollectionDashboard collectionId={1} onSelectItem={mockOnSelectItem} /></MemoryRouter>);

      await waitFor(() => {
        expect(screen.getByText('42')).toBeInTheDocument();
      });

      expect(container).toMatchSnapshot();
    });

    it('should match snapshot for empty state', async () => {
      const emptyStats: CollectionStatisticsResponse = {
        itemCount: 0,
        imageCount: 0,
        totalImageSizeBytes: 0,
        topViewedItems: [],
        recentlyAddedItems: [],
      };
      (collectionsApi.getStatistics as ReturnType<typeof vi.fn>).mockResolvedValue(emptyStats);

      const { container } = render(<MemoryRouter><CollectionDashboard collectionId={1} onSelectItem={mockOnSelectItem} /></MemoryRouter>);

      await waitFor(() => {
        expect(screen.getByText('No items yet. Select a category and start adding items.')).toBeInTheDocument();
      });

      expect(container).toMatchSnapshot();
    });
  });
});
