import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import MatchesSummary from '../src/components/matching/MatchesSummary';
import { matchesApi, type MatchCountResponse, type MatchListResponse, MatchStatus } from '../src/api';

vi.mock('../src/api', () => ({
  matchesApi: {
    getCount: vi.fn(),
    getAll: vi.fn(),
  },
  MatchStatus: {
    New: 'New',
    Saved: 'Saved',
    Dismissed: 'Dismissed',
  },
}));

describe('MatchesSummary', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('should render nothing when no matches or messages', async () => {
    (matchesApi.getCount as ReturnType<typeof vi.fn>).mockResolvedValue({
      newMatchCount: 0,
      unreadMessageCount: 0,
    });
    (matchesApi.getAll as ReturnType<typeof vi.fn>).mockResolvedValue({
      matches: [],
      totalCount: 0,
    });

    const { container } = render(<MemoryRouter><MatchesSummary /></MemoryRouter>);

    await waitFor(() => {
      // Component should render nothing
      expect(container.querySelector('.collection-dashboard__panel')).not.toBeInTheDocument();
    });
  });

  it('should show new match count badge', async () => {
    (matchesApi.getCount as ReturnType<typeof vi.fn>).mockResolvedValue({
      newMatchCount: 3,
      unreadMessageCount: 0,
    } as MatchCountResponse);
    (matchesApi.getAll as ReturnType<typeof vi.fn>).mockResolvedValue({
      matches: [{
        id: 1,
        wantItem: { itemId: 1, name: 'Want', summary: '', primaryImageUrl: null, workspaceName: 'A', workspaceId: 1 },
        tradeItem: { itemId: 2, name: 'Trade', summary: '', primaryImageUrl: null, workspaceName: 'B', workspaceId: 2 },
        confidenceScore: 0.8,
        matchReason: 'Good match',
        myStatus: MatchStatus.New,
        createdAt: new Date().toISOString(),
        hasUnreadMessages: false,
      }],
      totalCount: 1,
    } as MatchListResponse);

    render(<MemoryRouter><MatchesSummary /></MemoryRouter>);

    await waitFor(() => {
      expect(screen.getByText('3 new matches')).toBeInTheDocument();
    });
  });

  it('should show unread message count badge', async () => {
    (matchesApi.getCount as ReturnType<typeof vi.fn>).mockResolvedValue({
      newMatchCount: 0,
      unreadMessageCount: 5,
    } as MatchCountResponse);
    (matchesApi.getAll as ReturnType<typeof vi.fn>).mockResolvedValue({
      matches: [{
        id: 1,
        wantItem: { itemId: 1, name: 'Want', summary: '', primaryImageUrl: null, workspaceName: 'A', workspaceId: 1 },
        tradeItem: { itemId: 2, name: 'Trade', summary: '', primaryImageUrl: null, workspaceName: 'B', workspaceId: 2 },
        confidenceScore: 0.8,
        matchReason: 'Good match',
        myStatus: MatchStatus.New,
        createdAt: new Date().toISOString(),
        hasUnreadMessages: false,
      }],
      totalCount: 1,
    } as MatchListResponse);

    render(<MemoryRouter><MatchesSummary /></MemoryRouter>);

    await waitFor(() => {
      expect(screen.getByText('5 unread messages')).toBeInTheDocument();
    });
  });

  it('should show singular forms for count of 1', async () => {
    (matchesApi.getCount as ReturnType<typeof vi.fn>).mockResolvedValue({
      newMatchCount: 1,
      unreadMessageCount: 1,
    } as MatchCountResponse);
    (matchesApi.getAll as ReturnType<typeof vi.fn>).mockResolvedValue({
      matches: [{
        id: 1,
        wantItem: { itemId: 1, name: 'Want', summary: '', primaryImageUrl: null, workspaceName: 'A', workspaceId: 1 },
        tradeItem: { itemId: 2, name: 'Trade', summary: '', primaryImageUrl: null, workspaceName: 'B', workspaceId: 2 },
        confidenceScore: 0.8,
        matchReason: 'Good match',
        myStatus: MatchStatus.New,
        createdAt: new Date().toISOString(),
        hasUnreadMessages: false,
      }],
      totalCount: 1,
    } as MatchListResponse);

    render(<MemoryRouter><MatchesSummary /></MemoryRouter>);

    await waitFor(() => {
      expect(screen.getByText('1 new match')).toBeInTheDocument();
      expect(screen.getByText('1 unread message')).toBeInTheDocument();
    });
  });

  it('should show View All Matches button', async () => {
    (matchesApi.getCount as ReturnType<typeof vi.fn>).mockResolvedValue({
      newMatchCount: 2,
      unreadMessageCount: 0,
    } as MatchCountResponse);
    (matchesApi.getAll as ReturnType<typeof vi.fn>).mockResolvedValue({
      matches: [{
        id: 1,
        wantItem: { itemId: 1, name: 'Want', summary: '', primaryImageUrl: null, workspaceName: 'A', workspaceId: 1 },
        tradeItem: { itemId: 2, name: 'Trade', summary: '', primaryImageUrl: null, workspaceName: 'B', workspaceId: 2 },
        confidenceScore: 0.8,
        matchReason: 'Good match',
        myStatus: MatchStatus.New,
        createdAt: new Date().toISOString(),
        hasUnreadMessages: false,
      }],
      totalCount: 1,
    } as MatchListResponse);

    render(<MemoryRouter><MatchesSummary /></MemoryRouter>);

    await waitFor(() => {
      expect(screen.getByText('View All Matches')).toBeInTheDocument();
    });
  });

  it('should show recent match items', async () => {
    (matchesApi.getCount as ReturnType<typeof vi.fn>).mockResolvedValue({
      newMatchCount: 1,
      unreadMessageCount: 0,
    } as MatchCountResponse);
    (matchesApi.getAll as ReturnType<typeof vi.fn>).mockResolvedValue({
      matches: [{
        id: 1,
        wantItem: { itemId: 1, name: 'Pokemon Red', summary: '', primaryImageUrl: null, workspaceName: 'A', workspaceId: 1 },
        tradeItem: { itemId: 2, name: 'Pokemon Red CIB', summary: '', primaryImageUrl: null, workspaceName: 'B', workspaceId: 2 },
        confidenceScore: 0.9,
        matchReason: 'Same game',
        myStatus: MatchStatus.New,
        createdAt: new Date().toISOString(),
        hasUnreadMessages: false,
      }],
      totalCount: 1,
    } as MatchListResponse);

    render(<MemoryRouter><MatchesSummary /></MemoryRouter>);

    await waitFor(() => {
      expect(screen.getByText(/Pokemon Red/)).toBeInTheDocument();
      expect(screen.getByText('90%')).toBeInTheDocument();
    });
  });

  it('should show panel title', async () => {
    (matchesApi.getCount as ReturnType<typeof vi.fn>).mockResolvedValue({
      newMatchCount: 1,
      unreadMessageCount: 0,
    } as MatchCountResponse);
    (matchesApi.getAll as ReturnType<typeof vi.fn>).mockResolvedValue({
      matches: [{
        id: 1,
        wantItem: { itemId: 1, name: 'Want', summary: '', primaryImageUrl: null, workspaceName: 'A', workspaceId: 1 },
        tradeItem: { itemId: 2, name: 'Trade', summary: '', primaryImageUrl: null, workspaceName: 'B', workspaceId: 2 },
        confidenceScore: 0.8,
        matchReason: 'Good match',
        myStatus: MatchStatus.New,
        createdAt: new Date().toISOString(),
        hasUnreadMessages: false,
      }],
      totalCount: 1,
    } as MatchListResponse);

    render(<MemoryRouter><MatchesSummary /></MemoryRouter>);

    await waitFor(() => {
      expect(screen.getByText('Item Matches')).toBeInTheDocument();
    });
  });
});
