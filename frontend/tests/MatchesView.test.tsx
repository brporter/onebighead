import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import userEvent from '@testing-library/user-event';
import MatchesView from '../src/views/MatchesView';
import { matchesApi, MatchStatus, type MatchListResponse, type MatchResponse } from '../src/api';

vi.mock('../src/api', () => ({
  matchesApi: {
    getAll: vi.fn(),
    getById: vi.fn(),
    updateStatus: vi.fn(),
    getMessages: vi.fn(),
    sendMessage: vi.fn(),
    markMessagesRead: vi.fn(),
    getCount: vi.fn(),
  },
  MatchStatus: {
    New: 'New',
    Saved: 'Saved',
    Dismissed: 'Dismissed',
  },
}));

const mockMatch: MatchResponse = {
  id: 1,
  wantItem: {
    itemId: 10,
    name: 'Pokemon Red',
    summary: 'Game Boy game',
    primaryImageUrl: null,
    workspaceName: 'Workspace A',
    workspaceId: 1,
  },
  tradeItem: {
    itemId: 20,
    name: 'Pokemon Red CIB',
    summary: 'Complete in box',
    primaryImageUrl: null,
    workspaceName: 'Workspace B',
    workspaceId: 2,
  },
  confidenceScore: 0.85,
  matchReason: 'Same game, different conditions',
  myStatus: MatchStatus.New,
  createdAt: new Date().toISOString(),
  hasUnreadMessages: false,
};

const mockListResponse: MatchListResponse = {
  matches: [mockMatch],
  totalCount: 1,
};

const emptyResponse: MatchListResponse = {
  matches: [],
  totalCount: 0,
};

// Mock dialog methods
HTMLDialogElement.prototype.showModal = vi.fn(function (this: HTMLDialogElement) {
  this.setAttribute('open', '');
});
HTMLDialogElement.prototype.close = vi.fn(function (this: HTMLDialogElement) {
  this.removeAttribute('open');
});

// Mock scrollIntoView which is not available in jsdom
Element.prototype.scrollIntoView = vi.fn();

describe('MatchesView', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('should show loading state', () => {
    (matchesApi.getAll as ReturnType<typeof vi.fn>).mockReturnValue(new Promise(() => {}));

    render(<MemoryRouter><MatchesView /></MemoryRouter>);

    expect(screen.getByText('Loading matches...')).toBeInTheDocument();
  });

  it('should show empty state when no matches', async () => {
    (matchesApi.getAll as ReturnType<typeof vi.fn>).mockResolvedValue(emptyResponse);

    render(<MemoryRouter><MatchesView /></MemoryRouter>);

    await waitFor(() => {
      expect(screen.getByText(/No matches found/)).toBeInTheDocument();
    });
  });

  it('should display match cards', async () => {
    (matchesApi.getAll as ReturnType<typeof vi.fn>).mockResolvedValue(mockListResponse);

    render(<MemoryRouter><MatchesView /></MemoryRouter>);

    await waitFor(() => {
      expect(screen.getByText('Pokemon Red')).toBeInTheDocument();
      expect(screen.getByText('Pokemon Red CIB')).toBeInTheDocument();
    });
  });

  it('should show confidence percentage', async () => {
    (matchesApi.getAll as ReturnType<typeof vi.fn>).mockResolvedValue(mockListResponse);

    render(<MemoryRouter><MatchesView /></MemoryRouter>);

    await waitFor(() => {
      expect(screen.getByText('85%')).toBeInTheDocument();
    });
  });

  it('should show match reason', async () => {
    (matchesApi.getAll as ReturnType<typeof vi.fn>).mockResolvedValue(mockListResponse);

    render(<MemoryRouter><MatchesView /></MemoryRouter>);

    await waitFor(() => {
      expect(screen.getByText('Same game, different conditions')).toBeInTheDocument();
    });
  });

  it('should show workspace names', async () => {
    (matchesApi.getAll as ReturnType<typeof vi.fn>).mockResolvedValue(mockListResponse);

    render(<MemoryRouter><MatchesView /></MemoryRouter>);

    await waitFor(() => {
      expect(screen.getByText('Workspace A')).toBeInTheDocument();
      expect(screen.getByText('Workspace B')).toBeInTheDocument();
    });
  });

  it('should show Save and Dismiss buttons for new matches', async () => {
    (matchesApi.getAll as ReturnType<typeof vi.fn>).mockResolvedValue(mockListResponse);

    render(<MemoryRouter><MatchesView /></MemoryRouter>);

    await waitFor(() => {
      expect(screen.getByText('Save')).toBeInTheDocument();
      expect(screen.getByText('Dismiss')).toBeInTheDocument();
    });
  });

  it('should call updateStatus when Save is clicked', async () => {
    (matchesApi.getAll as ReturnType<typeof vi.fn>).mockResolvedValue(mockListResponse);
    (matchesApi.updateStatus as ReturnType<typeof vi.fn>).mockResolvedValue(undefined);

    const user = userEvent.setup();
    render(<MemoryRouter><MatchesView /></MemoryRouter>);

    await waitFor(() => {
      expect(screen.getByText('Save')).toBeInTheDocument();
    });

    await user.click(screen.getByText('Save'));

    await waitFor(() => {
      expect(matchesApi.updateStatus).toHaveBeenCalledWith(1, { status: 'Saved' });
    });
  });

  it('should call updateStatus when Dismiss is clicked', async () => {
    (matchesApi.getAll as ReturnType<typeof vi.fn>).mockResolvedValue(mockListResponse);
    (matchesApi.updateStatus as ReturnType<typeof vi.fn>).mockResolvedValue(undefined);

    const user = userEvent.setup();
    render(<MemoryRouter><MatchesView /></MemoryRouter>);

    await waitFor(() => {
      expect(screen.getByText('Dismiss')).toBeInTheDocument();
    });

    await user.click(screen.getByText('Dismiss'));

    await waitFor(() => {
      expect(matchesApi.updateStatus).toHaveBeenCalledWith(1, { status: 'Dismissed' });
    });
  });

  it('should have filter tabs', async () => {
    (matchesApi.getAll as ReturnType<typeof vi.fn>).mockResolvedValue(emptyResponse);

    render(<MemoryRouter><MatchesView /></MemoryRouter>);

    expect(screen.getByText('New')).toBeInTheDocument();
    expect(screen.getByText('Saved')).toBeInTheDocument();
    expect(screen.getByText('All')).toBeInTheDocument();
  });

  it('should switch filter tabs', async () => {
    (matchesApi.getAll as ReturnType<typeof vi.fn>).mockResolvedValue(emptyResponse);

    const user = userEvent.setup();
    render(<MemoryRouter><MatchesView /></MemoryRouter>);

    await user.click(screen.getByText('Saved'));

    await waitFor(() => {
      expect(matchesApi.getAll).toHaveBeenCalledWith('Saved', 0, 50);
    });
  });

  it('should show unread messages indicator', async () => {
    const matchWithMessages = {
      ...mockMatch,
      hasUnreadMessages: true,
    };
    const response: MatchListResponse = {
      matches: [matchWithMessages],
      totalCount: 1,
    };
    (matchesApi.getAll as ReturnType<typeof vi.fn>).mockResolvedValue(response);

    render(<MemoryRouter><MatchesView /></MemoryRouter>);

    await waitFor(() => {
      expect(screen.getByText('New messages')).toBeInTheDocument();
    });
  });

  it('should open match detail modal on card click', async () => {
    (matchesApi.getAll as ReturnType<typeof vi.fn>).mockResolvedValue(mockListResponse);
    (matchesApi.getMessages as ReturnType<typeof vi.fn>).mockResolvedValue([]);
    (matchesApi.markMessagesRead as ReturnType<typeof vi.fn>).mockResolvedValue(undefined);

    const user = userEvent.setup();
    render(<MemoryRouter><MatchesView /></MemoryRouter>);

    await waitFor(() => {
      expect(screen.getByText('Pokemon Red')).toBeInTheDocument();
    });

    // Click the match card
    await user.click(screen.getByText('Pokemon Red'));

    await waitFor(() => {
      expect(screen.getByText('Match Details')).toBeInTheDocument();
    });
  });

  it('should not show Save button for already saved matches', async () => {
    const savedMatch = { ...mockMatch, myStatus: MatchStatus.Saved };
    const response: MatchListResponse = {
      matches: [savedMatch],
      totalCount: 1,
    };
    (matchesApi.getAll as ReturnType<typeof vi.fn>).mockResolvedValue(response);

    render(<MemoryRouter><MatchesView /></MemoryRouter>);

    await waitFor(() => {
      expect(screen.getByText('Pokemon Red')).toBeInTheDocument();
    });

    expect(screen.queryByText('Save')).not.toBeInTheDocument();
    expect(screen.getByText('Dismiss')).toBeInTheDocument();
  });
});
