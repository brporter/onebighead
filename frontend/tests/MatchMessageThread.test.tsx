import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import MatchMessageThread from '../src/components/matching/MatchMessageThread';
import { matchesApi, type MatchMessageResponse } from '../src/api';

vi.mock('../src/api', () => ({
  matchesApi: {
    getMessages: vi.fn(),
    sendMessage: vi.fn(),
    markMessagesRead: vi.fn(),
  },
}));

// Mock scrollIntoView which is not available in jsdom
Element.prototype.scrollIntoView = vi.fn();

const mockMessages: MatchMessageResponse[] = [
  {
    id: 1,
    message: 'Hello, interested in trading?',
    isMine: true,
    isRead: true,
    createdAt: new Date(Date.now() - 60000).toISOString(),
  },
  {
    id: 2,
    message: 'Sure, what do you have?',
    isMine: false,
    isRead: false,
    createdAt: new Date().toISOString(),
  },
];

describe('MatchMessageThread', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('should show loading state', () => {
    (matchesApi.getMessages as ReturnType<typeof vi.fn>).mockReturnValue(new Promise(() => {}));

    render(<MatchMessageThread matchId={1} />);

    expect(screen.getByText('Loading messages...')).toBeInTheDocument();
  });

  it('should show empty state when no messages', async () => {
    (matchesApi.getMessages as ReturnType<typeof vi.fn>).mockResolvedValue([]);
    (matchesApi.markMessagesRead as ReturnType<typeof vi.fn>).mockResolvedValue(undefined);

    render(<MatchMessageThread matchId={1} />);

    await waitFor(() => {
      expect(screen.getByText('No messages yet. Start the conversation!')).toBeInTheDocument();
    });
  });

  it('should display messages', async () => {
    (matchesApi.getMessages as ReturnType<typeof vi.fn>).mockResolvedValue(mockMessages);
    (matchesApi.markMessagesRead as ReturnType<typeof vi.fn>).mockResolvedValue(undefined);

    render(<MatchMessageThread matchId={1} />);

    await waitFor(() => {
      expect(screen.getByText('Hello, interested in trading?')).toBeInTheDocument();
      expect(screen.getByText('Sure, what do you have?')).toBeInTheDocument();
    });
  });

  it('should style own messages differently', async () => {
    (matchesApi.getMessages as ReturnType<typeof vi.fn>).mockResolvedValue(mockMessages);
    (matchesApi.markMessagesRead as ReturnType<typeof vi.fn>).mockResolvedValue(undefined);

    render(<MatchMessageThread matchId={1} />);

    await waitFor(() => {
      const myMessage = screen.getByText('Hello, interested in trading?').closest('.match-message-thread__message');
      expect(myMessage).toHaveClass('match-message-thread__message--mine');

      const theirMessage = screen.getByText('Sure, what do you have?').closest('.match-message-thread__message');
      expect(theirMessage).toHaveClass('match-message-thread__message--theirs');
    });
  });

  it('should mark messages as read on load', async () => {
    (matchesApi.getMessages as ReturnType<typeof vi.fn>).mockResolvedValue(mockMessages);
    (matchesApi.markMessagesRead as ReturnType<typeof vi.fn>).mockResolvedValue(undefined);

    render(<MatchMessageThread matchId={1} />);

    await waitFor(() => {
      expect(matchesApi.markMessagesRead).toHaveBeenCalledWith(1);
    });
  });

  it('should send a message', async () => {
    (matchesApi.getMessages as ReturnType<typeof vi.fn>).mockResolvedValue([]);
    (matchesApi.markMessagesRead as ReturnType<typeof vi.fn>).mockResolvedValue(undefined);
    (matchesApi.sendMessage as ReturnType<typeof vi.fn>).mockResolvedValue({
      id: 3,
      message: 'New message',
      isMine: true,
      isRead: false,
      createdAt: new Date().toISOString(),
    });

    const user = userEvent.setup();
    render(<MatchMessageThread matchId={1} />);

    await waitFor(() => {
      expect(screen.getByPlaceholderText('Type a message...')).toBeInTheDocument();
    });

    await user.type(screen.getByPlaceholderText('Type a message...'), 'New message');
    await user.click(screen.getByText('Send'));

    await waitFor(() => {
      expect(matchesApi.sendMessage).toHaveBeenCalledWith(1, { message: 'New message' });
    });
  });

  it('should disable send button when input is empty', async () => {
    (matchesApi.getMessages as ReturnType<typeof vi.fn>).mockResolvedValue([]);
    (matchesApi.markMessagesRead as ReturnType<typeof vi.fn>).mockResolvedValue(undefined);

    render(<MatchMessageThread matchId={1} />);

    await waitFor(() => {
      expect(screen.getByText('Send')).toBeDisabled();
    });
  });

  it('should clear input after sending', async () => {
    (matchesApi.getMessages as ReturnType<typeof vi.fn>).mockResolvedValue([]);
    (matchesApi.markMessagesRead as ReturnType<typeof vi.fn>).mockResolvedValue(undefined);
    (matchesApi.sendMessage as ReturnType<typeof vi.fn>).mockResolvedValue({
      id: 3,
      message: 'Test',
      isMine: true,
      isRead: false,
      createdAt: new Date().toISOString(),
    });

    const user = userEvent.setup();
    render(<MatchMessageThread matchId={1} />);

    await waitFor(() => {
      expect(screen.getByPlaceholderText('Type a message...')).toBeInTheDocument();
    });

    const input = screen.getByPlaceholderText('Type a message...');
    await user.type(input, 'Test');
    await user.click(screen.getByText('Send'));

    await waitFor(() => {
      expect(input).toHaveValue('');
    });
  });

  it('should add sent message to the list', async () => {
    (matchesApi.getMessages as ReturnType<typeof vi.fn>).mockResolvedValue([]);
    (matchesApi.markMessagesRead as ReturnType<typeof vi.fn>).mockResolvedValue(undefined);
    (matchesApi.sendMessage as ReturnType<typeof vi.fn>).mockResolvedValue({
      id: 3,
      message: 'My new message',
      isMine: true,
      isRead: false,
      createdAt: new Date().toISOString(),
    });

    const user = userEvent.setup();
    render(<MatchMessageThread matchId={1} />);

    await waitFor(() => {
      expect(screen.getByPlaceholderText('Type a message...')).toBeInTheDocument();
    });

    await user.type(screen.getByPlaceholderText('Type a message...'), 'My new message');
    await user.click(screen.getByText('Send'));

    await waitFor(() => {
      expect(screen.getByText('My new message')).toBeInTheDocument();
    });
  });
});
