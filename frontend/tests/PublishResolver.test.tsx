import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { PublishResolver } from '../src/components/common/PublishResolver';
import type { PublishIntent } from '../src/utils/types';

const mockPreflight = vi.fn();
const mockExecute = vi.fn();
const mockShowToast = vi.fn();
const mockClearIntent = vi.fn();
const mockOnComplete = vi.fn();
const mockRefetchUser = vi.fn();

vi.mock('../src/api/publishManager', () => ({
  publishManagerApi: {
    preflight: (...args: unknown[]) => mockPreflight(...args),
    execute: (...args: unknown[]) => mockExecute(...args),
  },
}));

vi.mock('../src/contexts/useToast', () => ({
  useToast: () => ({ showToast: mockShowToast }),
}));

vi.mock('../src/contexts/useUser', () => ({
  useUser: () => ({
    user: { activeWorkspace: { workspaceId: 1, workspaceName: 'Test WS' } },
    refetch: mockRefetchUser,
  }),
}));

describe('PublishResolver', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('does not open dialog when no pending intent', () => {
    render(
      <PublishResolver intent={null} onClearIntent={mockClearIntent} onComplete={mockOnComplete} />
    );
    const dialog = document.querySelector('dialog');
    expect(dialog).toBeInTheDocument();
    expect(dialog).not.toHaveAttribute('open');
  });

  it('opens dialog via showModal when preflight returns requirements', async () => {
    mockPreflight.mockResolvedValue({
      ready: false,
      requirements: [{ kind: 'collection-not-public', collectionId: 5, collectionName: 'Vintage Cars' }],
    });

    const intent: PublishIntent = { action: 'publish', entities: [{ type: 'item', id: 1 }] };
    render(<PublishResolver intent={intent} onClearIntent={mockClearIntent} onComplete={mockOnComplete} />);

    await waitFor(() => {
      const dialog = document.querySelector('dialog');
      expect(dialog).toHaveAttribute('open');
    });
  });

  it('closes dialog and clears intent on backdrop click', async () => {
    mockPreflight.mockResolvedValue({
      ready: false,
      requirements: [{ kind: 'collection-not-public', collectionId: 5, collectionName: 'Vintage Cars' }],
    });

    const user = userEvent.setup();
    const intent: PublishIntent = { action: 'publish', entities: [{ type: 'item', id: 1 }] };
    render(<PublishResolver intent={intent} onClearIntent={mockClearIntent} onComplete={mockOnComplete} />);

    const dialog = await waitFor(() => {
      const d = document.querySelector('dialog');
      expect(d).toHaveAttribute('open');
      return d!;
    });

    await user.click(dialog);

    expect(mockClearIntent).toHaveBeenCalled();
  });

  it('auto-executes when preflight returns ready', async () => {
    mockPreflight.mockResolvedValue({ ready: true, requirements: [] });
    mockExecute.mockResolvedValue({ success: true, changed: [{ type: 'item', id: 1, name: 'Test' }], promoted: [] });

    const intent: PublishIntent = { action: 'publish', entities: [{ type: 'item', id: 1 }] };
    render(<PublishResolver intent={intent} onClearIntent={mockClearIntent} onComplete={mockOnComplete} />);

    await waitFor(() => {
      expect(mockExecute).toHaveBeenCalled();
    });
    await waitFor(() => {
      expect(mockShowToast).toHaveBeenCalled();
    });
    expect(mockClearIntent).toHaveBeenCalled();
    expect(mockOnComplete).toHaveBeenCalled();
  });

  it('renders slug input for workspace-slug-required requirement', async () => {
    mockPreflight.mockResolvedValue({
      ready: false,
      requirements: [{ kind: 'workspace-slug-required', workspaceId: 1, workspaceName: 'Test WS' }],
    });

    const intent: PublishIntent = { action: 'publish', entities: [{ type: 'item', id: 1 }] };
    render(<PublishResolver intent={intent} onClearIntent={mockClearIntent} onComplete={mockOnComplete} />);

    await waitFor(() => {
      expect(screen.getByLabelText('Gallery URL')).toBeInTheDocument();
    });
  });

  it('renders acknowledgment for collection-not-public', async () => {
    mockPreflight.mockResolvedValue({
      ready: false,
      requirements: [{ kind: 'collection-not-public', collectionId: 5, collectionName: 'Vintage Cars' }],
    });

    const intent: PublishIntent = { action: 'publish', entities: [{ type: 'item', id: 1 }] };
    render(<PublishResolver intent={intent} onClearIntent={mockClearIntent} onComplete={mockOnComplete} />);

    await waitFor(() => {
      expect(screen.getByText(/Vintage Cars/)).toBeInTheDocument();
    });
  });

  it('renders impact warning for unpublish-will-hide-children', async () => {
    mockPreflight.mockResolvedValue({
      ready: false,
      requirements: [{
        kind: 'unpublish-will-hide-children',
        entityType: 'category',
        entityId: 1,
        entityName: 'Watches',
        affectedPublicItems: 12,
        affectedPublicCategories: 2,
      }],
    });

    const intent: PublishIntent = { action: 'unpublish', entities: [{ type: 'category', id: 1 }] };
    render(<PublishResolver intent={intent} onClearIntent={mockClearIntent} onComplete={mockOnComplete} />);

    await waitFor(() => {
      expect(screen.getByText(/12 items/)).toBeInTheDocument();
    });
  });

  it('submit is disabled until all requirements are resolved', async () => {
    mockPreflight.mockResolvedValue({
      ready: false,
      requirements: [
        { kind: 'collection-not-public', collectionId: 5, collectionName: 'Vintage Cars' },
      ],
    });

    const user = userEvent.setup();
    const intent: PublishIntent = { action: 'publish', entities: [{ type: 'item', id: 1 }] };
    render(<PublishResolver intent={intent} onClearIntent={mockClearIntent} onComplete={mockOnComplete} />);

    await waitFor(() => {
      expect(screen.getByRole('button', { name: /publish/i })).toBeDisabled();
    });

    const checkbox = await screen.findByRole('checkbox');
    await user.click(checkbox);

    expect(screen.getByRole('button', { name: /publish/i })).toBeEnabled();
  });

  it('calls execute with correct resolutions and shows toast', async () => {
    mockPreflight.mockResolvedValue({
      ready: false,
      requirements: [
        { kind: 'collection-not-public', collectionId: 5, collectionName: 'Vintage Cars' },
      ],
    });
    mockExecute.mockResolvedValue({
      success: true,
      changed: [{ type: 'item', id: 1, name: 'Mustang' }],
      promoted: [{ type: 'collection', id: 5, name: 'Vintage Cars' }],
    });

    const user = userEvent.setup();
    const intent: PublishIntent = { action: 'publish', entities: [{ type: 'item', id: 1 }] };
    render(<PublishResolver intent={intent} onClearIntent={mockClearIntent} onComplete={mockOnComplete} />);

    const checkbox = await screen.findByRole('checkbox');
    await user.click(checkbox);
    await user.click(screen.getByRole('button', { name: /publish/i }));

    await waitFor(() => {
      expect(mockExecute).toHaveBeenCalledWith(1, expect.objectContaining({
        action: 'publish',
        resolutions: expect.arrayContaining([
          expect.objectContaining({ kind: 'collection-not-public', collectionId: 5 }),
        ]),
      }));
    });

    await waitFor(() => {
      expect(mockShowToast).toHaveBeenCalled();
    });
  });

  it('handles execute failure by re-rendering requirements', async () => {
    mockPreflight.mockResolvedValue({
      ready: false,
      requirements: [{ kind: 'workspace-slug-required', workspaceId: 1, workspaceName: 'Test WS' }],
    });
    mockExecute.mockResolvedValue({
      success: false,
      error: "Slug 'taken' is already taken",
      requirements: [{ kind: 'workspace-slug-required', workspaceId: 1, workspaceName: 'Test WS' }],
    });

    const user = userEvent.setup();
    const intent: PublishIntent = { action: 'publish', entities: [{ type: 'item', id: 1 }] };
    render(<PublishResolver intent={intent} onClearIntent={mockClearIntent} onComplete={mockOnComplete} />);

    const input = await screen.findByLabelText('Gallery URL');
    await user.type(input, 'taken');
    await user.click(screen.getByRole('button', { name: /publish/i }));

    await waitFor(() => {
      expect(screen.getByText(/already taken/)).toBeInTheDocument();
    });
  });

  it('cancel clears intent', async () => {
    mockPreflight.mockResolvedValue({
      ready: false,
      requirements: [{ kind: 'collection-not-public', collectionId: 5, collectionName: 'Vintage Cars' }],
    });

    const user = userEvent.setup();
    const intent: PublishIntent = { action: 'publish', entities: [{ type: 'item', id: 1 }] };
    render(<PublishResolver intent={intent} onClearIntent={mockClearIntent} onComplete={mockOnComplete} />);

    const cancelBtn = await screen.findByRole('button', { name: /cancel/i });
    await user.click(cancelBtn);

    expect(mockClearIntent).toHaveBeenCalled();
  });

  it('refetches user when workspace slug is set', async () => {
    mockPreflight.mockResolvedValue({ ready: true, requirements: [] });
    mockExecute.mockResolvedValue({
      success: true,
      changed: [{ type: 'item', id: 1, name: 'Test' }],
      promoted: [],
      workspaceSlugSet: 'my-gallery',
    });

    const intent: PublishIntent = { action: 'publish', entities: [{ type: 'item', id: 1 }] };
    render(<PublishResolver intent={intent} onClearIntent={mockClearIntent} onComplete={mockOnComplete} />);

    await waitFor(() => {
      expect(mockRefetchUser).toHaveBeenCalled();
    });
  });
});
