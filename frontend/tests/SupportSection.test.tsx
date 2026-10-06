import { describe, expect, it, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { SupportSection } from '../src/components/support/SupportSection';
import { getMySupportRequests, getSupportRequest } from '../src/api';
vi.mock('../src/api', () => ({ getMySupportRequests: vi.fn(), getSupportRequest: vi.fn(), addSupportReply: vi.fn(), deleteSupportRequest: vi.fn(), markSupportRequestAsRead: vi.fn() }));

describe('SupportSection', () => {
  it('opens support details using a native keyboard activated button', async () => {
    const request = { supportRequestId: 1, subject: 'Help', description: 'Details', status: 'Open', replyCount: 0, unreadCount: 0, createdAt: '2026-10-05T12:00:00Z', replies: [] } as unknown as Awaited<ReturnType<typeof getSupportRequest>>;
    vi.mocked(getMySupportRequests).mockResolvedValue([request]);
    vi.mocked(getSupportRequest).mockResolvedValue(request);
    render(<SupportSection />);
    const button = await screen.findByRole('button', { name: /Support request: Help/ });
    expect(button.tagName).toBe('BUTTON');
    button.focus();
    await userEvent.keyboard('{Enter}');
    expect(getSupportRequest).toHaveBeenCalledExactlyOnceWith(1);
    expect(await screen.findByText('Details')).toBeInTheDocument();
  });
});
