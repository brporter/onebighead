import type { SupportReply, SupportRequest } from '../../src/api/support';

export function supportRequest(overrides: Partial<SupportRequest> = {}): SupportRequest {
  return { supportRequestId: 1, userId: 7, email: 'reader@example.com', subject: 'Import help', description: 'How can I import my collection?', status: 'Open', createdAt: '2026-11-01T12:00:00Z', updatedAt: '2026-11-01T12:00:00Z', isDeleted: false, replyCount: 0, unreadCount: 0, replies: [], ...overrides };
}
export function supportReply(overrides: Partial<SupportReply> = {}): SupportReply {
  return { supportReplyId: 1, supportRequestId: 1, userId: 7, isFromAdmin: false, message: 'Here is more information.', createdAt: '2026-11-02T12:00:00Z', isRead: true, ...overrides };
}
