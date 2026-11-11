import type { RequestOptions } from '../../api/client';
import type { CreateSupportReply, CreateSupportRequest, SupportReply, SupportRequest, SupportRequestListResponse, UnreadCount } from '../../api/support';

export interface SupportSubmissionPort {
  create: (request: CreateSupportRequest) => Promise<SupportRequest>;
}
export interface SupportNotificationPort {
  read: (options: RequestOptions) => Promise<UnreadCount>;
}
export interface SupportDismissalPort {
  isDismissed: (userId: number) => boolean;
  dismiss: (userId: number) => void;
}

export interface SupportConversationPort {
  reply: (id: number, data: CreateSupportReply) => Promise<SupportReply>;
  remove: (id: number) => Promise<void>;
  markRead?: (id: number) => Promise<void>;
  changeStatus?: (id: number, status: string) => Promise<SupportRequest>;
}
export interface SupportSessionPort extends SupportConversationPort {
  read: (id: number, options?: RequestOptions) => Promise<SupportRequest>;
}
export interface SupportQueueQuery { status: string; includeDeleted: boolean; page: number }
export interface SupportQueuePort {
  list: (query: { status?: string; includeDeleted: boolean; limit: number; offset: number }, options?: RequestOptions) => Promise<SupportRequestListResponse>;
  remove: (id: number) => Promise<void>;
}
