import api from './client';

export interface SupportRequest {
  supportRequestId: number;
  userId: number | null;
  email: string;
  subject: string;
  description: string;
  status: string;
  createdAt: string;
  updatedAt: string;
  isDeleted: boolean;
  replyCount: number;
  unreadCount: number;
  replies: SupportReply[];
}

export interface SupportReply {
  supportReplyId: number;
  supportRequestId: number;
  userId: number | null;
  isFromAdmin: boolean;
  message: string;
  createdAt: string;
  isRead: boolean;
}

export interface CreateSupportRequest {
  subject: string;
  description: string;
  email?: string; // Required for anonymous users
}

export interface CreateSupportReply {
  message: string;
}

export interface SupportRequestListResponse {
  items: SupportRequest[];
  total: number;
  limit: number;
  offset: number;
}

export interface UnreadCount {
  unreadCount: number;
}

// User API (works for both logged-in and anonymous)
export const createSupportRequest = (data: CreateSupportRequest) =>
  api.post<SupportRequest>('/support', data);

// User API (requires auth)
export const getMySupportRequests = () =>
  api.get<SupportRequest[]>('/support');

export const getSupportRequest = (id: number) =>
  api.get<SupportRequest>(`/support/${id}`);

export const addSupportReply = (requestId: number, data: CreateSupportReply) =>
  api.post<SupportReply>(`/support/${requestId}/reply`, data);

export const deleteSupportRequest = (id: number) =>
  api.delete<void>(`/support/${id}`);

export const getUnreadSupportCount = () =>
  api.get<UnreadCount>('/support/unread-count');

export const markSupportRequestAsRead = (id: number) =>
  api.post<void>(`/support/${id}/mark-read`);

// Admin API
export const getAdminSupportRequests = (params?: {
  status?: string;
  includeDeleted?: boolean;
  limit?: number;
  offset?: number;
}) => {
  const searchParams = new URLSearchParams();
  if (params?.status) searchParams.set('status', params.status);
  if (params?.includeDeleted) searchParams.set('includeDeleted', 'true');
  if (params?.limit) searchParams.set('limit', params.limit.toString());
  if (params?.offset) searchParams.set('offset', params.offset.toString());
  
  const query = searchParams.toString();
  return api.get<SupportRequestListResponse>(`/admin/support${query ? `?${query}` : ''}`);
};

export const getAdminSupportRequest = (id: number) =>
  api.get<SupportRequest>(`/admin/support/${id}`);

export const addAdminSupportReply = (requestId: number, data: CreateSupportReply) =>
  api.post<SupportReply>(`/admin/support/${requestId}/reply`, data);

export const updateSupportStatus = (requestId: number, status: string) =>
  api.put<SupportRequest>(`/admin/support/${requestId}/status`, { status });

export const adminDeleteSupportRequest = (id: number) =>
  api.delete<void>(`/admin/support/${id}`);
