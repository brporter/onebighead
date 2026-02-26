/**
 * Matches API - LLM-powered item matching
 */
import { api } from './client';

export enum MatchStatus {
  New = 'New',
  Saved = 'Saved',
  Dismissed = 'Dismissed',
}

export interface MatchItemSummary {
  itemId: number;
  name: string;
  summary: string;
  primaryImageUrl: string | null;
  workspaceName: string;
  workspaceId: number;
}

export interface MatchResponse {
  id: number;
  wantItem: MatchItemSummary;
  tradeItem: MatchItemSummary;
  confidenceScore: number;
  matchReason: string;
  myStatus: MatchStatus;
  createdAt: string;
  hasUnreadMessages: boolean;
}

export interface MatchListResponse {
  matches: MatchResponse[];
  totalCount: number;
}

export interface MatchMessageResponse {
  id: number;
  message: string;
  isMine: boolean;
  isRead: boolean;
  createdAt: string;
}

export interface MatchCountResponse {
  newMatchCount: number;
  unreadMessageCount: number;
}

export interface UpdateMatchStatusRequest {
  status: MatchStatus;
}

export interface CreateMatchMessageRequest {
  message: string;
}

export const matchesApi = {
  getAll(
    status?: MatchStatus,
    skip = 0,
    take = 20,
  ): Promise<MatchListResponse> {
    const params = new URLSearchParams();
    if (status) params.set('status', status);
    params.set('skip', skip.toString());
    params.set('take', take.toString());
    return api.get<MatchListResponse>(`/matches?${params}`);
  },

  getById(id: number): Promise<MatchResponse> {
    return api.get<MatchResponse>(`/matches/${id}`);
  },

  updateStatus(id: number, request: UpdateMatchStatusRequest): Promise<void> {
    return api.put(`/matches/${id}/status`, request);
  },

  getMessages(
    matchId: number,
    skip = 0,
    take = 50,
  ): Promise<MatchMessageResponse[]> {
    return api.get<MatchMessageResponse[]>(
      `/matches/${matchId}/messages?skip=${skip}&take=${take}`,
    );
  },

  sendMessage(
    matchId: number,
    request: CreateMatchMessageRequest,
  ): Promise<MatchMessageResponse> {
    return api.post<MatchMessageResponse>(
      `/matches/${matchId}/messages`,
      request,
    );
  },

  markMessagesRead(matchId: number): Promise<void> {
    return api.post(`/matches/${matchId}/messages/read`);
  },

  getCount(): Promise<MatchCountResponse> {
    return api.get<MatchCountResponse>('/matches/count');
  },
};
