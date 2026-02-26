import { useState, useCallback } from 'react';
import { matchesApi, MatchStatus, type MatchResponse, type MatchListResponse } from '../api';
import { useAsyncData } from '../utils/useAsyncData';
import { Loading } from '../components/common';
import MatchDetailModal from '../components/matching/MatchDetailModal';
import '../styles/components/Matches.css';

type FilterTab = 'all' | MatchStatus.New | MatchStatus.Saved;

function MatchesView() {
  const [activeTab, setActiveTab] = useState<FilterTab>(MatchStatus.New);
  const [selectedMatch, setSelectedMatch] = useState<MatchResponse | null>(null);
  const [refreshKey, setRefreshKey] = useState(0);

  const statusFilter = activeTab === 'all' ? undefined : activeTab;

  const fetchMatches = useCallback(
    () => matchesApi.getAll(statusFilter as MatchStatus | undefined, 0, 50),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [statusFilter, refreshKey],
  );
  const { data, loading, error } = useAsyncData<MatchListResponse>(fetchMatches);

  const handleRefresh = () => setRefreshKey(k => k + 1);

  const handleStatusUpdate = async (matchId: number, status: MatchStatus) => {
    try {
      await matchesApi.updateStatus(matchId, { status });
      handleRefresh();
    } catch {
      // Error handled silently
    }
  };

  const formatRelativeTime = (dateString: string): string => {
    const now = new Date();
    const date = new Date(dateString);
    const diffMs = now.getTime() - date.getTime();
    const diffMinutes = Math.floor(diffMs / 60000);
    const diffHours = Math.floor(diffMinutes / 60);
    const diffDays = Math.floor(diffHours / 24);

    if (diffMinutes < 1) return 'just now';
    if (diffMinutes < 60) return `${diffMinutes}m ago`;
    if (diffHours < 24) return `${diffHours}h ago`;
    if (diffDays < 30) return `${diffDays}d ago`;
    return date.toLocaleDateString();
  };

  return (
    <div className="matches-view">
      <div className="matches-view__header">
        <h1>Item Matches</h1>
      </div>

      <div className="matches-view__filters">
        <button
          className={`matches-view__filter-tab ${activeTab === MatchStatus.New ? 'matches-view__filter-tab--active' : ''}`}
          onClick={() => setActiveTab(MatchStatus.New)}
        >
          New
        </button>
        <button
          className={`matches-view__filter-tab ${activeTab === MatchStatus.Saved ? 'matches-view__filter-tab--active' : ''}`}
          onClick={() => setActiveTab(MatchStatus.Saved)}
        >
          Saved
        </button>
        <button
          className={`matches-view__filter-tab ${activeTab === 'all' ? 'matches-view__filter-tab--active' : ''}`}
          onClick={() => setActiveTab('all')}
        >
          All
        </button>
      </div>

      {loading && <Loading message="Loading matches..." />}

      {error && (
        <div className="matches-view__error">
          <p>Failed to load matches.</p>
        </div>
      )}

      {!loading && !error && data && data.matches.length === 0 && (
        <div className="matches-view__empty">
          <p>No matches found. Matches are automatically discovered when you tag items as &quot;Want&quot; and other users have matching items for trade or sale.</p>
        </div>
      )}

      {!loading && data && data.matches.length > 0 && (
        <div className="matches-view__list">
          {data.matches.map((match) => {
            const confidencePercent = Math.round(match.confidenceScore * 100);
            return (
              <div
                key={match.id}
                className="match-card"
                onClick={() => setSelectedMatch(match)}
                role="button"
                tabIndex={0}
                onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') setSelectedMatch(match); }}
              >
                <div className="match-card__items">
                  <div className="match-card__item">
                    <span className="match-card__label">Want</span>
                    <span className="match-card__item-name">{match.wantItem.name}</span>
                    <span className="match-card__workspace">{match.wantItem.workspaceName}</span>
                  </div>
                  <div className="match-card__arrow">&harr;</div>
                  <div className="match-card__item">
                    <span className="match-card__label">Trade/Sell</span>
                    <span className="match-card__item-name">{match.tradeItem.name}</span>
                    <span className="match-card__workspace">{match.tradeItem.workspaceName}</span>
                  </div>
                </div>
                <div className="match-card__meta">
                  <span className={`match-card__confidence ${confidencePercent >= 80 ? 'match-card__confidence--high' : confidencePercent >= 60 ? 'match-card__confidence--medium' : 'match-card__confidence--low'}`}>
                    {confidencePercent}%
                  </span>
                  <span className="match-card__reason">{match.matchReason}</span>
                  <span className="match-card__time">{formatRelativeTime(match.createdAt)}</span>
                  {match.hasUnreadMessages && (
                    <span className="match-card__unread">New messages</span>
                  )}
                </div>
                <div className="match-card__actions" onClick={(e) => e.stopPropagation()}>
                  {match.myStatus !== MatchStatus.Saved && (
                    <button
                      className="btn btn--sm btn--primary"
                      onClick={() => handleStatusUpdate(match.id, MatchStatus.Saved)}
                    >
                      Save
                    </button>
                  )}
                  {match.myStatus !== MatchStatus.Dismissed && (
                    <button
                      className="btn btn--sm btn--secondary"
                      onClick={() => handleStatusUpdate(match.id, MatchStatus.Dismissed)}
                    >
                      Dismiss
                    </button>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      )}

      <MatchDetailModal
        match={selectedMatch}
        isOpen={selectedMatch !== null}
        onClose={() => setSelectedMatch(null)}
        onStatusChanged={handleRefresh}
      />
    </div>
  );
}

export default MatchesView;
