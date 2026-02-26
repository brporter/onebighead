import { useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { matchesApi, type MatchCountResponse, type MatchListResponse } from '../../api';
import { useAsyncData } from '../../utils/useAsyncData';

function MatchesSummary() {
  const navigate = useNavigate();

  const fetchCount = useCallback(() => matchesApi.getCount(), []);
  const { data: count } = useAsyncData<MatchCountResponse>(fetchCount);

  const fetchRecent = useCallback(() => matchesApi.getAll(undefined, 0, 3), []);
  const { data: recent } = useAsyncData<MatchListResponse>(fetchRecent);

  if (!count || (count.newMatchCount === 0 && count.unreadMessageCount === 0 && (!recent || recent.matches.length === 0))) {
    return null;
  }

  return (
    <div className="collection-dashboard__panel">
      <h2 className="collection-dashboard__panel-title">Item Matches</h2>
      <div className="matches-summary">
        <div className="matches-summary__counts">
          {count.newMatchCount > 0 && (
            <span className="matches-summary__badge matches-summary__badge--new">
              {count.newMatchCount} new {count.newMatchCount === 1 ? 'match' : 'matches'}
            </span>
          )}
          {count.unreadMessageCount > 0 && (
            <span className="matches-summary__badge matches-summary__badge--messages">
              {count.unreadMessageCount} unread {count.unreadMessageCount === 1 ? 'message' : 'messages'}
            </span>
          )}
        </div>
        {recent && recent.matches.length > 0 && (
          <ul className="matches-summary__list">
            {recent.matches.map((match) => (
              <li key={match.id} className="matches-summary__item">
                <span className="matches-summary__item-name">
                  {match.wantItem.name} &harr; {match.tradeItem.name}
                </span>
                <span className={`match-card__confidence ${Math.round(match.confidenceScore * 100) >= 80 ? 'match-card__confidence--high' : 'match-card__confidence--medium'}`}>
                  {Math.round(match.confidenceScore * 100)}%
                </span>
              </li>
            ))}
          </ul>
        )}
        <button
          className="btn btn--link matches-summary__view-all"
          onClick={() => navigate('/matches')}
        >
          View All Matches
        </button>
      </div>
    </div>
  );
}

export default MatchesSummary;
