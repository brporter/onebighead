import { useCallback } from 'react';
import { collectionsApi, type CollectionStatisticsResponse } from '../../api/collections';
import { useAsyncData } from '../../utils/useAsyncData';
import { Loading } from '../common';
import '../../styles/components/CollectionDashboard.css';

interface CollectionDashboardProps {
  collectionId: number;
  onSelectItem: (itemId: number) => void;
}

function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(1024));
  return `${(bytes / Math.pow(1024, i)).toFixed(i === 0 ? 0 : 1)} ${units[i]}`;
}

function formatRelativeTime(dateString: string): string {
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
}

function CollectionDashboard({ collectionId, onSelectItem }: CollectionDashboardProps) {
  const fetchStats = useCallback(
    () => collectionsApi.getStatistics(collectionId),
    [collectionId],
  );
  const { data: stats, loading, error } = useAsyncData<CollectionStatisticsResponse>(fetchStats);

  if (loading) {
    return <Loading message="Loading dashboard..." />;
  }

  if (error) {
    return (
      <div className="collection-dashboard__empty">
        <p>Failed to load collection statistics.</p>
      </div>
    );
  }

  if (!stats || stats.itemCount === 0) {
    return (
      <div className="collection-dashboard__empty">
        <p>No items yet. Select a category and start adding items.</p>
      </div>
    );
  }

  return (
    <div className="collection-dashboard">
      <div className="collection-dashboard__stats">
        <div className="collection-dashboard__stats-card">
          <div className="collection-dashboard__stats-value">{stats.itemCount}</div>
          <div className="collection-dashboard__stats-label">Items</div>
        </div>
        <div className="collection-dashboard__stats-card">
          <div className="collection-dashboard__stats-value">{stats.imageCount}</div>
          <div className="collection-dashboard__stats-label">Images</div>
        </div>
        <div className="collection-dashboard__stats-card">
          <div className="collection-dashboard__stats-value">{formatBytes(stats.totalImageSizeBytes)}</div>
          <div className="collection-dashboard__stats-label">Total Image Size</div>
        </div>
      </div>

      <div className="collection-dashboard__panels">
        {stats.recentlyAddedItems.length > 0 && (
          <div className="collection-dashboard__panel">
            <h2 className="collection-dashboard__panel-title">Recently Added</h2>
            <ul className="collection-dashboard__item-list">
              {stats.recentlyAddedItems.map((item) => (
                <li
                  key={item.itemId}
                  className="collection-dashboard__item"
                  onClick={() => onSelectItem(item.itemId)}
                  role="button"
                  tabIndex={0}
                  onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') onSelectItem(item.itemId); }}
                >
                  <span className="collection-dashboard__item-name">{item.itemName}</span>
                  <span className="collection-dashboard__item-meta">{formatRelativeTime(item.createdAt)}</span>
                </li>
              ))}
            </ul>
          </div>
        )}

        {stats.topViewedItems.length > 0 && (
          <div className="collection-dashboard__panel">
            <h2 className="collection-dashboard__panel-title">Most Viewed</h2>
            <ul className="collection-dashboard__item-list">
              {stats.topViewedItems.map((item) => (
                <li
                  key={item.itemId}
                  className="collection-dashboard__item"
                  onClick={() => onSelectItem(item.itemId)}
                  role="button"
                  tabIndex={0}
                  onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') onSelectItem(item.itemId); }}
                >
                  <span className="collection-dashboard__item-name">{item.itemName}</span>
                  <span className="collection-dashboard__item-meta">{item.viewCount} views</span>
                </li>
              ))}
            </ul>
          </div>
        )}
      </div>
    </div>
  );
}

export default CollectionDashboard;
