import { useCallback } from 'react';
import type { dashboardApi } from '../../api/dashboard';
import { useAsyncData } from '../../utils/useAsyncData';
import { formatBytes } from '../../utils/formatBytes';
import { ContentState } from '../common/ContentState';
import '../../styles/components/DashboardSection.css';

interface DashboardSectionProps {
  gateway: Pick<typeof dashboardApi, 'get'>;
}

const fullDate = new Intl.DateTimeFormat('en-US', { dateStyle: 'long', timeZone: 'UTC' });
const weekday = new Intl.DateTimeFormat('en-US', { weekday: 'short', timeZone: 'UTC' });

/** Read-only workspace overview, independent of other settings workflows. */
export function DashboardSection({ gateway }: DashboardSectionProps) {
  const fetchDashboard = useCallback((signal: AbortSignal) => gateway.get({ signal }), [gateway]);
  const { data, loading, error, retry } = useAsyncData(fetchDashboard);
  const maxViews = Math.max(1, ...data?.dailyViews.map(day => day.viewCount) ?? []);

  return (
    <section className="settings-section dashboard" aria-labelledby="dashboard-title">
      <div className="settings-section__header">
        <div>
          <h2 id="dashboard-title" className="settings-section__title">Dashboard</h2>
          <p className="settings-section__description">Overview of your workspace activity and statistics.</p>
        </div>
      </div>
      {loading && <ContentState kind="loading" title="Loading workspace statistics..." />}
      {error && <ContentState kind="error" title="Unable to load workspace statistics"
        action={<button type="button" className="settings__button settings__button--secondary" onClick={retry}>Try again</button>}>
        {error}
      </ContentState>}
      {data && <>
        <dl className="dashboard-stats" aria-label="Workspace statistics">
          <div className="dashboard-stats__card">
            <dt className="dashboard-stats__label">Collections</dt>
            <dd className="dashboard-stats__value">{data.collectionCount}</dd>
          </div>
          <div className="dashboard-stats__card">
            <dt className="dashboard-stats__label">Items</dt>
            <dd className="dashboard-stats__value">{data.itemCount}</dd>
          </div>
          <div className="dashboard-stats__card">
            <dt className="dashboard-stats__label">Images</dt>
            <dd className="dashboard-stats__value">{data.imageCount}</dd>
            <dd className="dashboard-stats__detail">{formatBytes(data.imageTotalSizeBytes)} stored</dd>
          </div>
        </dl>
        <div className="dashboard-chart">
          <h3 className="dashboard-chart__title">Item Views (Last 7 Days)</h3>
          {data.dailyViews.length === 0 ? <ContentState kind="empty" title="No view history yet">
            Item views will appear here as people explore your collection.
          </ContentState> : <ul className="dashboard-chart__bars" aria-label="Daily item views">
            {data.dailyViews.map(day => {
              const date = new Date(`${day.date}T00:00:00Z`);
              const description = `${fullDate.format(date)}: ${day.viewCount} ${day.viewCount === 1 ? 'view' : 'views'}`;
              return <li key={day.date} className="dashboard-chart__bar-wrapper" aria-label={description} title={description}>
                <span className="dashboard-chart__bar-count" aria-hidden="true">{day.viewCount}</span>
                <div className="dashboard-chart__bar-track" aria-hidden="true">
                  <div className="dashboard-chart__bar" style={{ height: `${day.viewCount / maxViews * 100}%` }} />
                </div>
                <time className="dashboard-chart__bar-label" dateTime={day.date} aria-hidden="true">{weekday.format(date)}</time>
              </li>;
            })}
          </ul>}
        </div>
      </>}
    </section>
  );
}
