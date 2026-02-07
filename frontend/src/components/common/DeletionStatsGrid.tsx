
export interface DeletionStatsGridProps {
  collections?: number;
  categories?: number;
  items?: number;
  images?: number;
  users?: number;
}

export function DeletionStatsGrid({ collections, categories, items, images, users }: DeletionStatsGridProps) {
  const stats = [
    { label: 'Collections', value: collections, show: collections !== undefined },
    { label: 'Categories', value: categories, show: categories !== undefined },
    { label: 'Items', value: items, show: items !== undefined },
    { label: 'Images', value: images, show: images !== undefined },
    { label: 'Users', value: users, show: users !== undefined },
  ].filter(s => s.show);

  if (stats.length === 0) return null;

  return (
    <div className="deletion-stats-grid">
      {stats.map(stat => (
        <div key={stat.label} className="deletion-stats-grid__stat">
          <span className="deletion-stats-grid__value">{stat.value}</span>
          <span className="deletion-stats-grid__label">{stat.label}</span>
        </div>
      ))}
    </div>
  );
}

export default DeletionStatsGrid;
