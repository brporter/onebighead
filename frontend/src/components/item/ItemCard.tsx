import type { Item } from '../../utils/types';
import type { AccentColor } from '../../utils/accentColors';
import type { KeyboardEvent } from 'react';
import './ItemCard.css';

const MAX_PILLS = 3;

interface ItemCardProps {
  item: Item;
  accentColor: AccentColor;
  isSelected: boolean;
  onSelect: (id: number) => void;
}

function ItemCard({ item, accentColor, isSelected, onSelect }: ItemCardProps) {
  const hasImages = item.images.length > 0;
  const isTextOnly = !hasImages;

  function handleClick() {
    if (item.id !== null) {
      onSelect(item.id);
    }
  }

  function handleKeyDown(e: KeyboardEvent<HTMLDivElement>) {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      if (item.id !== null) {
        onSelect(item.id);
      }
    }
  }

  const visibleProps = item.properties.slice(0, MAX_PILLS);
  const extraCount = item.properties.length - MAX_PILLS;

  return (
    <div
      className={`item-card${isTextOnly ? ' item-card--textonly' : ''}${isSelected ? ' item-card--selected' : ''}`}
      role="button"
      tabIndex={0}
      aria-label={`Select ${item.name}`}
      onClick={handleClick}
      onKeyDown={handleKeyDown}
    >
      <div
        className="item-card__ribbon"
        style={{ background: `linear-gradient(90deg, ${accentColor.start}, ${accentColor.end})` }}
      />

      {hasImages && (
        <img
          className="item-card__img"
          src={item.images[0].url}
          alt={item.images[0].alt || item.name}
          loading="lazy"
        />
      )}

      <div className="item-card__body">
        <div className="item-card__name">{item.name}</div>
        {item.summary && (
          <div className="item-card__meta">{item.summary}</div>
        )}

        {isTextOnly && item.properties.length > 0 && (
          <div className="item-card__props">
            {visibleProps.map((prop) => (
              <span key={`${prop.category}-${prop.name}`} className="item-card__prop">
                {prop.value}
              </span>
            ))}
            {extraCount > 0 && (
              <span className="item-card__prop">+{extraCount} more</span>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

export default ItemCard;
