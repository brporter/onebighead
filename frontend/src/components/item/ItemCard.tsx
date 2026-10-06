import type { Item } from '../../utils/types';
import type { AccentColor } from '../../utils/accentColors';
import { PublishButton, PublicBadge } from '../common';
import { usePublish } from '../../contexts/usePublish';
import './ItemCard.css';

const MAX_PILLS = 3;

interface ItemCardProps {
  item: Item;
  accentColor: AccentColor;
  isSelected: boolean;
  onSelect: (id: number) => void;
  selectionMode?: boolean;
  isChecked?: boolean;
  onToggleCheck?: (id: number) => void;
}

function ItemCard({ item, accentColor, isSelected, onSelect, selectionMode, isChecked, onToggleCheck }: ItemCardProps) {
  const { requestPublish, requestUnpublish } = usePublish();
  const hasImages = item.images.length > 0;
  const isTextOnly = !hasImages;

  function handleClick() {
    if (selectionMode && onToggleCheck && item.id !== null) {
      onToggleCheck(item.id);
      return;
    }
    if (item.id !== null) {
      onSelect(item.id);
    }
  }

  function handlePublish() {
    if (item.id === null) return;
    requestPublish([{ type: 'item', id: item.id }]);
  }

  function handleUnpublish() {
    if (item.id === null) return;
    requestUnpublish([{ type: 'item', id: item.id }]);
  }

  const visibleProps = item.properties.slice(0, MAX_PILLS);
  const extraCount = item.properties.length - MAX_PILLS;

  return (
    <div
      className={`item-card${isTextOnly ? ' item-card--textonly' : ''}${isSelected ? ' item-card--selected' : ''}${selectionMode ? ' item-card--selectable' : ''}`}
    >
      {selectionMode && (
        <div className="item-card__checkbox">
          <input
            type="checkbox"
            checked={isChecked ?? false}
            onChange={() => { if (item.id !== null) onToggleCheck?.(item.id); }}
            aria-label={`Select ${item.name}`}
          />
        </div>
      )}

      <div
        className="item-card__ribbon"
        style={{ background: `linear-gradient(90deg, ${accentColor.start}, ${accentColor.end})` }}
      />

      {item.effectiveIsPublic ? (
        <PublicBadge
          effectiveIsPublic={item.effectiveIsPublic}
          onUnpublish={handleUnpublish}
          className="item-card__badge"
        />
      ) : (
        <PublishButton
          onPublish={handlePublish}
          className="item-card__publish-btn"
        />
      )}

      {hasImages && (
        <img
          className="item-card__img"
          src={item.images[0].url}
          alt={item.images[0].alt || item.name}
          loading="lazy"
        />
      )}

      <div className="item-card__body">
        <button
          type="button"
          className="item-card__name item-card__select"
          aria-label={`Select ${item.name}`}
          aria-pressed={selectionMode ? (isChecked ?? false) : undefined}
          onClick={handleClick}
        >{item.name}</button>

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
