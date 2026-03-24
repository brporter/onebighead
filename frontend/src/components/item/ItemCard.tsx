import { useState } from 'react';
import type { Item } from '../../utils/types';
import type { AccentColor } from '../../utils/accentColors';
import type { KeyboardEvent } from 'react';
import { PublishButton, PublicBadge, SlugSetupModal } from '../common';
import { useData } from '../../contexts/useData';
import { useToast } from '../../contexts/useToast';
import { buildPublishToastMessage, buildPublishToastDetails, buildUnpublishToastMessage } from '../../utils/publishToastUtils';
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
  const { publishItem, unpublishItem } = useData();
  const { showToast } = useToast();
  const [showSlugSetup, setShowSlugSetup] = useState(false);
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

  function handleKeyDown(e: KeyboardEvent<HTMLDivElement>) {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      if (selectionMode && onToggleCheck && item.id !== null) {
        onToggleCheck(item.id);
        return;
      }
      if (item.id !== null) {
        onSelect(item.id);
      }
    }
  }

  async function handlePublish() {
    if (item.id === null) return;
    const result = await publishItem(item.id);
    if (result.requiresSlugSetup) {
      setShowSlugSetup(true);
    } else {
      showToast(buildPublishToastMessage(result), buildPublishToastDetails(result));
    }
  }

  async function handleUnpublish() {
    if (item.id === null) return;
    const result = await unpublishItem(item.id);
    showToast(buildUnpublishToastMessage(result));
  }

  async function handleSlugConfirm() {
    setShowSlugSetup(false);
    if (item.id === null) return;
    // Retry publish after slug setup
    const result = await publishItem(item.id);
    showToast(buildPublishToastMessage(result), buildPublishToastDetails(result));
  }

  const visibleProps = item.properties.slice(0, MAX_PILLS);
  const extraCount = item.properties.length - MAX_PILLS;

  return (
    <>
      <div
        className={`item-card${isTextOnly ? ' item-card--textonly' : ''}${isSelected ? ' item-card--selected' : ''}${selectionMode ? ' item-card--selectable' : ''}`}
        role="button"
        tabIndex={0}
        aria-label={`Select ${item.name}`}
        onClick={handleClick}
        onKeyDown={handleKeyDown}
      >
        {selectionMode && (
          <div className="item-card__checkbox">
            <input
              type="checkbox"
              checked={isChecked ?? false}
              readOnly
              tabIndex={-1}
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

      {showSlugSetup && (
        <SlugSetupModal
          onConfirm={handleSlugConfirm}
          onCancel={() => setShowSlugSetup(false)}
        />
      )}
    </>
  );
}

export default ItemCard;
