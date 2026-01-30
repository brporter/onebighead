import ImageGallery from '../common/ImageGallery';
import PropertyRender from './PropertyRender';
import type { Item } from '../../utils/types';

interface ItemDetailProps {
  item: Item | null;
  onEdit?: (() => void) | null;
  onClose?: (() => void) | null;
}

function ItemDetail({
  item,
  onEdit,
  onClose,
}: ItemDetailProps) {
  if (!item) {
    return (
      <section className="detail detail--empty">
        <p className="detail__placeholder">Select an item</p>
      </section>
    );
  }

  return (
    <section className="detail">
      <div className="detail__header">
        <h2 className="detail__title">{item.name}</h2>
        <div className="detail__headerActions">
          {onEdit && (
            <button
              type="button"
              className="detail__btn detail__btn--secondary"
              onClick={onEdit}
            >
              Edit
            </button>
          )}
          {onClose && (
            <button type="button" className="detail__close" onClick={onClose}>
              Back to list
            </button>
          )}
        </div>
      </div>

      <p className="detail__description">{item.description}</p>

      <ImageGallery key={item.id ?? 'new'} images={item.images} title={item.name} />

      <PropertyRender properties={item.properties} />
    </section>
  );
}

export default ItemDetail;

