import { useEffect, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { publicApi, type PublicItem } from '../api';
import '../styles/components/PublicItem.css';

function PublicItemView() {
  const { slug, itemId } = useParams<{ slug: string; itemId: string }>();
  const navigate = useNavigate();
  const [item, setItem] = useState<PublicItem | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedImageIndex, setSelectedImageIndex] = useState(0);

  const itemIdNum = itemId ? parseInt(itemId, 10) : null;

  useEffect(() => {
    if (!slug || !itemIdNum) return;
    // eslint-disable-next-line react-hooks/set-state-in-effect -- loading state must be set before async fetch
    setLoading(true);
    publicApi.getItem(slug, itemIdNum)
      .then(setItem)
      .catch(() => setError('Item not found'))
      .finally(() => setLoading(false));
  }, [slug, itemIdNum]);

  if (loading) {
    return <div className="publicItem__loading">Loading item...</div>;
  }

  if (error || !item) {
    return <div className="publicItem__error">{error || 'Item not found'}</div>;
  }

  const propertyGroups = item.properties.reduce<Record<string, { name: string; value: string }[]>>((acc, prop) => {
    const key = prop.category || 'Details';
    if (!acc[key]) acc[key] = [];
    acc[key].push({ name: prop.name, value: prop.value });
    return acc;
  }, {});

  return (
    <div className="publicItem">
      <button className="publicItem__back" onClick={() => navigate(-1)}>
        &larr; Back
      </button>
      <div className="publicItem__layout">
        {item.images.length > 0 && (
          <div className="publicItem__gallery">
            <div className="publicItem__mainImage">
              <img
                src={item.images[selectedImageIndex]?.url}
                alt={item.images[selectedImageIndex]?.alt || item.name}
                className="publicItem__image"
              />
            </div>
            {item.images.length > 1 && (
              <div className="publicItem__thumbnails">
                {item.images.map((img, idx) => (
                  <button
                    key={idx}
                    className={`publicItem__thumbnail ${idx === selectedImageIndex ? 'publicItem__thumbnail--active' : ''}`}
                    onClick={() => setSelectedImageIndex(idx)}
                  >
                    <img src={img.url} alt={img.alt || `Image ${idx + 1}`} />
                  </button>
                ))}
              </div>
            )}
          </div>
        )}
        <div className="publicItem__info">
          <h1 className="publicItem__name">{item.name}</h1>
          {item.categoryName && <div className="publicItem__category">{item.categoryName}</div>}
          {item.summary && <p className="publicItem__summary">{item.summary}</p>}
          {item.description && <div className="publicItem__description">{item.description}</div>}
          {Object.entries(propertyGroups).map(([category, props]) => (
            <div key={category} className="publicItem__propertyGroup">
              <h2 className="publicItem__propertyGroupTitle">{category}</h2>
              <dl className="publicItem__properties">
                {props.map((prop, idx) => (
                  <div key={idx} className="publicItem__property">
                    <dt className="publicItem__propertyName">{prop.name}</dt>
                    <dd className="publicItem__propertyValue">{prop.value}</dd>
                  </div>
                ))}
              </dl>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

export default PublicItemView;
